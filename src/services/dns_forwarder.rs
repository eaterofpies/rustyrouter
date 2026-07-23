use super::utils::WanLease;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// =========================================================================
// DNS Constants & Config
// =========================================================================
const DNS_PORT: u16 = 53;
const DNS_HEADER_SIZE: usize = 12;

const DEFAULT_TTL_SECS: u32 = 30;
const MAX_TTL_SECS: u32 = 3600;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const RECV_BUF_SIZE: usize = 4096;

const FALLBACK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_PENDING_QUERIES: usize = 4096;

// =========================================================================
// Cache Structure
// =========================================================================
#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expiry: Instant,
}

struct PendingQuery {
    tx: tokio::sync::oneshot::Sender<Vec<u8>>,
    upstream_ip: Ipv4Addr,
}

type SharedCache = Arc<Mutex<HashMap<Vec<u8>, CacheEntry>>>;
type PendingQueries = Arc<Mutex<HashMap<u16, PendingQuery>>>;

pub async fn start_dns_forwarder(lease_state: Arc<Mutex<WanLease>>) {
    let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT);
    let socket = match tokio::net::UdpSocket::bind(addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[dns-forwarder] Failed to bind to 0.0.0.0:{}: {}. Retrying in 5s...",
                DNS_PORT, e
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
            return;
        }
    };
    let socket = Arc::new(socket);
    println!("[dns-forwarder] Listening on 0.0.0.0:{}...", DNS_PORT);

    let cache: SharedCache = Arc::new(Mutex::new(HashMap::new()));

    // Bind a single, long-lived client socket for all outgoing upstream DNS queries.
    let upstream_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("[dns-forwarder] Failed to bind upstream socket: {}. Aborting.", e);
            return;
        }
    };

    let pending_queries: PendingQueries = Arc::new(Mutex::new(HashMap::new()));

    // Spawn the background receiver task for upstream replies.
    // This task reads continuously from the shared socket, parses the 16-bit
    // DNS transaction ID (xid), and dispatches the response to the corresponding
    // query task after verifying the sender's IP address.
    let upstream_socket_recv = upstream_socket.clone();
    let pending_queries_recv = pending_queries.clone();
    tokio::spawn(async move {
        let mut resp_buf = [0u8; RECV_BUF_SIZE];
        loop {
            let (len, from_addr) = match upstream_socket_recv.recv_from(&mut resp_buf).await {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("[dns-forwarder] Upstream socket read error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if len < DNS_HEADER_SIZE {
                continue;
            }
            let xid = u16::from_be_bytes([resp_buf[0], resp_buf[1]]);

            let pending = {
                let mut lock = pending_queries_recv.lock().unwrap();
                lock.remove(&xid)
            };

            if let Some(p) = pending {
                if from_addr.ip() == std::net::IpAddr::V4(p.upstream_ip) {
                    let _ = p.tx.send(resp_buf[..len].to_vec());
                } else {
                    eprintln!(
                        "[dns-forwarder] WARNING: Received DNS spoof attempt! IP {} mismatch for xid {}",
                        from_addr.ip(), xid
                    );
                }
            }
        }
    });

    // Spawn periodic cleanup task to prune expired cache entries
    let cache_cleanup = cache.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CLEANUP_INTERVAL).await;
            let mut lock = cache_cleanup.lock().unwrap();
            let now = Instant::now();
            lock.retain(|_, entry| entry.expiry > now);
        }
    });

    let mut buf = [0u8; RECV_BUF_SIZE];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!(
                    "[dns-forwarder] Socket receive error: {}. Retrying in 1s...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let query = buf[..len].to_vec();
        let socket_clone = socket.clone();
        let cache_clone = cache.clone();
        let lease_clone = lease_state.clone();
        let upstream_sock_clone = upstream_socket.clone();
        let pending_queries_clone = pending_queries.clone();

        tokio::spawn(async move {
            handle_dns_query(
                query,
                src,
                socket_clone,
                cache_clone,
                lease_clone,
                upstream_sock_clone,
                pending_queries_clone,
            )
            .await;
        });
    }
}

async fn handle_dns_query(
    query: Vec<u8>,
    src: std::net::SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
    cache: SharedCache,
    lease_state: Arc<Mutex<WanLease>>,
    upstream_socket: Arc<tokio::net::UdpSocket>,
    pending_queries: PendingQueries,
) {
    if query.len() < DNS_HEADER_SIZE {
        return;
    }

    let cache_key = match get_cache_key(&query) {
        Some(key) => key,
        None => return,
    };

    if let Some(mut response) = lookup_cache(&cache_key, &cache) {
        response[0] = query[0];
        response[1] = query[1];
        let _ = socket.send_to(&response, src).await;
        return;
    }

    let upstream_dns = get_upstream_dns(&lease_state);

    if let Some(response) = forward_query(
        &query,
        upstream_dns,
        &upstream_socket,
        &pending_queries,
    )
    .await
    {
        insert_cache(cache_key, response.clone(), &cache);
        let _ = socket.send_to(&response, src).await;
    }
}

fn get_cache_key(query_bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = dns_parser::Packet::parse(query_bytes).ok()?;
    if packet.questions.is_empty() {
        return None;
    }
    let q = &packet.questions[0];
    let key = format!("{}:{:?}:{:?}", q.qname, q.qtype, q.qclass);
    Some(key.into_bytes())
}

fn lookup_cache(cache_key: &[u8], cache: &Mutex<HashMap<Vec<u8>, CacheEntry>>) -> Option<Vec<u8>> {
    let mut lock = cache.lock().unwrap();
    match lock.get(cache_key) {
        Some(entry) if entry.expiry > Instant::now() => Some(entry.response.clone()),
        Some(_) => {
            lock.remove(cache_key);
            None
        }
        None => None,
    }
}

fn insert_cache(
    cache_key: Vec<u8>,
    response: Vec<u8>,
    cache: &Mutex<HashMap<Vec<u8>, CacheEntry>>,
) {
    if response.len() < DNS_HEADER_SIZE {
        return;
    }
    let packet = match dns_parser::Packet::parse(&response) {
        Ok(p) => p,
        Err(_) => return,
    };
    let ttl = packet
        .answers
        .iter()
        .map(|ans| ans.ttl)
        .min()
        .unwrap_or(DEFAULT_TTL_SECS);
    if ttl == 0 {
        return;
    }
    let cache_ttl = std::cmp::min(MAX_TTL_SECS, ttl);
    let expiry = Instant::now() + Duration::from_secs(cache_ttl as u64);

    let mut lock = cache.lock().unwrap();
    lock.insert(cache_key, CacheEntry { response, expiry });
}

fn get_upstream_dns(lease_state: &Mutex<WanLease>) -> Ipv4Addr {
    let lease = lease_state.lock().unwrap();
    if !lease.dns_servers.is_empty() {
        lease.dns_servers[0]
    } else {
        FALLBACK_DNS_SERVER
    }
}

// Forward query to the upstream DNS resolver using the shared socket.
// To support concurrent requests over a single socket, we:
// 1. Save the client's original transaction ID (xid).
// 2. Generate a new, unique transaction ID and write it to the DNS query header.
// 3. Register a oneshot channel mapping our unique transaction ID to the waiting task.
// 4. Send the modified query upstream.
// 5. Wait for the background loop to receive and dispatch the response payload, then restore
//    the client's original transaction ID before returning.
async fn forward_query(
    query: &[u8],
    upstream_dns: Ipv4Addr,
    upstream_socket: &tokio::net::UdpSocket,
    pending_queries: &PendingQueries,
) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_SIZE {
        return None;
    }
    let client_xid = u16::from_be_bytes([query[0], query[1]]);

    // Generate a unique transaction ID that doesn't conflict with any active query.
    // Limit maximum pending queries to prevent infinite search loops under high load.
    let mut rng_xid = rand::random::<u16>();
    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let mut lock = pending_queries.lock().unwrap();
        if lock.len() >= MAX_PENDING_QUERIES {
            return None;
        }
        while lock.contains_key(&rng_xid) {
            rng_xid = rand::random::<u16>();
        }
        lock.insert(
            rng_xid,
            PendingQuery {
                tx,
                upstream_ip: upstream_dns,
            },
        );
    }

    let mut forwarded_query = query.to_vec();
    let xid_bytes = rng_xid.to_be_bytes();
    forwarded_query[0] = xid_bytes[0];
    forwarded_query[1] = xid_bytes[1];

    let upstream_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(upstream_dns), DNS_PORT);
    if upstream_socket.send_to(&forwarded_query, upstream_addr).await.is_err() {
        pending_queries.lock().unwrap().remove(&rng_xid);
        return None;
    }

    let rx_res = tokio::time::timeout(UPSTREAM_TIMEOUT, rx).await;
    let mut response = match rx_res {
        Ok(Ok(resp)) => resp,
        _ => {
            // Clean up registry entry if timeout/error occurs to prevent memory leaks
            pending_queries.lock().unwrap().remove(&rng_xid);
            return None;
        }
    };

    if response.len() >= DNS_HEADER_SIZE {
        let client_xid_bytes = client_xid.to_be_bytes();
        response[0] = client_xid_bytes[0];
        response[1] = client_xid_bytes[1];
        Some(response)
    } else {
        None
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cache_key_valid() {
        // DNS header (12 bytes) + "google.com" question + Type A (2 bytes) + Class IN (2 bytes)
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query.extend_from_slice(&[0, 1]); // Type A
        query.extend_from_slice(&[0, 1]); // Class IN

        let key = get_cache_key(&query);
        assert_eq!(key, Some("google.com:A:IN".to_string().into_bytes()));
    }

    #[test]
    fn test_get_cache_key_invalid() {
        let query = vec![0u8; 10]; // Too short
        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_insert_cache_ttl() {
        // Build a raw DNS response with answers having TTL 300 and 150
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        // Question: "google.com", Type A, Class IN
        resp.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN

        // Modify header to specify 1 question and 2 answers
        resp[5] = 1; // QDCount = 1
        resp[7] = 2; // ANCount = 2

        // Answer 1: name compression pointer 0xc00c, Type A, Class IN, TTL 300, RDLength 4, IP 8.8.8.8
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN
        resp.extend_from_slice(&[0, 0, 1, 0x2c]); // TTL = 300
        resp.extend_from_slice(&[0, 4]); // RDLength
        resp.extend_from_slice(&[8, 8, 8, 8]); // IP

        // Answer 2: name compression pointer 0xc00c, Type A, Class IN, TTL 150, RDLength 4, IP 8.8.4.4
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN
        resp.extend_from_slice(&[0, 0, 0, 0x96]); // TTL = 150
        resp.extend_from_slice(&[0, 4]); // RDLength
        resp.extend_from_slice(&[8, 8, 4, 4]); // IP

        let cache = Mutex::new(HashMap::new());
        insert_cache(b"key".to_vec(), resp, &cache);

        let lock = cache.lock().unwrap();
        let entry = lock.get(&b"key".to_vec()[..]).unwrap();
        let cache_ttl = entry.expiry.duration_since(Instant::now()).as_secs();
        assert!((148..=150).contains(&cache_ttl));
    }
}
