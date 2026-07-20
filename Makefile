# =========================================================================
# Rustyrouter Makefile
# =========================================================================

.PHONY: all clean qemu

# Target files
BINARY := target/x86_64-unknown-linux-musl/release/rustyrouter
INITRAMFS := target/initramfs.cpio.gz
STAGING := target/staging

# Source files for dependency tracking
SRCS := $(shell find src -name "*.rs")

# Default target
all: $(INITRAMFS)

# Compile the static release binary
$(BINARY): Cargo.toml Cargo.lock $(SRCS)
	@echo "[build] Ensuring x86_64-unknown-linux-musl target is installed..."
	@rustup target add x86_64-unknown-linux-musl
	@echo "[build] Compiling rustyrouter (Static MUSL Release)..."
	@cargo build --release --target x86_64-unknown-linux-musl

# Package the initramfs cpio archive
$(INITRAMFS): $(BINARY)
	@echo "[build] Creating initramfs staging area..."
	@rm -rf $(STAGING)
	@mkdir -p $(STAGING)/proc $(STAGING)/sys $(STAGING)/dev $(STAGING)/run
	@cp $(BINARY) $(STAGING)/init
	@chmod +x $(STAGING)/init
	@if [ -d "host/modules" ]; then \
		echo "[build] Copying local kernel modules from host/modules/ to /lib/modules..."; \
		mkdir -p $(STAGING)/lib/modules; \
		cp -r host/modules/* $(STAGING)/lib/modules/; \
	fi
	@KVER=$$(ls /lib/modules 2>/dev/null | head -n 1); \
	if [ -n "$$KVER" ]; then \
		echo "[build] Found container kernel modules for $$KVER. Copying required drivers..."; \
		mkdir -p $(STAGING)/lib/modules/$$KVER; \
		for mod in failover net_failover virtio_net nfnetlink libcrc32c nf_defrag_ipv4 nf_defrag_ipv6 nf_tables nf_conntrack nf_nat nft_ct nft_chain_nat nft_masq; do \
			found=$$(find "/lib/modules/$$KVER" -name "$${mod}.ko" -o -name "$${mod}.ko.zst" -o -name "$${mod}.ko.xz" -o -name "$${mod}.ko.gz" 2>/dev/null | head -n 1); \
			if [ -n "$$found" ]; then \
				dest="$(STAGING)/lib/modules/$$KVER/$${mod}.ko"; \
				case "$$found" in \
					*.zst) zstd -d -c "$$found" > "$$dest" ;; \
					*.xz) xz -d -c "$$found" > "$$dest" ;; \
					*.gz) gunzip -c "$$found" > "$$dest" ;; \
					*) cp "$$found" "$$dest" ;; \
				esac; \
				chmod 644 "$$dest"; \
			fi; \
		done; \
	fi
	@echo "[build] Packaging initramfs into $(INITRAMFS)..."
	@(cd $(STAGING) && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz)
	@echo "[build] Initramfs archived successfully at: $(INITRAMFS)"

# Run interactive QEMU simulation
qemu: $(INITRAMFS)
	@./test_qemu.sh

# Clean build artifacts
clean:
	@echo "[clean] Cleaning build target and staging directories..."
	@cargo clean
	@rm -rf $(STAGING) $(INITRAMFS)
