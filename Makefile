# =========================================================================
# Rustyrouter main Makefile (Supports parameterized ARCH builds & tests)
# =========================================================================

.PHONY: all clean qemu image test

# Default architecture: x86_64 (Host simulation). Can be overridden via ARCH=arm64 or ARCH=armhf
ARCH ?= x86_64

# Architecture mapping to rust target and QEMU setup
ifeq ($(ARCH),x86_64)
    RUST_TARGET := x86_64-unknown-linux-musl
    KERNEL_SOURCE := apt-generic
    DEB_ARCH := amd64
    KERNEL_PKG := linux-image-cloud-amd64
else ifeq ($(ARCH),arm64)
    RUST_TARGET := aarch64-unknown-linux-musl
    KERNEL_SOURCE := apt-generic
    DEB_ARCH := arm64
    KERNEL_PKG := linux-image-cloud-arm64
else ifeq ($(ARCH),armhf)
    RUST_TARGET := arm-unknown-linux-musleabihf
    KERNEL_SOURCE := apt-generic
    DEB_ARCH := armhf
    KERNEL_PKG := linux-image-armmp
else
    $(error Unsupported ARCH: $(ARCH). Must be x86_64, arm64, or armhf)
endif

# Target files
BINARY := target/$(RUST_TARGET)/release/rustyrouter
INITRAMFS := target/$(ARCH)/initramfs.cpio.gz
STAGING := target/$(ARCH)/staging
APT_DIR := $(CURDIR)/target/$(ARCH)/apt
TEST_BOOT_DIR := $(CURDIR)/target/$(ARCH)/test_boot

# Source files for dependency tracking
SRCS := $(shell find src -name "*.rs")

# Default target (packages the test initramfs)
all: $(INITRAMFS)

# Unified target-specific static MUSL compilation rule
$(BINARY): Cargo.toml Cargo.lock $(SRCS)
	@echo "[build] Ensuring $(RUST_TARGET) target is installed..."
	@rustup target add $(RUST_TARGET)
	@echo "[build] Compiling rustyrouter (Static $(ARCH) Release)..."
	@RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld" cargo build --release --target $(RUST_TARGET)

# Securely download and extract a generic Debian cloud kernel for emulated integration tests
$(TEST_BOOT_DIR)/.kernel_extracted:
	@echo "[apt-test] Downloading generic $(ARCH) kernel package..."
	@rm -rf $(TEST_BOOT_DIR) $(APT_DIR)
	@mkdir -p $(TEST_BOOT_DIR)
	@mkdir -p $(APT_DIR)/state/lists/partial $(APT_DIR)/cache/archives/partial $(APT_DIR)/etc/trusted.gpg.d
	@touch $(APT_DIR)/state/status
	@echo "deb [arch=$(DEB_ARCH) trusted=yes] http://deb.debian.org/debian/ bookworm main" > $(APT_DIR)/etc/sources.list
	@echo "Updating sandboxed APT package index..."
	@apt-get -o Dir::State=$(APT_DIR)/state \
	         -o Dir::State::status=$(APT_DIR)/state/status \
	         -o Dir::State::Lists=$(APT_DIR)/state/lists \
	         -o Dir::Cache=$(APT_DIR)/cache \
	         -o Dir::Cache::archives=$(APT_DIR)/cache/archives \
	         -o Dir::Etc=$(APT_DIR)/etc \
	         -o Dir::Etc::SourceList=$(APT_DIR)/etc/sources.list \
	         -o Dir::Etc::TrustedParts=$(APT_DIR)/etc/trusted.gpg.d \
	         update
	@echo "Resolving dependencies for meta-package: $(KERNEL_PKG)..."
	@PKG=$$(apt-cache -o Dir::State=$(APT_DIR)/state \
	                  -o Dir::State::status=$(APT_DIR)/state/status \
	                  -o Dir::State::Lists=$(APT_DIR)/state/lists \
	                  -o Dir::Cache=$(APT_DIR)/cache \
	                  -o Dir::Cache::archives=$(APT_DIR)/cache/archives \
	                  -o Dir::Etc=$(APT_DIR)/etc \
	                  -o Dir::Etc::SourceList=$(APT_DIR)/etc/sources.list \
	                  -o Dir::Etc::TrustedParts=$(APT_DIR)/etc/trusted.gpg.d \
	                  show $(KERNEL_PKG) | grep Depends | head -n 1 | awk '{print $$2}' | tr -d ','); \
	echo "Downloading resolved package: $$PKG..."; \
	cd $(TEST_BOOT_DIR) && apt-get -o Dir::State=$(APT_DIR)/state \
	                           -o Dir::State::status=$(APT_DIR)/state/status \
	                           -o Dir::State::Lists=$(APT_DIR)/state/lists \
	                           -o Dir::Cache=$(APT_DIR)/cache \
	                           -o Dir::Cache::archives=$(APT_DIR)/cache/archives \
	                           -o Dir::Etc=$(APT_DIR)/etc \
	                           -o Dir::Etc::SourceList=$(APT_DIR)/etc/sources.list \
	                           -o Dir::Etc::TrustedParts=$(APT_DIR)/etc/trusted.gpg.d \
	                           download $$PKG
	@echo "Extracting packages..."
	@cd $(TEST_BOOT_DIR) && for f in *.deb; do \
		ar x "$$f" && (tar -xf data.tar.xz 2>/dev/null || tar -xf data.tar.zst 2>/dev/null || tar -xf data.tar.gz 2>/dev/null); \
		rm -f debian-binary control.tar.* data.tar.*; \
	done
	@echo "Locating and copying kernel image..."
	@cd $(TEST_BOOT_DIR) && cp boot/vmlinuz-* ./vmlinuz
	@touch $@

# Package the test initramfs cpio archive
$(INITRAMFS): $(BINARY) $(TEST_BOOT_DIR)/.kernel_extracted
	@echo "[build] Creating initramfs staging area for $(ARCH)..."
	@rm -rf $(STAGING)
	@mkdir -p $(STAGING)/proc $(STAGING)/sys $(STAGING)/dev $(STAGING)/run $(STAGING)/etc $(STAGING)/bin
	@cp $(BINARY) $(STAGING)/init
	@chmod +x $(STAGING)/init
	@mknod -m 600 $(STAGING)/dev/console c 5 1 2>/dev/null || true
	@mknod -m 666 $(STAGING)/dev/null c 1 3 2>/dev/null || true
	@KVER=$$(ls $(TEST_BOOT_DIR)/lib/modules 2>/dev/null | head -n 1); \
	if [ -n "$$KVER" ]; then \
		echo "[build] Staging $(ARCH) kernel modules ($$KVER)..."; \
		mkdir -p $(STAGING)/lib/modules/$$KVER; \
		for mod in virtio virtio_ring virtio_mmio virtio_pci_modern_dev virtio_pci_legacy_dev virtio_pci failover net_failover virtio_net nfnetlink crc32c_generic libcrc32c nf_defrag_ipv4 nf_defrag_ipv6 nf_tables nf_conntrack nf_nat nft_ct nft_chain_nat nft_masq; do \
			found=$$(find "$(TEST_BOOT_DIR)/lib/modules/$$KVER" -name "$${mod}.ko" -o -name "$${mod}.ko.zst" -o -name "$${mod}.ko.xz" -o -name "$${mod}.ko.gz" 2>/dev/null | head -n 1); \
			if [ -n "$$found" ]; then \
				cp "$$found" "$(STAGING)/lib/modules/$$KVER/"; \
			fi; \
		done; \
	fi
	@echo "[build] Packaging initramfs into $(INITRAMFS)..."
	@mkdir -p target/$(ARCH)
	@(cd $(STAGING) && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz)
	@echo "[build] Initramfs archived successfully at: $(INITRAMFS)"

# Run interactive QEMU simulation (host simulation target)
qemu: $(INITRAMFS)
	@./test_qemu.sh

# Run integration tests for the selected ARCH
test: $(INITRAMFS)
	@echo "[test] Running integration tests for target architecture $(ARCH)..."
	@TEST_ARCH=$(ARCH) cargo test --test wan_dhcp_test -- --nocapture

# Clean build artifacts
clean: clean-rpi
	@echo "[clean] Cleaning build target and staging directories..."
	@cargo clean
	@rm -rf target/x86_64 target/arm64 target/armhf

# Include Raspberry Pi deployment build rules
include Makefile.rpi
