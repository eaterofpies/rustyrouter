#!/bin/bash
# =========================================================================
# Initramfs Builder Wrapper (Supports ARCH parameter)
# =========================================================================
set -e
ARCH=${TEST_ARCH:-x86_64}
exec make target/${ARCH}/initramfs.cpio.gz ARCH=${ARCH}
