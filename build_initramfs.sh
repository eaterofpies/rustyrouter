#!/bin/bash
# =========================================================================
# Initramfs Builder Wrapper
# =========================================================================
# This script is a wrapper around the Makefile to maintain compatibility
# with existing scripts while supporting incremental builds.
# =========================================================================
set -e

exec make target/initramfs.cpio.gz
