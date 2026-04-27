#!/usr/bin/env bash
# Clean all build artifacts
set -e
cd "$(dirname "$0")/.."

make clean || true
rm -f Enclave/Enclave_private.pem
rm -rf results figures
mkdir -p results figures
echo "Cleaned."
