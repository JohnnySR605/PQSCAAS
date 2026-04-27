#!/usr/bin/env bash
# Build PQSCAAS in SGX simulation mode (no SGX hardware required)
set -e

cd "$(dirname "$0")/.."

if [ -z "$SGX_SDK" ]; then
    if [ -f /opt/intel/sgxsdk/environment ]; then
        source /opt/intel/sgxsdk/environment
    else
        echo "ERROR: SGX_SDK not set. Install Intel SGX SDK from:"
        echo "  https://download.01.org/intel-sgx/"
        echo "Then: source /opt/intel/sgxsdk/environment"
        exit 1
    fi
fi

echo "======================================================================"
echo "PQSCAAS Build"
echo "======================================================================"
echo "SGX_SDK   = $SGX_SDK"
echo "SGX_MODE  = SIM (simulation — no hardware required)"
echo "SGX_DEBUG = 1"
echo

# Generate signing key if missing
if [ ! -f Enclave/Enclave_private.pem ]; then
    echo "Generating enclave signing key..."
    openssl genrsa -out Enclave/Enclave_private.pem -3 3072
fi

# Clean previous builds
make clean

# Build
make SGX_MODE=SIM SGX_DEBUG=1 -j$(nproc)

echo
echo "======================================================================"
echo "Build complete."
echo "  Run:    ./pqscaas_app all   (or: bash scripts/run_all.sh)"
echo "  Plots:  cd plot_scripts && python plot_all.py"
echo "======================================================================"
