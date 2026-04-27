#!/usr/bin/env bash
# Install Intel SGX SDK on Ubuntu 20.04 / 22.04
set -e

echo "======================================================================"
echo "Intel SGX SDK installer (Ubuntu 20.04 / 22.04)"
echo "======================================================================"

UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
SDK_VERSION="2.25.100.3"

case "$UBUNTU_VER" in
    20.04) DISTRO="ubuntu20.04-server" ;;
    22.04) DISTRO="ubuntu22.04-server" ;;
    *)     DISTRO="ubuntu22.04-server" ;;
esac

# Prerequisites
sudo apt-get update
sudo apt-get install -y \
    build-essential python3 libssl-dev libcurl4-openssl-dev \
    protobuf-compiler libprotobuf-dev debhelper cmake reprepro \
    unzip pkgconf libboost-dev libboost-system-dev libboost-thread-dev \
    lsb-release libsystemd0

# Download SDK binary installer
cd /tmp
BIN="sgx_linux_x64_sdk_${SDK_VERSION}.bin"
URL="https://download.01.org/intel-sgx/sgx-linux/2.25/distro/${DISTRO}/${BIN}"

if [ ! -f "$BIN" ]; then
    echo "Downloading: $URL"
    wget "$URL"
fi

chmod +x "$BIN"

# Install to /opt/intel
sudo mkdir -p /opt/intel
cd /opt/intel
sudo /tmp/$BIN --prefix=/opt/intel <<< $'no\n/opt/intel\n'

echo
echo "SDK installed to /opt/intel/sgxsdk"
echo
echo "Activate with:"
echo "  source /opt/intel/sgxsdk/environment"
echo
echo "Add to ~/.bashrc for permanent use:"
echo '  echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc'
