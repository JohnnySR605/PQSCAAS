# PQSCAAS Build & Run Guide

This guide walks through building and running PQSCAAS from scratch on a
clean Ubuntu 20.04 / 22.04 system.

---

## 1. Install Dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential git python3 python3-pip \
    libssl-dev pkg-config
```

---

## 2. Install Intel SGX SDK

Two options:

### Option A — One-command installer (recommended)

```bash
bash scripts/install_sgx_sdk.sh
source /opt/intel/sgxsdk/environment
```

### Option B — Manual

```bash
# Download SDK binary (Ubuntu 22.04)
wget https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.25.100.3.bin
chmod +x sgx_linux_x64_sdk_*.bin
sudo ./sgx_linux_x64_sdk_*.bin --prefix=/opt/intel

# Add to shell (optional)
echo 'source /opt/intel/sgxsdk/environment' >> ~/.bashrc
source ~/.bashrc
```

Verify installation:

```bash
echo "$SGX_SDK"   # should print /opt/intel/sgxsdk
ls "$SGX_SDK/lib64/libsgx_urts_sim.so"
ls "$SGX_SDK/bin/x64/sgx_sign"
```

---

## 3. Build PQSCAAS

```bash
cd pqscaas_c
bash scripts/build.sh
```

Or manually:

```bash
make SGX_MODE=SIM SGX_DEBUG=1 -j$(nproc)
```

This produces:
- `app` — untrusted host binary
- `enclave.signed.so` — signed enclave image

---

## 4. Run the Experiments

```bash
# All 12 experiments
bash scripts/run_all.sh

# Single experiment (e.g. Exp 9)
./app 12
```

Results are written to `results/*.csv`.

Approximate runtime (Intel Xeon Platinum 8124M class host, SIM mode):
| Experiment | Time   |
|-----------:|-------:|
| 1          | 2 min  |
| 2          | 3 min  |
| 3          | 5 min  |
| 4          | 1 min  |
| 5          | 2 min  |
| 6          | 1 min  |
| 7          | 2 min  |
| 8          | 8 min  |
| 9          | 2 min  |
| **Total**  | ~25 min |

---

## 5. Generate Figures

```bash
cd plot_scripts
pip install -r requirements.txt
python plot_all.py
```

PNG figures are written to `../figures/`.

---

## 6. Troubleshooting

### "SGX_SDK not set"
```bash
source /opt/intel/sgxsdk/environment
```

### "libsgx_urts_sim.so: cannot open shared object file"
```bash
export LD_LIBRARY_PATH=$SGX_SDK/lib64:$LD_LIBRARY_PATH
```

### "sgx_edger8r: command not found"
```bash
export PATH=$SGX_SDK/bin/x64:$PATH
```

### Enclave signing fails with "no such file Enclave_private.pem"
```bash
openssl genrsa -out Enclave/Enclave_private.pem -3 3072
```

### Running on a machine without SGX
Simulation mode (`SGX_MODE=SIM`) runs anywhere — no CPU check needed.
All measurements in this guide were collected in SIM mode.

---

## 7. Switching to Hardware Mode

If SGX-capable hardware is available:

```bash
# Check SGX
is-sgx-available

# Build for HW
make clean
make SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1 -j$(nproc)
./app all
```

Expect modest latency shifts from real EPC paging; the relative orderings
in the paper (PQSCAAS vs baselines) remain the same.
