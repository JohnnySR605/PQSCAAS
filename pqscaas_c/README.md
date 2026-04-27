# PQSCAAS — Scalable Post-Quantum Signcryption as a Service

**C/C++ implementation with Intel SGX SDK (simulation mode)**

This repository provides a complete C/C++ implementation of the PQSCAAS
framework along with three calibrated baseline comparisons. The PQSCAAS
implementation uses real Intel SGX SDK enclave APIs (sealing, trusted
memory, ECALL/OCALL transitions) executed in simulation mode.

---

## Prerequisites

Before building, make sure you have the following installed on your machine:

| Requirement | Version | Notes |
|-------------|---------|-------|
| OS | Ubuntu 22.04 or 24.04 | Native Linux or WSL2 on Windows |
| Intel SGX SDK | 2.25 | Must be installed at `/opt/intel/sgxsdk` |
| GCC | 11 or newer | Comes with Ubuntu 22.04+ by default |
| GNU Make | any | Comes with Ubuntu by default |
| Python | 3.10+ | For generating figures only |
| pip packages | matplotlib, numpy, pandas | For generating figures only |

---

## Step 1: Install Intel SGX SDK

If you already have the SGX SDK installed at `/opt/intel/sgxsdk`, skip to Step 2.

**Option A — Use the provided script:**

```bash
bash scripts/install_sgx_sdk.sh
```

**Option B — Manual installation:**

```bash
# Download the SGX SDK installer
wget https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu24.04-server/sgx_linux_x64_sdk_2.25.100.3.bin

# Make it executable
chmod +x sgx_linux_x64_sdk_2.25.100.3.bin

# Install (will ask for install path — enter /opt/intel)
sudo ./sgx_linux_x64_sdk_2.25.100.3.bin --prefix=/opt/intel
```

**Verify installation:**

```bash
ls /opt/intel/sgxsdk/
# You should see: bin8x64  include  lib64  SampleCode  ...
```

---

## Step 2: Build the Project

Every time you open a new terminal, you must source the SGX environment first:

```bash
source /opt/intel/sgxsdk/environment
```

Then build:

```bash
cd pqscaas_c
make clean
make SGX_MODE=SIM
```

If the build succeeds, you will see two files:

```
app                  # The main application binary
enclave.signed.so    # The signed SGX enclave
```

If you get errors, check the troubleshooting section at the bottom.

---

## Step 3: Run Experiments

### Delete old results first (important!)

```bash
rm -f results/*.csv figures/*.png
```

### Run all 11 experiments at once

```bash
mkdir -p results figures
./app all
```

This takes approximately 1–3 minutes depending on your hardware. Each experiment prints progress to the terminal and saves a CSV file to `results/`.

### Run a single experiment

```bash
./app 1     # Exp 1: KeyGen vs number of users
./app 2     # Exp 2: Signcrypt vs file size
./app 3     # Exp 3: Batch signcrypt vs number of requests
./app 4     # Exp 4: Unsigncrypt vs file size
./app 5     # Exp 5: Sequential unsigncrypt vs N
./app 6     # Exp 6: Signcrypt throughput vs workload
./app 7     # Exp 7: Unsigncrypt throughput vs workload
./app 8     # Exp 8: Throughput vs request rate (dynamic elastic)
./app 9     # Exp 9: Active enclaves vs request rate
./app 10    # Exp 10: Merkle-root vs CRL revocation verification
./app 11    # Exp 11: Policy update (deferred binding vs re-encryption)
```

### What the output looks like

When you run `./app all`, you should see something like this:

```
=== Experiment 1 ===
[Exp 1] Internal timing unreliable (0.000 ms); using host wall-clock: 0.037 ms
[Exp 1] N = 100 users ...
  Enclaves: 3 | PQSCAAS: 1.2 ms | Bai: 25.4 ms
[Exp 1] N = 1000 users ...
  Enclaves: 26 | PQSCAAS: 1.4 ms | Bai: 254.4 ms
...
[Exp 1] Saved: results/exp1_keygen_vs_users.csv
=== Experiment 2 ===
[Exp 2] File size = 1 KB ...
  PQSCAAS: 0.000 ± 0.000 ms | Sinha: 16.59 | Yu: 0.67 | Bai: 0.11
...
```

After all experiments finish, you should have 11 CSV files in `results/`:

```bash
ls results/
# exp1_keygen_vs_users.csv
# exp2_phase4_vs_filesize.csv
# exp3_signcrypt_batch_vs_requests.csv
# exp4_phase5_vs_filesize.csv
# exp5_unsigncrypt_vs_requests.csv
# exp6_signcrypt_throughput.csv
# exp7_unsigncrypt_throughput.csv
# exp8_throughput_vs_rate.csv
# exp9_active_enclaves_vs_rate.csv
# exp10_merkle_vs_crl.csv
# exp11_policy_update.csv
```

---

## Step 4: Generate Figures

```bash
cd plot_scripts
pip3 install -r requirements.txt --break-system-packages
python3 plot_all.py
cd ..
```

This reads all CSV files from `results/` and generates 11 PNG figures in `figures/`.

To view figures on Windows via WSL2:

```bash
explorer.exe $(wslpath -w figures)
```

---

## Experiment Catalog

| Exp # | Fig # | Experiment | CSV File | PNG File |
|-------|-------|------------|----------|----------|
| 1 | Fig. 1 | KeyGen vs number of users | `exp1_keygen_vs_users.csv` | `fig1_keygen_vs_users.png` |
| 2 | Fig. 2 | Signcrypt vs file size (Phase 4) | `exp2_phase4_vs_filesize.csv` | `fig2_phase4_vs_filesize.png` |
| 3 | Fig. 3 | Batch signcrypt vs number of requests | `exp3_signcrypt_batch_vs_requests.csv` | `fig3_signcrypt_batch_vs_requests.png` |
| 4 | Fig. 4 | Unsigncrypt vs file size (Phase 5) | `exp4_phase5_vs_filesize.csv` | `fig4_phase5_vs_filesize.png` |
| 5 | Fig. 5 | Sequential unsigncrypt vs N | `exp5_unsigncrypt_vs_requests.csv` | `fig5_unsigncrypt_vs_requests.png` |
| 6 | Fig. 6 | Signcrypt throughput vs workload | `exp6_signcrypt_throughput.csv` | `fig6_signcrypt_throughput.png` |
| 7 | Fig. 7 | Unsigncrypt throughput vs workload | `exp7_unsigncrypt_throughput.csv` | `fig7_unsigncrypt_throughput.png` |
| 8 | Fig. 8 | Throughput vs request rate (dynamic elastic) | `exp8_throughput_vs_rate.csv` | `fig8_throughput_vs_rate.png` |
| 9 | Fig. 9 | Active enclaves vs request rate | `exp9_active_enclaves_vs_rate.csv` | `fig9_active_enclaves_vs_rate.png` |
| 10 | Fig. 10 | Merkle-root vs CRL revocation | `exp10_merkle_vs_crl.csv` | `fig10_merkle_vs_crl.png` |
| 11 | Fig. 11 | Policy update (deferred binding vs re-encryption) | `exp11_policy_update.csv` | `fig11_policy_update.png` |

---

## Project Structure

```
pqscaas_c/
├── App/
│   ├── App.cpp              # Main entry point, dispatches ./app 1..11
│   ├── App.h
│   ├── ocalls.cpp           # OCALLs: logging + host wall-clock timing
│   └── bench_common.c
│
├── Enclave/
│   ├── Enclave.cpp          # Trusted code: Phase 2/4/5/6 ECALLs
│   ├── Enclave.edl          # ECALL/OCALL interface definition
│   ├── Enclave.config.xml
│   ├── ml_kem/              # ML-KEM-768 (NIST FIPS 203)
│   ├── ml_dsa/              # ML-DSA-65 (NIST FIPS 204)
│   ├── aes_gcm/             # AES-128-GCM (hardware AES-NI)
│   └── sha256/              # SHA-256 + HKDF
│
├── baselines_c/
│   ├── yu2021/              # Yu et al. 2021 — L-CLSS
│   ├── bai2025/             # Bai et al. 2025 — MLCLOOSC
│   └── sinha2026/           # Sinha et al. 2026 — NTRU-GIBLRSCS
│
├── experiments_c/
│   ├── bench_utils.hpp      # Elastic scaling (Eq. 61), stats helpers
│   ├── exp1_keygen_vs_users.cpp
│   ├── exp2_phase4_vs_filesize.cpp
│   ├── exp3_signcrypt_batch_vs_requests.cpp
│   ├── exp4_phase5_vs_filesize.cpp
│   ├── exp5_6_7.cpp         # Sequential unsigncrypt + throughput exps
│   ├── exp8_throughput_vs_rate.cpp         # Real ECALL bursts
│   ├── exp9_active_enclaves_vs_rate.cpp
│   ├── exp10_merkle_vs_crl.cpp
│   └── exp11_policy_update.cpp
│
├── include/
│   ├── pqscaas_types.h      # Protocol constants and struct definitions
│   ├── bench_common.h
│   └── csv_writer.h
│
├── plot_scripts/
│   ├── plot_all.py          # Reads CSV, generates Fig 1–11
│   └── requirements.txt
│
├── scripts/
│   ├── build.sh
│   ├── install_sgx_sdk.sh
│   └── run_all.sh
│
├── results/                 # CSV output (generated by ./app)
├── figures/                 # PNG output (generated by plot_all.py)
│
├── Makefile
├── README.md                # This file
├── BUILD_GUIDE.md
├── ENCLAVE_DESIGN.md
└── BASELINE_NOTES.md
```

---

## How Measurements Work

### PQSCAAS measurements (Exp 1–7, 8)

All PQSCAAS numbers come from **real ECALLs** into the SGX enclave, timed with the host wall-clock:

```cpp
uint64_t t0 = host_now_ns();          // clock_gettime(CLOCK_MONOTONIC)
ecall_phase4_signcrypt_single(...);   // Real ECALL into enclave
uint64_t t1 = host_now_ns();
double elapsed_ms = (t1 - t0) / 1e6;
```

Experiment 8 (throughput vs request rate) issues real ECALL bursts of 50–5,000 signcryptions per data point, wall-clocked over 5 trials per rate. This produces natural variance in the results.

### Baseline measurements (all experiments)

Baseline costs are **calibrated to the published per-operation costs** from the original papers. The implementations perform real lattice operations (LWE matrix-vector multiply, module-lattice polynomial-vector multiply, NTRU ring operations, Gaussian sampling) but the final timing is calibrated via `calibrate_to_target()` to match the published benchmarks. This is necessary because the original papers ran on different hardware.

**Extrapolation note:** The baselines were designed for small IoT messages (≤ 1 KB). At file sizes beyond 1 KB (Exp 2 and 4), baseline costs are extrapolated using a linear scaling model. The original papers do not provide data at large file sizes, so the extrapolated values may underestimate actual costs.

See `BASELINE_NOTES.md` for full details on parameters, operation profiles, and calibration methodology.

### Cost-model experiments (Exp 9–11)

Experiments 9 (active enclaves), 10 (Merkle vs CRL), and 11 (policy update) use **cost models built from measured primitives**:

- SHA-256 hash time: measured via 5,000-iteration microbenchmark on your machine
- Per-ID memcmp time: measured via 50,000-iteration microbenchmark on your machine
- Network download time: modeled at 1 GB/s LAN throughput (conservative assumption)
- PQSCAAS rebind cost (Exp 11): measured via real `ecall_revoke_rebind_all` ECALL

If Exp 11 prints `Using fallback cost` in stderr, it means the measured per-rebind time was below clock resolution (< 0.001 ms) and the code used a calibrated fallback. This is normal and should be documented in your paper.

---

## Baseline References

### Yu et al. 2021 — L-CLSS

H. Yu, L. Bai, M. Hao, and N. Wang, "Certificateless signcryption scheme from lattice," *IEEE Systems Journal*, vol. 15, no. 2, pp. 2687–2695, Jun. 2021. DOI: 10.1109/JSYST.2020.3007519.

- Platform: Intel CORE i7, 16 GB RAM, Windows 10, MATLAB
- Per-op cost: Signcrypt = 0.665 ms, Unsigncrypt = 0.333 ms
- Parameters: n = 512, q = 8192, M = 3n

### Bai et al. 2025 — MLCLOOSC

Y. Bai, D. He, Z. Yang, M. Luo, and C. Peng, "Efficient Module-Lattice-Based Certificateless Online/Offline Signcryption Scheme for Internet of Medical Things," *IEEE Internet of Things Journal*, vol. 12, no. 14, pp. 27350–27363, Jul. 2025. DOI: 10.1109/JIOT.2025.3562262.

- Platform: Intel Core i5-13600K @ 3.5 GHz, 32 GB RAM, Ubuntu 20.04
- Per-op cost: OffSig = 0.110 ms, OnSig = 0.002 ms, UnSig = 0.112 ms
- Total signcrypt (offline + online): 0.112 ms
- Parameters: Module-lattice N = 256, k = 4, q = 3329
- GitHub: https://github.com/MrBaiii/MLCLOOSC

### Sinha et al. 2026 — NTRU-GIBLRSCS

D. Sinha et al., "Post-Quantum Identity-Based Linkable Ring Signcryption for Edge IoT Devices," *IEEE Transactions on Consumer Electronics*, vol. 72, no. 1, pp. 1876–1889, Feb. 2026. DOI: 10.1109/TCE.2026.3655021.

- Platform: AMD Ryzen 5 4500U, 16 GB RAM, Windows 11
- Per-op cost: Encrypt ≈ 16.5 ms, Decrypt ≈ 16.5 ms (at λ = 128)
- Parameters: NTRU n = 743, q = 2048

---

## Full Reproduction (Start to Finish)

Copy-paste these commands in order. If any step fails, check the troubleshooting section below.

```bash
# 1. Install SGX SDK (skip if already at /opt/intel/sgxsdk)
bash scripts/install_sgx_sdk.sh

# 2. Source the SGX environment (required every time you open a new terminal)
source /opt/intel/sgxsdk/environment

# 3. Build
cd pqscaas_c
make clean
make SGX_MODE=SIM

# 4. Verify build output
ls -la app enclave.signed.so
# Both files should exist

# 5. Delete old results
rm -f results/*.csv figures/*.png

# 6. Create output directories
mkdir -p results figures

# 7. Run all 11 experiments
./app all

# 8. Verify CSV output (should be 11 files)
ls results/*.csv | wc -l
# Expected: 11

# 9. Generate figures
cd plot_scripts
pip3 install -r requirements.txt --break-system-packages
python3 plot_all.py
cd ..

# 10. Verify figure output (should be 11 files)
ls figures/*.png | wc -l
# Expected: 11

# 11. (WSL2 only) Open figures folder in Windows
explorer.exe $(wslpath -w figures)
```

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `make` fails with "No such file sgx_urts.h" | SGX environment not sourced | Run `source /opt/intel/sgxsdk/environment` |
| `make` fails with "sgx_edger8r not found" | SGX SDK not installed correctly | Reinstall: `bash scripts/install_sgx_sdk.sh` |
| `./app` prints "Failed to create enclave" | SGX environment not sourced | Run `source /opt/intel/sgxsdk/environment` |
| `./app` segfaults immediately | Stale build artifacts | Run `make clean && make SGX_MODE=SIM` |
| `plot_all.py` fails with ImportError | Missing Python packages | Run `pip3 install matplotlib numpy pandas --break-system-packages` |
| `plot_all.py` fails with "file not found" | CSV files not generated yet | Run `./app all` first |
| Exp 1 shows "Internal timing unreliable" | Normal in SGX-SIM mode | The code automatically falls back to host wall-clock (no action needed) |
| Exp 11 shows "Using fallback cost" | Per-rebind time below clock resolution | Normal; document in paper that fallback was used |
| Numbers look different from expected | Different hardware | Normal; absolute times vary by CPU, but ratios should be similar |

---

## Academic Integrity

All numbers reported in the paper must come from running this code on your own hardware.

The code performs real ECALLs into the SGX enclave and records wall-clock timing via `clock_gettime(CLOCK_MONOTONIC)`. Every CSV file is generated by the `./app` binary, not by any external tool.

Before submitting your paper:

1. Delete all CSV and PNG files: `rm -f results/*.csv figures/*.png`
2. Rebuild and run everything from scratch: `make clean && make SGX_MODE=SIM && ./app all`
3. Open each CSV file and verify the numbers make sense
4. Regenerate figures: `cd plot_scripts && python3 plot_all.py`
5. Never use figures or numbers generated by an AI tool — always run the code yourself

---

## License

This implementation accompanies the PQSCAAS paper. Baseline implementations are derived from publicly available algorithm descriptions in the cited IEEE papers; please cite the original sources when referencing baseline results.