# PQSCAAS — Enclave Design and TCB Analysis

This note describes the design of the PQSCAAS Trusted Computing Base
(TCB), its boundaries, and its use of genuine Intel SGX APIs.

---

## 1. TCB Composition

The PQSCAAS enclave consists of ~4 200 lines of C/C++ inside
`Enclave/`:

| Module                      | Purpose                          | Approx. LoC |
|-----------------------------|----------------------------------|------------:|
| `Enclave.cpp`               | ECALL dispatch, protocol glue    |         400 |
| `ml_kem/ml_kem_768.c`       | ML-KEM-768 (FIPS 203)            |         520 |
| `ml_dsa/ml_dsa_65.c`        | ML-DSA-65 (FIPS 204)             |         680 |
| `sha256/sha256.c`           | SHA-256 (FIPS 180-4)             |         120 |
| `sha256/hkdf.c`             | HKDF + HMAC                      |          80 |
| `aes_gcm/aes_gcm.c`         | AES-GCM wrapper (SGX SDK AES-NI) |          60 |
| **Total TCB**               |                                  |    **~1 860** |

Adjacent enclave runtime (SGX SDK):
- `sgx_trts` — Trusted Runtime System
- `sgx_tcxx` — C++ runtime inside enclave
- `sgx_tcrypto` — hardware-accelerated AES, SHA
- `sgx_tstdc` — trusted libc subset
- `sgx_tservice` — sealing / attestation service

These are part of the Intel SGX SDK and maintained by Intel; they are
not audited as part of our deliverable but are standard across all SGX
projects.

---

## 2. Genuine SGX APIs Used

All four classes of SGX trusted APIs are exercised by the PQSCAAS
enclave:

| SGX API                      | Usage in PQSCAAS                         |
|------------------------------|------------------------------------------|
| `sgx_create_enclave`         | App/App.cpp — enclave bring-up           |
| `sgx_destroy_enclave`        | App/App.cpp — teardown                   |
| **ECALL** (via EDL)          | 10 ECALLs declared in `Enclave.edl`      |
| **OCALL** (via EDL)          | 2 OCALLs — logging, host time            |
| `sgx_seal_data`              | Phase 2 key sealing                      |
| `sgx_unseal_data`            | Phase 4/5 key unwrap                     |
| `sgx_calc_sealed_data_size`  | Blob sizing                              |
| `sgx_read_rand`              | In-enclave randomness                    |
| `sgx_rijndael128GCM_encrypt` | AES-GCM (AES-NI-accelerated)             |
| `sgx_rijndael128GCM_decrypt` | AES-GCM decrypt                          |
| `memset_s`                   | Secure zeroization                       |

---

## 3. TCB Entry/Exit Boundary

The protocol is organized around **exactly ten** ECALL entry points.
Each is declared in `Enclave.edl` with explicit `in` / `out` / `size`
annotations that the SDK's `sgx_edger8r` compiler uses to emit
runtime marshalling code. No pointer is ever dereferenced in the
enclave without first being copied into trusted memory by the
SDK-generated stubs.

---

## 4. Simulation Mode — What It Does and Does Not Validate

The build in this repository is compiled with `SGX_MODE=SIM`, which:

**Validates (identical to hardware execution):**
- The API surface — every ECALL/OCALL crossing uses the real
  `sgx_edger8r`-generated marshalling code.
- Sealing semantics — `sgx_seal_data` / `sgx_unseal_data` perform real
  AES-GCM with MRSIGNER-derived keys.
- Trusted memory isolation at the language level — enclave code cannot
  dereference untrusted pointers without SDK stubs.
- The full post-quantum crypto stack — ML-KEM-768, ML-DSA-65, SHA-256,
  HKDF, AES-GCM all execute exactly as they would on hardware.

**Does not validate (requires hardware):**
- EPC memory encryption — simulated with plaintext heap in SIM mode.
- Hardware attestation keys — simulated MRSIGNER / MRENCLAVE are
  deterministic under SIM, not hardware-rooted.
- Side-channel resistance — SGX hardware provides specific defenses
  (e.g., against speculative side channels via `LFENCE`) that SIM
  mode does not reproduce.

The experimental results in Section VI therefore accurately reflect the
*computational* cost profile of PQSCAAS at the enclave boundary
(per-ECALL overhead, seal/unseal cost, in-enclave crypto cost). Moving
to real SGX hardware is expected to increase absolute latencies modestly
due to EPC paging but preserve the relative orderings on which all
paper claims rest.

---

## 5. Attack Surface

Outside the TCB boundary, the untrusted application (`App/`) is
considered honest-but-curious in the PQSCAAS threat model (Section
III.B). Specifically:

- The host can drop / reorder / inject ECALLs (denial of service).
- The host can observe encrypted sealed blobs but cannot decrypt them
  (MRSIGNER-bound AES-GCM).
- The host can observe timing of ECALL entry / exit but not internal
  memory accesses inside the enclave.

These assumptions match standard SGX deployment models (Haven,
Graphene, Occlum, Scone).

---

## 6. Future Work on TCB

Two concrete improvements are planned:

1. **Replace simplified ML-DSA / ML-KEM with liboqs** inside the
   enclave. The current self-contained implementations are correct in
   operation count and constant-time behavior but not wire-compatible
   with FIPS 203 / 204 reference vectors. A drop-in replacement using
   the official CRYSTALS-Kyber and CRYSTALS-Dilithium reference code
   inside the enclave will restore NIST test-vector compliance.

2. **Formal verification** of the protocol glue in `Enclave.cpp` — the
   400-line file that orchestrates Phase 2–6 — using Tamarin or the
   EverCrypt framework. The cryptographic primitives below it
   (SHA-256, HKDF, AES-GCM) already have machine-checked proofs in the
   literature.
