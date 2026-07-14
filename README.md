# E2IBS-5G-Authentication

This repository contains the **E2IBS** implementation (an efficient identity-based
signature scheme for authenticating 5G base stations), the other schemes used in
its evaluation, formal verification, and a full end-to-end 5G deployment where the
**Core-PKG (CPKG)** provisions base-station signing keys over the network.

## Structure

### Crypto scheme implementations
| Scheme | Source |
|--------|--------|
| E2IBS | `E2IBS/FourQ_64bit_and_portable/tests/E2IBS.c` |
| SchnorrQ | `E2IBS/FourQ_64bit_and_portable/tests/crypto_tests.c` |
| Schnorr-HIBS | `E2IBS/FourQ_64bit_and_portable/tests/schnorr-HIBS.c` |
| ARIS | `E2IBS/FourQ_64bit_and_portable/tests/ARIS.c` |
| BLS | `bls/bls_aggregate.cc` |
| SCRA-BGLS | `bls/scra_bls_aggregate.cc` |
| ECDSA | `ECDSA/sign.c` |

### Formal verification
ProVerif model under `Proverif/E2IBS.pv`.

### End-to-end 5G implementation
- `E2IBS-OAI-Integration/` — modified OpenAirInterface **RAN** (gNB + UE). The gNB
  requests its E2IBS key from the Core-PKG over NGAP, signs SIB1, and self-verifies
  it before broadcast; the UE verifies the SIB1 signature under `PK_PKG`.
- `E2IBS-OAI-CN-Integration/` — modified OpenAirInterface **5G core**, containing:
  - **CPKG** (`component/cpkg/`) — the E2IBS Core-PKG (holds `sk_PKG`/`PK_PKG`,
    serves key extraction over REST `POST /keyext`);
  - **AMF** (`component/oai-amf/`) — forwards the base station's `Keyext_Request`
    (NGAP procedure code 53) to the CPKG and returns the key material.

**Authentication flow (Fig. 4, networked mode):**
`gNB → NGAP NGSigningRequest(NRCell_ID) → AMF → REST /keyext → CPKG` derives
`(sk_BS, PK_BS, U_BS)` → `NGAP NGSigningResponse → gNB` installs the key, signs
SIB1, self-verifies, and broadcasts → UE verifies under `PK_PKG`.

**Self-contained mode** (`--e2ibs-selfcontained`): the original demo where the gNB
is its own PKG (local `setup`/`keygen`, no Core-PKG). See
`E2IBS-OAI-CN-Integration/E2IBS_CN_BS_CHANGES.md` for the full change log.

---

## Evaluation scripts

### 1. Crypto micro-benchmarks (per-scheme sign/verify latency)
Each binary runs many iterations and prints microseconds per sign, per verify, and
the end-to-end delay.

- **E2IBS / SchnorrQ / Schnorr-HIBS / ARIS** (FourQ, gcc `-O1` + AVX2):
  ```bash
  cd E2IBS/FourQ_64bit_and_portable
  make ARCH=x64
  ./E2IBS          # E2IBS sign/verify + end-to-end delay
  ./schnorr-HIBS   # Schnorr-HIBS
  ./ARIS           # ARIS
  ./crypto_test    # SchnorrQ
  ```
- **BLS / SCRA-BGLS:**
  ```bash
  cd bls && make
  ./bls_aggregate
  ./scra_bls_aggregate
  ```
- **ECDSA** (needs OpenSSL):
  ```bash
  cd ECDSA && make
  ./sign
  ```

### 2. End-to-end workflow test (Core-PKG ↔ base station ↔ UE)
Builds the CPKG / E2IBS-AMF / gNB / UE Docker images, brings up the full rfsimulator
stack, and asserts the whole E2IBS chain (CPKG key extraction → AMF → gNB key
install → gNB SIB1 self-verify → UE `Sign Verified!`).

- **Location:** `E2IBS-OAI-CN-Integration/scripts/test_e2ibs_e2e.sh`
- **Usage:**
  ```bash
  cd E2IBS-OAI-CN-Integration
  ./scripts/test_e2ibs_e2e.sh              # build images + run + verify + tear down
  SKIP_BUILD=1 ./scripts/test_e2ibs_e2e.sh # reuse already-built images
  KEEP_UP=1    ./scripts/test_e2ibs_e2e.sh # leave the stack running for inspection
  ```
  Self-contained variant (gNB is its own PKG, CPKG idle):
  ```bash
  docker compose \
    -f docker-compose/docker-compose-e2ibs-rfsim.yaml \
    -f docker-compose/docker-compose-e2ibs-selfcontained.override.yaml up -d
  ```

### 3. Key-extraction end-to-end delay benchmark
The gNB fires `N` `Keyext` requests at the Core-PKG over the real NGAP + REST path
(`gNB → AMF → CPKG → AMF → gNB`), sequentially, and logs total / average / min / max
end-to-end delay. (gNB flag: `--e2ibs-keyext-bench N`.)

- **Location:** `E2IBS-OAI-CN-Integration/scripts/bench_keyext.sh`
- **Usage:**
  ```bash
  cd E2IBS-OAI-CN-Integration
  KEYEXT_N=1000 ./scripts/bench_keyext.sh
  ```
  Example result: `1000 requests, total 411.6 ms, avg 411.5 us/req end-to-end`.

### 4. CPKG crypto self-test (fast pre-check)
Standalone round-trip (Setup → KeyExtract → sign → verify) proving the CPKG key
extraction is cryptographically correct; built as `cpkg_selftest` in the CPKG image
and run automatically at the start of `test_e2ibs_e2e.sh`.

- **Source:** `E2IBS-OAI-CN-Integration/component/cpkg/src/cpkg_selftest.c`

---

### Requirements
Docker + Docker Compose for the end-to-end scripts; `asn1c` 0.9.29 is used at RAN
build time to regenerate the custom NGAP messages from `openair3/NGAP/MESSAGES/ASN1/`.
The crypto micro-benchmarks need `gcc`, `libb2` (BLAKE2), and (for BLS/SCRA-BGLS)
PBC + GMP + mbedTLS, and (for ECDSA) OpenSSL.
