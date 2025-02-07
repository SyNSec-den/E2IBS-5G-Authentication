# E2IBS-5G-Authentication
This repository contains the E2IBS implemtation and other schemes used in evaluation. 

## Structure
# Crypto Scheme Implementations
E2IBS: `E2IBS/FourQ_64bit_and_portable/tests/E2IBS.c`

SchnorrQ: `E2IBS/FourQ_64bit_and_portable/tests/crypto_tests.c` 

Schnorr-HIBS: `E2IBS/FourQ_64bit_and_portable/tests/schnorr-HIBS.c`

ARIS: `E2IBS/FourQ_64bit_and_portable/tests/ARIS.c`

BLS: `bls/bls_aggregate.cc`

SCRA-BGLS: `bls/scra_bls_aggregate.cc`

ECDSA: `ECDSA/sign.c`

# Formal Verification
ProVerif code under `Proverif/E2IBS.pv`

# End-to-end 5G Implementation
See submodule at `E2IBS-OAI-Integration`