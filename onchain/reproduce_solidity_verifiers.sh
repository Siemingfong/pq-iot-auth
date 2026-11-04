#!/bin/sh
# Reproduces the verification gas of the ZKNOX Solidity verifiers used in Table 1.
# Requires Foundry (tested: 1.8.7) and native solc 0.8.25 / 0.8.30 binaries.
set -e
SOLC25=${SOLC25:-solc-0.8.25}; SOLC30=${SOLC30:-solc-0.8.30}
git clone -q https://github.com/ZKNoxHQ/ETHDILITHIUM.git && (cd ETHDILITHIUM && git checkout -q f9f4fe1 && git submodule update --init --recursive -q \
  && forge test --offline --use "$SOLC30" --match-path test/dilithiumKATS.t.sol -vv | grep "Gas used" \
  && forge test --offline --use "$SOLC30" --match-path test/ethdilithiumKAT.t.sol -vv | grep "Gas used")
git clone -q -b exp/packed-verifier https://github.com/ZKNoxHQ/ETHDILITHIUM.git ETHDIL_packed && (cd ETHDIL_packed && git checkout -q f85ca80 && git submodule update --init --recursive -q \
  && forge test --offline --use "$SOLC30" --match-path test/dilithiumKATS.t.sol -vv | grep "Gas used" \
  && forge test --offline --use "$SOLC30" --match-path test/ethdilithiumKAT.t.sol -vv | grep "Gas used")
git clone -q https://github.com/ZKNoxHQ/ETHFALCON.git && (cd ETHFALCON && git checkout -q 43ac863 && git submodule update --init --recursive -q \
  && forge test --offline --use "$SOLC25" --match-path test/Benchmarks.t.sol -vv | grep -E "Verify (NIST|EVM)")
# Measured: ML-DSA-44 NIST main 8,128,360 | optimized 1,192,929 | EVM-friendly optimized 845,438
#           Falcon-512 NIST-compliant 4,818,843 | EVM-friendly 1,547,336
