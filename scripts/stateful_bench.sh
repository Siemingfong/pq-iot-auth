#!/bin/sh
# Device-side cost of stateful hash-based signatures (LMS, HSS, XMSS) with liboqs 0.16.0 (C).
# Builds liboqs with stateful key generation and signing enabled (hazardous-experimental flag).
set -e
git clone --depth 1 -b 0.16.0 https://github.com/open-quantum-safe/liboqs.git liboqs-stfl
cmake -S liboqs-stfl -B liboqs-stfl/build -GNinja -DOQS_USE_OPENSSL=OFF \
  -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
ninja -C liboqs-stfl/build speed_sig_stfl
for a in LMS_SHA256_H10_W4 LMS_SHA256_H10_W8 LMS_SHA256_H15_W4 LMS_SHA256_H10_W4_H10_W4 XMSS-SHA2_10_256; do
  ./liboqs-stfl/build/tests/speed_sig_stfl -d 1 -i "$a"
done
