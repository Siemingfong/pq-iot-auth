#!/bin/sh
# Builds liboqs 0.16.0 (signature schemes used in the paper) and installs liboqs-python.
# Tested on Ubuntu 24.04 (x86-64); intended also for Raspberry Pi OS (64-bit).
set -e
sudo apt-get install -y cmake ninja-build git build-essential python3-pip
git clone --depth 1 -b 0.16.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_falcon_512;SIG_falcon_1024;SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_sha2_128f"
ninja -C liboqs/build && sudo ninja -C liboqs/build install && sudo ldconfig
git clone --depth 1 -b 0.16.0 https://github.com/open-quantum-safe/liboqs-python.git
pip install ./liboqs-python coincurve cryptography matplotlib
