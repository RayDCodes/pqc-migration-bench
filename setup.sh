#!/usr/bin/env bash
#
# One-shot setup: builds liboqs (C library, shared build, ML-KEM only for
# speed), installs the Python bindings, and installs the remaining Python
# deps. Tested on Ubuntu 24.04.
#
# Usage:
#   ./setup.sh
#   source ./env.sh          # every new shell before running bench.py/analyze.py
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${ROOT_DIR}/liboqs-install"

echo "==> Installing OS build dependencies (cmake, ninja, libssl-dev)"
if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq cmake ninja-build libssl-dev python3-dev
else
    echo "    Skipping apt-get (not on Debian/Ubuntu) -- make sure cmake, ninja, and OpenSSL headers are installed."
fi

echo "==> Cloning liboqs"
if [ ! -d "${ROOT_DIR}/liboqs" ]; then
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git "${ROOT_DIR}/liboqs"
fi

echo "==> Building liboqs (shared lib, ML-KEM only)"
mkdir -p "${ROOT_DIR}/liboqs/build"
cd "${ROOT_DIR}/liboqs/build"
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" \
    ..
ninja -j"$(nproc)"
ninja install

echo "==> Cloning + installing liboqs-python bindings"
cd "${ROOT_DIR}"
if [ ! -d "${ROOT_DIR}/liboqs-python" ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
fi
pip install --break-system-packages -q "${ROOT_DIR}/liboqs-python"

echo "==> Installing remaining Python dependencies"
pip install --break-system-packages -q -r "${ROOT_DIR}/requirements.txt"

cat > "${ROOT_DIR}/env.sh" <<EOF
export OQS_INSTALL_PATH="${INSTALL_DIR}"
export LD_LIBRARY_PATH="${INSTALL_DIR}/lib:\${LD_LIBRARY_PATH:-}"
EOF

echo ""
echo "==> Done. Before running anything, in every new shell run:"
echo "        source ${ROOT_DIR}/env.sh"
echo ""
echo "    Then:"
echo "        cd src && python3 bench.py --quick   # fast smoke test"
echo "        python3 bench.py --trials 60          # full sweep"
echo "        python3 analyze.py                    # generate charts"
