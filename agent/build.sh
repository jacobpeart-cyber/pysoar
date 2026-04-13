#!/usr/bin/env bash
#
# Build a single-file PySOAR agent binary for the current host OS/arch.
#
# PyInstaller is NOT a cross-compiler. To ship Windows binaries, run
# this script from a Windows host (use build.bat). To ship Linux x86_64,
# run it from a Linux x86_64 host. For Linux arm64, run on arm64. For
# macOS, run on macOS. CI should have one job per target platform.
#
# Output: dist/pysoar-agent  (Linux/macOS) or dist/pysoar-agent.exe (Windows)
#
# The produced binary is fully self-contained — no Python interpreter,
# no venv, no dependencies. Ship it to customer endpoints as a single
# file and run:
#
#   ./pysoar-agent --server https://pysoar.example.com --enroll <TOKEN>
#   ./pysoar-agent --server https://pysoar.example.com --poll
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[build] Installing build deps..."
python -m pip install --quiet -r requirements-build.txt

PLATFORM="$(python -c 'import platform; print(platform.system().lower())')"
ARCH="$(python -c 'import platform; print(platform.machine().lower())')"
OUT_NAME="pysoar-agent-${PLATFORM}-${ARCH}"

echo "[build] Bundling pysoar_agent.py into ./dist/${OUT_NAME} ..."
python -m PyInstaller \
    --onefile \
    --noconfirm \
    --clean \
    --name "pysoar-agent" \
    --distpath "./dist" \
    --workpath "./build-tmp" \
    --specpath "./build-tmp" \
    pysoar_agent.py

# Rename so shipping multiple platforms side-by-side is unambiguous
if [[ "$PLATFORM" == "windows" ]]; then
    mv "./dist/pysoar-agent.exe" "./dist/${OUT_NAME}.exe"
    BINARY="./dist/${OUT_NAME}.exe"
else
    mv "./dist/pysoar-agent" "./dist/${OUT_NAME}"
    BINARY="./dist/${OUT_NAME}"
fi

# Hash the binary so operators can verify the download matches the
# build artifact (put this on your release page alongside the binary).
SHA256="$(python -c "import hashlib,sys; print(hashlib.sha256(open('${BINARY}','rb').read()).hexdigest())")"

echo ""
echo "[build] OK"
echo "  binary: ${BINARY}"
echo "  size:   $(stat -c '%s' "${BINARY}" 2>/dev/null || stat -f '%z' "${BINARY}") bytes"
echo "  sha256: ${SHA256}"
echo ""
echo "[build] Test the binary with:  ${BINARY} --help"
