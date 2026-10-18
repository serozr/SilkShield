#!/usr/bin/env bash
# Environment check and installation for IBM Z / LinuxONE (s390x); also works on x86_64.
#
#   scripts/z_setup.sh [--system-packages] [--api] [--yara] [--snapml] [--skip-tests]
#
# Creates .venv in the repository root (override with PYTHON=/path/to/python3.x).
# PyPI has no s390x wheels for numpy, scipy, scikit-learn, lightgbm or yara-python. With
# --system-packages the venv also sees the distribution's packages, so only lightgbm is compiled:
#   Ubuntu/Debian: apt install python3-venv python3-dev python3-numpy python3-scipy python3-sklearn \
#                  python3-yaml python3-yara cmake g++ make git
#   RHEL/SLES:     the same packages under their python3-* names (or use conda)
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
PYTHON=${PYTHON:-python3}
WITH_API=0 WITH_YARA=0 WITH_SNAPML=0 RUN_TESTS=1 VENV_ARGS=""
for a in "$@"; do
    case "$a" in
        --system-packages) VENV_ARGS="--system-site-packages" ;;
        --api) WITH_API=1 ;; --yara) WITH_YARA=1 ;; --snapml) WITH_SNAPML=1 ;; --skip-tests) RUN_TESTS=0 ;;
        *) echo "unknown option: $a"; exit 2 ;;
    esac
done
THREMBER="thrember @ git+https://github.com/FutureComputing4AI/EMBER2024@0ef753e81d98bf209f71b03cd331dfc190b5b54d"
# oscrypto 1.3.0 on PyPI fails on OpenSSL versions such as 3.0.13 (Ubuntu 24.04).
OSCRYPTO="oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8"

echo "== environment"
echo "architecture: $(uname -m)   byte order: $($PYTHON -c 'import sys; print(sys.byteorder)')"
if grep -qw nnpa /proc/cpuinfo 2>/dev/null; then echo "NNPA: present (snapml-nnpa backend possible)"
else echo "NNPA: not present (use lightgbm or snapml)"; fi
if ! $PYTHON -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    echo "Python >= 3.10 is required (found $($PYTHON --version 2>&1)). Set PYTHON=/usr/bin/python3.11 or similar."
    exit 1
fi
for tool in git cmake g++ make; do
    command -v "$tool" >/dev/null || echo "warning: '$tool' not found; needed if a package (e.g. lightgbm) has no prebuilt wheel for $(uname -m)"
done

echo "== virtual environment"
[ -d .venv ] || $PYTHON -m venv $VENV_ARGS .venv
PIP=".venv/bin/python -m pip"
$PIP install -q -U pip wheel || exit 1

echo "== core"
$PIP install -e . || { echo "core installation failed"; exit 1; }

echo "== EMBER v3 feature extractor (thrember)"
# The full thrember package pulls in polars and matplotlib, which have no s390x wheels; the feature
# extractor itself only needs the packages below.
if [ "$(uname -m)" = s390x ] || ! $PIP install -e '.[ember]'; then
    echo "installing thrember's feature extractor and its dependencies only"
    $PIP install --no-deps "$THREMBER" && $PIP install pefile scikit-learn "signify==0.8.1" "$OSCRYPTO" huggingface_hub || exit 1
fi
.venv/bin/python -c "from silkscan.features.groups.ember_v3 import load_thrember_features as f; print('thrember features OK, dim', f().PEFeatureExtractor().dim)" || exit 1

[ $WITH_API -eq 1 ] && { $PIP install -e '.[api]' || exit 1; }
[ $WITH_YARA -eq 1 ] && { $PIP install -e '.[checks]' || echo "warning: yara-python failed; the yara check stays optional"; }
[ $WITH_SNAPML -eq 1 ] && { $PIP install -e '.[snapml]' || echo "warning: snapml failed; use backend lightgbm"; }

if [ $RUN_TESTS -eq 1 ]; then
    echo "== tests"
    $PIP install -q pytest
    .venv/bin/python -m pytest -q -p no:cacheprovider || exit 1
fi
echo "== done. Next: python scripts/fetch_ember2024.py --out <dir>; export EMBER2024_DIR=<dir>; scripts/train_all.sh"
