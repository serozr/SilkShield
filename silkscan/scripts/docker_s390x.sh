#!/usr/bin/env bash
# Rehearse the IBM Z install on an x86_64 machine: build for linux/s390x under QEMU, run the
# tests, then check that the trained model gives the same verdicts as on the source machine.
#
#   docker run --privileged --rm tonistiigi/binfmt --install s390x    # once, enables emulation
#   scripts/docker_s390x.sh [parity_dir]                               # default work/z_transfer/parity
#
# Emulation is slow (the first build compiles LightGBM) and has no NNPA, so only the lightgbm
# backend can be checked here. The model and parity files are mounted read-only from runs/ and work/.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
PARITY=${1:-work/z_transfer/parity}
IMAGE=silkscan:s390x

docker build --platform linux/s390x -f docker/Dockerfile -t "$IMAGE" .
docker run --rm --platform linux/s390x \
    -v "$ROOT/runs:/opt/silkscan/runs:ro" -v "$ROOT/work:/opt/silkscan/work:ro" \
    "$IMAGE" bash -c "
        set -e
        python -c 'import platform, sys; print(\"machine:\", platform.machine(), \"| byte order:\", sys.byteorder)'
        python -m pytest -q -p no:cacheprovider
        python scripts/check_parity.py --serving configs/serving.yaml \
            --records $PARITY/records.jsonl --expected $PARITY/expected.jsonl"
