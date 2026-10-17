# silkscan on Ubuntu 24.04. Built for linux/s390x it rehearses an IBM Z install under QEMU:
#   scripts/docker_s390x.sh
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev python3-pip git cmake g++ make ca-certificates \
        python3-numpy python3-scipy python3-sklearn python3-yaml python3-yara \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/silkscan
# LightGBM has no s390x wheel and compiles slowly under emulation: keep it in its own layer.
RUN python3 -m venv --system-site-packages .venv && .venv/bin/pip install "lightgbm>=4.3" pytest
COPY . .
RUN scripts/z_setup.sh --system-packages --api --yara --skip-tests
ENV PATH=/opt/silkscan/.venv/bin:$PATH
EXPOSE 8090
CMD ["python", "-m", "silkscan.api", "--config", "configs/api.yaml", "--host", "0.0.0.0"]
