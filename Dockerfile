# ═══════════════════════════════════════════════════════════════
# SilkShield — Multi-Arch Container Image (IBM LinuxONE / s390x & amd64)
# ═══════════════════════════════════════════════════════════════

FROM python:3.11-slim AS runtime

# System labels for IBM LinuxONE / Datathon tracking
LABEL maintainer="SilkShield Team <dev@silkshield.ai>"
LABEL description="SilkShield AI-Powered Threat Decision Engine on IBM LinuxONE"
LABEL org.opencontainers.image.architecture="s390x,amd64"

# Set environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    APP_HOME=/app

WORKDIR $APP_HOME

# Install minimal build and networking tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    build-essential \
    cmake \
    gfortran \
    libopenblas-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

# Ensure model directory exists and model is trained
RUN python -m ml.train

# Expose HTTP port
EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

# Start Uvicorn ASGI server
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"]
