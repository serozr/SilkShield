#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# SilkShield — Automated Deployment Script for IBM LinuxONE (s390x)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}   SilkShield -- IBM LinuxONE (s390x) Deployment Setup     ${NC}"
echo -e "${CYAN}============================================================${NC}"

# 1. Architecture Check
ARCH=$(uname -m)
echo -e "[*] Host Architecture: ${YELLOW}${ARCH}${NC}"
if [[ "$ARCH" == "s390x" ]]; then
    echo -e "${GREEN}[+] Verified IBM LinuxONE (s390x) enterprise host!${NC}"
else
    echo -e "${YELLOW}[!] Warning: Running on ${ARCH} (Non-s390x host). Standard deployment proceeding.${NC}"
fi

# 2. Check Prerequisites
echo -e "\n[*] Checking system dependencies..."
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] python3 could not be found. Please install Python 3.10+ first.${NC}"
    exit 1
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "[+] Found Python ${GREEN}${PYTHON_VER}${NC}"

# 3. Environment File
if [ ! -f ".env" ]; then
    echo -e "[*] Creating .env from .env.example..."
    cp .env.example .env
    echo -e "${YELLOW}[!] .env created. Don't forget to configure VIRUSTOTAL_API_KEY if needed.${NC}"
else
    echo -e "[+] .env file already exists."
fi

# 4. Virtual Environment & Dependencies
echo -e "\n[*] Setting up Python virtual environment (.venv)..."
python3 -m venv .venv
source .venv/bin/activate

echo -e "[*] Upgrading pip and installing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo -e "${GREEN}[+] Dependencies installed successfully.${NC}"

# 5. Model Training & Verification
echo -e "\n[*] Training & validating XGBoost risk scoring model..."
python3 -m ml.train

# 6. Start Server in Background (nohup)
PORT=${PORT:-8000}
echo -e "\n[*] Starting SilkShield server on port ${PORT}..."

# Stop any existing instance
pkill -f "uvicorn app.main:app" 2>/dev/null || true

nohup python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" > silkshield.log 2>&1 &
SERVER_PID=$!
echo -e "[+] SilkShield started in background with PID ${GREEN}${SERVER_PID}${NC}."

# 7. Health Check Verification
echo -e "[*] Waiting for server to become healthy..."
sleep 3

HEALTH_STATUS=$(curl -s "http://127.0.0.1:${PORT}/health" || echo "failed")

if [[ "$HEALTH_STATUS" =~ "silkshield" ]]; then
    echo -e "\n${GREEN}============================================================${NC}"
    echo -e "${GREEN}  ✓ SilkShield is ONLINE on IBM LinuxONE!                  ${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo -e "Dashboard URL : ${CYAN}http://$(hostname -I | awk '{print $1}'):${PORT}/${NC}"
    echo -e "Local URL     : ${CYAN}http://127.0.0.1:${PORT}/${NC}"
    echo -e "System Info   : ${CYAN}http://127.0.0.1:${PORT}/system/info${NC}"
    echo -e "Logs          : tail -f silkshield.log"
    echo -e "============================================================"
else
    echo -e "${RED}[-] Health check failed. Check silkshield.log for details:${NC}"
    cat silkshield.log | tail -n 20
    exit 1
fi
