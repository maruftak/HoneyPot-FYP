#!/bin/bash
# honeyPot — Start Script
# Run: sudo ./START.sh
set -e

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}"
cat << 'EOF'
  ╔══════════════════════════════════════════════════════╗
  ║         honeyPot — IoT Threat Intelligence           ║
  ║         Hikvision DS-2CD2043G2-I Emulator            ║
  ╚══════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Root check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Root required for low ports. Run: sudo ./START.sh${NC}"; exit 1
fi

# Python check
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python 3 required${NC}"; exit 1
fi

# Dependencies
echo -e "${GREEN}[1/3] Installing dependencies…${NC}"
pip3 install flask flask-cors requests geoip2 -q --break-system-packages 2>/dev/null || \
pip3 install flask flask-cors requests geoip2 -q 2>/dev/null || true

# Init DB
echo -e "${GREEN}[2/3] Initialising database…${NC}"
python3 -c "import sys; sys.path.insert(0,'$SCRIPT_DIR'); import db; db.init()"

# Optional Telegram env vars
if [ -n "$TELEGRAM_TOKEN" ]; then
    echo -e "${GREEN}[✓] Telegram alerts enabled${NC}"
else
    echo -e "${YELLOW}[!] Telegram disabled — export TELEGRAM_TOKEN and TELEGRAM_CHAT_ID to enable${NC}"
fi

# Start dashboard (background)
echo -e "${GREEN}[3/3] Starting services…${NC}"
python3 "$SCRIPT_DIR/dashboard.py" --port 5001 &
DASH_PID=$!
sleep 1

# Start honeypot (background)
python3 "$SCRIPT_DIR/honeypot.py" &
HP_PID=$!

MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] honeyPot is running!${NC}"
echo ""
echo -e "  Dashboard → ${YELLOW}http://${MY_IP}:5001${NC}"
echo -e "  Also try  → ${YELLOW}http://localhost:5001${NC}"
echo ""
echo -e "  Honeypot PID:   $HP_PID"
echo -e "  Dashboard PID:  $DASH_PID"
echo -e "  Logs dir:       $SCRIPT_DIR/logs/"
echo -e "  Database:       $SCRIPT_DIR/logs/honeypot.db"
echo ""
echo -e "  Stop: Ctrl+C"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

cleanup() {
    echo -e "\n${RED}[!] Shutting down honeyPot…${NC}"
    kill $HP_PID $DASH_PID 2>/dev/null || true
    echo -e "${GREEN}[✓] Stopped.${NC}"
}
trap cleanup EXIT INT TERM
wait
