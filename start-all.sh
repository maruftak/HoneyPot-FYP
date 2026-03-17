#!/bin/bash

cd "$(dirname "$0")"

echo "[*] Starting honeyPot Dashboard..."
nohup python3 dashboard.py --port 5001 > logs/dashboard.log 2>&1 &

echo "[*] Starting Telnet Honeypot..."
nohup python3 src/telnet_server.py > logs/telnet_server.log 2>&1 &

# Uncomment if you want to run the main honeypot.py as well
# echo "[*] Starting Main Honeypot..."
# nohup python3 honeypot.py > logs/honeypot.log 2>&1 &

echo "[*] All services started!"
echo "Dashboard: http://localhost:5001"
