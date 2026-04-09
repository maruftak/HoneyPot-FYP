#!/bin/bash
# Deploy daily PDF report to server and set up systemd timer
set -e

SERVER="ubuntu@65.1.44.47"
KEY="$HOME/Downloads/honeypot4.pem"
PORT="2223"
REMOTE="/home/ubuntu/honeyPot"

echo "[deploy] Copying daily_report.py..."
scp -i "$KEY" -P "$PORT" daily_report.py "${SERVER}:${REMOTE}/daily_report.py"

echo "[deploy] Installing Python dependencies..."
ssh -i "$KEY" -p "$PORT" "$SERVER" "cd ${REMOTE} && ./venv/bin/pip install -q reportlab matplotlib requests numpy"

echo "[deploy] Creating systemd service & timer..."
ssh -i "$KEY" -p "$PORT" "$SERVER" "sudo tee /etc/systemd/system/honeyPot-report.service > /dev/null << 'EOF'
[Unit]
Description=honeyPot Daily PDF Report
After=network.target

[Service]
Type=oneshot
User=ubuntu
WorkingDirectory=/home/ubuntu/honeyPot
ExecStart=/home/ubuntu/honeyPot/venv/bin/python /home/ubuntu/honeyPot/daily_report.py
StandardOutput=append:/var/log/honeyPot_report.log
StandardError=append:/var/log/honeyPot_report.log
EOF"

ssh -i "$KEY" -p "$PORT" "$SERVER" "sudo tee /etc/systemd/system/honeyPot-report.timer > /dev/null << 'EOF'
[Unit]
Description=honeyPot Daily Report — runs at 08:00 UTC
Requires=honeyPot-report.service

[Timer]
OnCalendar=*-*-* 08:00:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF"

echo "[deploy] Enabling and starting timer..."
ssh -i "$KEY" -p "$PORT" "$SERVER" "sudo systemctl daemon-reload && sudo systemctl enable --now honeyPot-report.timer"

echo "[deploy] Timer status:"
ssh -i "$KEY" -p "$PORT" "$SERVER" "sudo systemctl list-timers honeyPot-report.timer --no-pager"

echo ""
echo "[deploy] Done! Report will run daily at 08:00 UTC."
echo "[deploy] To test immediately: ssh -i $KEY -p $PORT $SERVER 'cd /home/ubuntu/honeyPot && ./venv/bin/python daily_report.py'"
