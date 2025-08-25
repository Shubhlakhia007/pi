#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "Please run as root: sudo bash rpi/install_service.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p /var/log
touch /var/log/wifi_scanner.log

cat > /etc/systemd/system/wifi-scanner.service <<'UNIT'
[Unit]
Description=Raspberry Pi WiFi Scanner (Lite)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=REPO_ROOT
ExecStart=REPO_ROOT/.venv/bin/python rpi/wifi_scan_pi.py --watch 30
Restart=on-failure
StandardOutput=append:/var/log/wifi_scanner.log
StandardError=append:/var/log/wifi_scanner.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

sed -i "s|REPO_ROOT|$REPO_ROOT|g" /etc/systemd/system/wifi-scanner.service

systemctl daemon-reload
echo "Installed wifi-scanner.service. Enable with: sudo systemctl enable --now wifi-scanner.service"


