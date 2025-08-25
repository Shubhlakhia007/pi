#!/usr/bin/env bash
set -euo pipefail

# Minimal setup for Raspberry Pi OS Lite
# - Installs required packages
# - Creates a Python venv
# - Installs Python deps

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "Please run as root: sudo bash rpi/setup.sh" >&2
  exit 1
fi

apt-get update
apt-get install -y python3 python3-venv python3-pip wireless-tools network-manager net-tools

cd "$(dirname "$0")"/..

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt || true

echo "Setup complete. To activate: source .venv/bin/activate"
echo "Run WiFi scanner: python rpi/wifi_scan_pi.py"


