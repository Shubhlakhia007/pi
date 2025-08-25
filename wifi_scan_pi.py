#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from typing import List, Dict


def run(cmd: list, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def parse_iwlist(output: str) -> List[Dict]:
    nets = []
    curr = {}
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Cell ") and "Address:" in line:
            if curr.get("ssid") or curr.get("bssid"):
                nets.append(curr)
            curr = {}
            # Example: Cell 01 - Address: AA:BB:CC:DD:EE:FF
            try:
                curr["bssid"] = line.split("Address:")[-1].strip()
            except Exception:
                pass
        elif "ESSID:" in line:
            ssid = line.split("ESSID:")[-1].strip().strip('"')
            curr["ssid"] = ssid or "Hidden"
        elif "Channel:" in line:
            try:
                curr["channel"] = int(line.split(":")[-1].strip())
            except Exception:
                curr["channel"] = "N/A"
        elif "Quality=" in line or "Signal level=" in line:
            # iwlist formats vary; keep raw for now
            if "Signal level=" in line:
                try:
                    part = line.split("Signal level=")[-1].split()[0]
                    if part.endswith("dBm"):
                        curr["signal"] = part
                except Exception:
                    pass
    if curr.get("ssid") or curr.get("bssid"):
        nets.append(curr)
    return nets


def parse_nmcli(output: str) -> List[Dict]:
    nets = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) < 5:
            continue
        nets.append({
            "ssid": parts[0] or "Hidden",
            "bssid": parts[1] or "Unknown",
            "channel": parts[2] or "N/A",
            "signal": (parts[3] + " dBm") if parts[3] and parts[3].lstrip("-+").isdigit() else parts[3],
            "security": parts[4] or "Unknown",
        })
    return nets


def scan_wifi(iface: str) -> List[Dict]:
    # Try iwlist first
    try:
        res = run(["sudo", "iwlist", iface, "scan"], timeout=25)
        if res.returncode == 0 and res.stdout:
            nets = parse_iwlist(res.stdout)
            if nets:
                return nets
    except Exception:
        pass
    # Fallback nmcli
    try:
        res = run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi", "list"], timeout=15)
        if res.returncode == 0 and res.stdout:
            return parse_nmcli(res.stdout)
    except Exception:
        pass
    return []


def print_table(nets: List[Dict]):
    print("\nWiFi Networks:\n" + "=" * 80)
    print(f"{'#':<3} {'SSID':<28} {'BSSID':<18} {'Signal':<10} {'Channel':<7}")
    print("-" * 80)
    for i, n in enumerate(nets, 1):
        ssid = (n.get("ssid") or "Hidden")[:27]
        bssid = (n.get("bssid") or "Unknown")[:17]
        sig = n.get("signal", "N/A")
        chan = str(n.get("channel", "N/A"))
        print(f"{i:<3} {ssid:<28} {bssid:<18} {sig:<10} {chan:<7}")
    print("=" * 80)


def main():
    ap = argparse.ArgumentParser(description="Raspberry Pi WiFi Scanner (Lite)")
    ap.add_argument("--iface", default="wlan0", help="Wireless interface (default: wlan0)")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--watch", type=int, default=0, help="Repeat every N seconds")
    args = ap.parse_args()

    import time
    while True:
        nets = scan_wifi(args.iface)
        if args.json:
            print(json.dumps({"iface": args.iface, "networks": nets}, indent=2))
        else:
            print_table(nets)
        if args.watch <= 0:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    sys.exit(main())


