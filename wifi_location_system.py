#!/usr/bin/env python3
"""
WiFi-Based Location System

A complete system for creating location anchors using WiFi devices.
Features:
- Automatic network device scanning
- WiFi device scanning with SSID and BSSID information
- Automatic coordinate generation
- Database storage
- Phone communication via WiFi
- JSON export functionality
"""

import os
import sys
import time
import json
import sqlite3
import socket
import threading
import random
import subprocess
import platform
import re
import math
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from pathlib import Path

class WiFiLocationSystem:
    def __init__(self, db_path="data/wifi_location.db"):
        """Initialize the WiFi-based location system."""
        self.db_path = db_path
        self.phone_mac = None
        self.phone_ip = None
        self.anchors = []
        self.running = True
        
        # Create database
        self._init_database()
        
        # Load existing anchors
        self._load_anchors()
        
        print("🌐 WiFi-Based Location System Initialized")
        print(f"📊 Database: {self.db_path}")
        print(f"📍 Loaded {len(self.anchors)} existing anchors")
    
    def _init_database(self):
        """Initialize the database with required tables."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create anchors table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS anchors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            x_coord REAL NOT NULL,
            y_coord REAL NOT NULL,
            z_coord REAL DEFAULT 0,
            anchor_number INTEGER UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            phone_mac TEXT,
            phone_ip TEXT,
            bssid TEXT,
            ssid TEXT,
            signal_strength INTEGER,
            channel INTEGER
        )
        ''')
        
        # Create phone table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS phone (
            id INTEGER PRIMARY KEY,
            mac_address TEXT UNIQUE,
            ip_address TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create devices table for scanned devices
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scanned_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT,
            bssid TEXT UNIQUE,
            signal_strength INTEGER,
            channel INTEGER,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create IoT devices table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT UNIQUE,
            device_type TEXT,
            x_coord REAL,
            y_coord REAL,
            z_coord REAL,
            rssi_values TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create RSSI mapping table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rssi_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_id INTEGER,
            device_id TEXT,
            rssi_value INTEGER,
            distance REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (anchor_id) REFERENCES anchors (id)
        )
        ''')
        
        conn.commit()
        conn.close()
        print(f"✅ Database initialized: {self.db_path}")
    
    def _load_anchors(self):
        """Load existing anchors from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM anchors ORDER BY anchor_number')
        rows = cursor.fetchall()
        
        self.anchors = []
        for row in rows:
            self.anchors.append({
                'id': row[0],
                'name': row[1],
                'x_coord': row[2],
                'y_coord': row[3],
                'z_coord': row[4],
                'anchor_number': row[5],
                'created_at': row[6],
                'phone_mac': row[7],
                'phone_ip': row[8],
                'bssid': row[9],
                'ssid': row[10],
                'signal_strength': row[11],
                'channel': row[12]
            })
        
        conn.close()
    
    def scan_for_devices(self):
        """Scan for devices that can be used for positioning (phones, computers, IoT)."""
        print("\n📱 === Scanning for Devices ===")
        print("Scanning for devices that can be used for positioning...")
        
        all_devices = []
        
        try:
            # Get local network information
            local_ip = self._get_local_ip()
            network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'
            
            print(f"📍 Local IP: {local_ip}")
            print(f"🌐 Scanning network: {network_prefix}0/24")
            
            # 1. Scan for actual devices connected to the network
            print("\n📱 Scanning for devices connected to the network...")
            network_devices = self._scan_for_network_devices(network_prefix)
            print(f"   Found {len(network_devices)} network devices")
            all_devices.extend(network_devices)
            
            # 2. Specifically scan for mobile devices
            print("\n📱 Scanning for mobile devices...")
            mobile_devices = self._scan_for_mobile_devices(network_prefix)
            print(f"   Found {len(mobile_devices)} mobile devices")
            if mobile_devices:
                all_devices.extend(mobile_devices)
            
            print(f"\n📊 Total devices found: {len(all_devices)}")
            
            if all_devices:
                self._display_all_devices(all_devices)
                return all_devices
            else:
                print("❌ No devices found on network")
                return []
                
        except Exception as e:
            print(f"❌ Error scanning network: {e}")
            return []
    
    def _get_local_ip(self):
        """Get the local IP address."""
        try:
            # Create a socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "192.168.1.100"  # Fallback
    
    def _scan_network_range(self, network_prefix):
        """Scan network range for devices."""
        devices = []
        
        # Common ports to check
        ports = [80, 443, 8080, 22, 21, 23, 25, 53, 110, 143, 993, 995]
        
        print("🔍 Scanning for devices...")
        
        # Scan first 50 IP addresses in the range
        for i in range(1, 51):
            ip = network_prefix + str(i)
            
            # Quick ping test
            if self._ping_host(ip):
                # Check for open ports
                open_ports = self._check_ports(ip, ports)
                if open_ports:
                    device_info = self._get_device_info(ip, open_ports)
                    devices.append(device_info)
        
        return devices
    
    def _ping_host_fast(self, ip):
        """Fast ping with shorter timeout."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '300', ip], 
                                      capture_output=True, text=True, timeout=1)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=1)
            
            return result.returncode == 0
        except:
            return False
    
    def _ping_host(self, ip):
        """Ping a host to check if it's alive."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True, timeout=2)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, text=True, timeout=2)
            
            return result.returncode == 0
        except:
            return False
    
    def _check_ports_fast(self, ip, ports):
        """Fast port check with shorter timeout."""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Increased timeout for Windows
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                # Don't treat error 10035 as a failure - device exists but ports may be blocked
                elif result != 10035:  # Windows non-blocking socket error
                    continue
            except Exception as e:
                # Log but continue scanning
                continue
        
        return open_ports
    
    def _check_ports(self, ip, ports):
        """Check which ports are open on a device."""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)  # Increased timeout
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                # Don't treat error 10035 as a failure - device exists but ports may be blocked
                elif result != 10035:  # Windows non-blocking socket error
                    continue
            except Exception as e:
                # Log but continue scanning
                continue
        
        return open_ports
    
    def _get_device_info(self, ip, open_ports):
        """Get device information based on open ports."""
        device_type = "Unknown"
        
        if 80 in open_ports or 443 in open_ports:
            device_type = "Web Server"
        elif 22 in open_ports:
            device_type = "SSH Server"
        elif 8080 in open_ports:
            device_type = "Phone Simulator"
        elif 21 in open_ports:
            device_type = "FTP Server"
        elif 23 in open_ports:
            device_type = "Telnet Server"
        
        return {
            'ip': ip,
            'type': device_type,
            'ports': open_ports,
            'mac': self._get_mac_address(ip)
        }
    
    def _scan_for_network_devices(self, network_prefix):
        """Simple WiFi-style device discovery - just like opening WiFi settings."""
        devices = []
        print(f"🔍 Scanning for devices in {network_prefix}0/24...")
        
        # Simple approach: just check ARP table (like WiFi settings do)
        print("   📱 Checking connected devices (like WiFi settings)...")
        arp_devices = self._scan_arp_table_simple(network_prefix)
        devices.extend(arp_devices)
        
        # Also do a quick ping sweep for any devices that might not be in ARP
        print("   📡 Quick network scan...")
        ping_devices = self._quick_ping_scan(network_prefix)
        devices.extend(ping_devices)
        
        # Remove duplicates
        unique_devices = []
        seen_ips = set()
        for device in devices:
            if device['ip'] not in seen_ips:
                unique_devices.append(device)
                seen_ips.add(device['ip'])
        
        return unique_devices
    
    def _scan_arp_table_simple(self, network_prefix):
        """Simple ARP scan - just like WiFi settings show connected devices."""
        devices = []
        try:
            # Just run arp -a and parse it simply
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    # Look for lines with our network prefix
                    if network_prefix in line:
                        # Simple parsing - just get IP and MAC
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if network_prefix in part and self._is_valid_ip(part):
                                ip = part
                                # Look for MAC address (next part that looks like MAC)
                                mac = "Unknown"
                                for j in range(i+1, min(i+3, len(parts))):
                                    if self._is_valid_mac(parts[j]):
                                        mac = parts[j]
                                        break
                                
                                device_info = {
                                    'ip': ip,
                                    'mac': mac,
                                    'type': 'Connected Device',
                                    'ports': [],
                                    'device_category': 'Network_Device',
                                    'ssid': 'Local Network',
                                    'discovery_method': 'ARP Table'
                                }
                                devices.append(device_info)
                                break  # Found this IP, move to next line
        except Exception as e:
            print(f"   ⚠️  ARP scan error: {e}")
        
        return devices
    
    def _quick_ping_scan(self, network_prefix):
        """Quick ping scan for any devices not in ARP table."""
        devices = []
        
        # Just check a few common IPs quickly
        common_ips = [1, 2, 10, 20, 50, 100, 200, 254]
        
        for i in common_ips:
            ip = f"{network_prefix}{i}"
            if self._ping_host_fast(ip):
                # Check if we already found this IP in ARP
                mac = self._get_mac_address(ip)
                device_info = {
                    'ip': ip,
                    'mac': mac or 'Unknown',
                    'type': 'Network Device',
                    'ports': [],
                    'device_category': 'Network_Device',
                    'ssid': 'Your WiFi',
                    'discovery_method': 'Ping'
                }
                devices.append(device_info)
        
        return devices
    
    def _scan_active_network(self, network_prefix):
        """Actively discover devices by sending network probes."""
        devices = []
        
        # Send broadcast packets to discover devices
        try:
            # Use nmap-style discovery if available, otherwise use ping sweep
            if self._has_nmap():
                devices = self._nmap_discovery(network_prefix)
            else:
                devices = self._ping_discovery(network_prefix)
        except Exception as e:
            print(f"   ⚠️  Active discovery error: {e}")
        
        return devices
    
    def _scan_ping_sweep(self, network_prefix):
        """Enhanced ping sweep to find responsive devices."""
        devices = []
        
        # Scan common IP ranges where devices are likely to be
        common_ranges = [
            (1, 50),      # Common DHCP range start
            (100, 150),   # DHCP range middle
            (200, 254)    # DHCP range end
        ]
        
        for start, end in common_ranges:
            for i in range(start, end + 1):
                ip = f"{network_prefix}{i}"
                if self._ping_host_fast(ip):
                    # Get MAC address if possible
                    mac = self._get_mac_address(ip)
                    device_info = {
                        'ip': ip,
                        'mac': mac or 'Unknown',
                        'type': 'Network Device (Ping)',
                        'ports': [],
                        'device_category': 'Connected_Device',
                        'ssid': 'Local Network',
                        'discovery_method': 'Ping Sweep'
                    }
                    devices.append(device_info)
        
        return devices
    
    def _has_nmap(self):
        """Check if nmap is available on the system."""
        try:
            result = subprocess.run(['nmap', '--version'], capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def _nmap_discovery(self, network_prefix):
        """Use nmap for fast network discovery."""
        devices = []
        try:
            network = f"{network_prefix}0/24"
            result = subprocess.run(['nmap', '-sn', network], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            ip = parts[4]
                            if self._is_valid_ip(ip):
                                mac = self._get_mac_address(ip)
                                device_info = {
                                    'ip': ip,
                                    'mac': mac or 'Unknown',
                                    'type': 'Network Device (Nmap)',
                                    'ports': [],
                                    'device_category': 'Connected_Device',
                                    'ssid': 'Local Network',
                                    'discovery_method': 'Nmap'
                                }
                                devices.append(device_info)
        except Exception as e:
            print(f"   ⚠️  Nmap discovery error: {e}")
        
        return devices
    
    def _ping_discovery(self, network_prefix):
        """Fallback ping-based discovery."""
        devices = []
        
        # Quick ping sweep of common ranges
        for i in range(1, 51):
            ip = f"{network_prefix}{i}"
            if self._ping_host_fast(ip):
                mac = self._get_mac_address(ip)
                device_info = {
                    'ip': ip,
                    'mac': mac or 'Unknown',
                    'type': 'Network Device (Ping)',
                    'ports': [],
                    'device_category': 'Connected_Device',
                    'ssid': 'Local Network',
                    'discovery_method': 'Ping'
                }
                devices.append(device_info)
        
        return devices
    
    def _is_valid_ip(self, ip):
        """Check if string is a valid IP address."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or int(part) < 0 or int(part) > 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_mac(self, mac):
        """Check if string is a valid MAC address."""
        import re
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(mac_pattern.match(mac))
    
    def create_iot_positioning_map(self):
        """Create a positioning map using IoT devices as reference points."""
        print("\n🗺️  Creating IoT Positioning Map...")
        
        # Get all IoT devices
        iot_devices = []
        for device in self.anchors:
            if 'IoT' in device.get('type', ''):
                iot_devices.append(device)
        
        if not iot_devices:
            print("❌ No IoT devices found for positioning")
            return None
        
        print(f"✅ Found {len(iot_devices)} IoT devices for positioning")
        
        # Create simple positioning grid
        positioning_map = {}
        for i, device in enumerate(iot_devices):
            # Assign positions in a grid pattern
            x = (i % 3) * 100  # 3 columns
            y = (i // 3) * 100  # Rows
            z = 0
            
            positioning_map[device['ip']] = {
                'x': x,
                'y': y,
                'z': z,
                'type': device['type'],
                'ports': device.get('ports', []),
                'category': 'IoT_Positioning_Anchor'
            }
        
        return positioning_map
    
    def _get_network_device_info(self, ip, open_ports):
        """Get information about a device on the network."""
        # Determine device type and category
        device_type = self._identify_device_type(open_ports)
        device_category = self._categorize_device_by_ports(open_ports)
        
        # Get MAC address
        mac = self._get_mac_address(ip)
        
        # Try to get WiFi SSID if this is a wireless device
        ssid = self._get_device_ssid(ip, mac)
        
        return {
            'ip': ip,
            'type': device_type,
            'ports': open_ports,
            'mac': mac,
            'device_category': device_category,
            'ssid': ssid
        }
    
    def _identify_device_type(self, ports):
        """Identify the type of device based on open ports."""
        if not ports:  # No open ports (likely blocked by firewall)
            return "Network Device (Firewall Protected)"
        elif 1883 in ports or 5683 in ports:
            return "IoT Device (MQTT/CoAP)"
        elif 8080 in ports or 3000 in ports or 5000 in ports or 8000 in ports:
            return "Phone/Tablet (Mobile Device)"
        elif 3389 in ports:
            return "Windows Computer"
        elif 22 in ports:
            return "Linux/Mac Computer"
        elif 5900 in ports:
            return "Remote Desktop Device"
        elif 80 in ports or 443 in ports:
            return "Web-Enabled Device"
        else:
            return "Network Device"
    
    def _categorize_device_by_ports(self, ports):
        """Categorize device based on open ports."""
        if 1883 in ports or 5683 in ports:
            return 'IoT_Device'
        elif 8080 in ports:
            return 'Mobile_Device'
        elif 22 in ports or 3389 in ports:
            return 'Computer'
        elif 80 in ports or 443 in ports:
            return 'Web_Device'
        else:
            return 'Network_Device'
    
    def _scan_for_smart_devices(self, network_prefix):
        """Scan for IoT and smart devices."""
        devices = []
        print(f"🔍 Scanning for smart devices in {network_prefix}0/24...")
        
        # Common IoT ports to scan
        iot_ports = [1883, 5683, 80, 443, 8080, 8883, 8884, 1884, 8880, 9001]
        
        for i in range(1, 255):
            ip = f"{network_prefix}{i}"
            if self._ping_host(ip):
                # Check for IoT services
                iot_info = self._check_iot_services(ip, iot_ports)
                if iot_info:
                    devices.append(iot_info)
        
        return devices
    
    def _categorize_device(self, device_info):
        """Categorize device based on ports and characteristics."""
        ports = device_info.get('ports', [])
        
        # Common port patterns for different device types
        if 80 in ports or 443 in ports:
            if 22 in ports or 23 in ports:
                return 'Computer_Server'
            elif 8080 in ports or 3000 in ports:
                return 'Development_Device'
            else:
                return 'Web_Device'
        elif 22 in ports or 23 in ports:
            return 'Computer_Server'
        elif 3389 in ports:
            return 'Windows_Device'
        elif 5900 in ports:
            return 'Remote_Desktop_Device'
        else:
            return 'Network_Device'
    
    def _check_iot_services(self, ip, iot_ports):
        """Check if a device has IoT services running."""
        for port in iot_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Found IoT service, get device info
                    device_type = self._identify_iot_device_type(port)
                    return {
                        'ip': ip,
                        'type': f"IoT: {device_type}",
                        'ports': [port],
                        'mac': self._get_mac_address(ip),
                        'service': f"Port {port}",
                        'device_category': 'IoT_Device'
                    }
            except:
                continue
        
        return None
    
    def _get_device_ssid(self, ip, mac):
        """Try to get the WiFi SSID that a device is connected to."""
        try:
            if platform.system() == "Windows":
                # Use netsh to get connected WiFi info
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    # Parse to find current connected SSID
                    lines = result.stdout.split('\n')
                    current_ssid = None
                    for line in lines:
                        if 'SSID' in line and 'BSSID' not in line:
                            current_ssid = line.split(':')[1].strip() if ':' in line else None
                            break
                    
                    # If we found current SSID, check if this device might be on it
                    if current_ssid and current_ssid != "":
                        return current_ssid
                    
            # Fallback: try to determine from MAC address patterns
            if mac and mac != "Unknown":
                # Check if MAC suggests it's a wireless device
                if self._is_wireless_device(mac):
                    return "Wireless Device"
            
            return "Wired Device"
            
        except:
            return "Unknown"
    
    def _is_wireless_device(self, mac):
        """Check if MAC address suggests it's a wireless device."""
        try:
            # Common wireless device MAC prefixes
            wireless_prefixes = [
                "00:1A:11", "00:1B:63", "00:1C:B3", "00:1D:7D", "00:1E:58",
                "00:1F:3A", "00:21:6A", "00:22:6B", "00:23:76", "00:24:E4",
                "00:25:90", "00:26:08", "00:27:84", "00:28:F8", "00:29:15",
                "00:2A:6A", "00:2B:0E", "00:2C:41", "00:2D:76", "00:2E:3C"
            ]
            
            mac_upper = mac.upper().replace('-', ':')
            for prefix in wireless_prefixes:
                if mac_upper.startswith(prefix):
                    return True
            
            return False
        except:
            return False
    
    def _scan_for_mobile_devices(self, network_prefix):
        """Simple mobile device scan - just like WiFi shows phones/tablets."""
        print(f"📱 Scanning for mobile devices in {network_prefix}0/24...")
        mobile_devices = []
        
        # Just check if any devices we found look like mobile devices
        # (This will be populated by the main network scan)
        return mobile_devices
    
    def scan_network_devices(self):
        """Scan for network devices - main entry point for device scanning."""
        return self.scan_for_devices()
    
    def _identify_iot_device_type(self, port):
        """Identify IoT device type based on port."""
        iot_ports = {
            1883: 'MQTT_Broker',
            5683: 'CoAP_Device',
            80: 'HTTP_Device',
            443: 'HTTPS_Device',
            8080: 'Web_Server',
            8883: 'MQTT_SSL',
            8884: 'MQTT_WebSocket',
            1884: 'MQTT_Alternative',
            8880: 'Web_Interface',
            9001: 'WebSocket_Server'
        }
        return iot_ports.get(port, 'Unknown_IoT')
    
    def _scan_for_connected_devices(self, network_prefix):
        """Scan for devices actually connected to WiFi networks (phones, laptops, etc.)."""
        devices = []
        print(f"🔍 Looking for devices connected to WiFi in {network_prefix}0/24...")
        
        # Common ports for connected devices
        device_ports = [80, 443, 8080, 22, 3389, 5900, 3000, 5000, 8000]
        
        for i in range(1, 255):
            ip = f"{network_prefix}{i}"
            if self._ping_host(ip):
                # Check if this is a connected device (not just infrastructure)
                device_info = self._get_connected_device_info(ip, device_ports)
                if device_info:
                    devices.append(device_info)
        
        return devices
    
    def _get_connected_device_info(self, ip, ports):
        """Get information about a device connected to WiFi."""
        open_ports = self._check_ports(ip, ports)
        if not open_ports:
            return None
        
        # Determine device type based on open ports and characteristics
        device_type = self._identify_connected_device_type(open_ports)
        
        return {
            'ip': ip,
            'type': device_type,
            'ports': open_ports,
            'mac': self._get_mac_address(ip),
            'device_category': 'Connected_Device'
        }
    
    def _identify_connected_device_type(self, ports):
        """Identify the type of connected device based on open ports."""
        if 8080 in ports:
            return "Phone/Tablet"
        elif 3389 in ports:
            return "Windows Computer"
        elif 22 in ports:
            return "Linux/Mac Computer"
        elif 5900 in ports:
            return "Remote Desktop Device"
        elif 3000 in ports or 5000 in ports or 8000 in ports:
            return "Development Device"
        elif 80 in ports or 443 in ports:
            return "Web-Enabled Device"
        else:
            return "Connected Device"
    
    def _get_mac_address(self, ip):
        """Get MAC address from ARP table."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], 
                                      capture_output=True, text=True, timeout=2)
            else:
                result = subprocess.run(['arp', '-n', ip], 
                                      capture_output=True, text=True, timeout=2)
            
            # Parse MAC address from output
            output = result.stdout
            mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
            match = re.search(mac_pattern, output)
            
            if match:
                return match.group(0)
            else:
                return "Unknown"
        except:
            return "Unknown"
    
    def _display_all_devices(self, devices):
        """Display all found devices with categories and SSID info."""
        print(f"\n📱 Found {len(devices)} devices for positioning:")
        print("=" * 140)
        print(f"{'#':<3} {'IP Address':<18} {'Device Type':<20} {'MAC Address':<18} {'Discovery':<15}")
        print("-" * 80)
        
        for i, device in enumerate(devices, 1):
            device_type = device['type']
            mac_addr = device['mac']
            discovery = device.get('discovery_method', 'Unknown')
            
            print(f"{i:<3} {device['ip']:<18} {device_type:<20} {mac_addr:<18} {discovery:<15}")
        
        print("=" * 80)
    
    def _display_network_devices(self, devices):
        """Display found network devices."""
        print(f"\n📱 Found {len(devices)} devices on network:")
        print("=" * 80)
        print(f"{'#':<3} {'IP Address':<15} {'Type':<20} {'MAC Address':<18} {'Open Ports':<15}")
        print("-" * 80)
        
        for i, device in enumerate(devices, 1):
            ports_str = ', '.join(map(str, device['ports'][:3]))  # Show first 3 ports
            if len(device['ports']) > 3:
                ports_str += "..."
            
            print(f"{i:<3} {device['ip']:<15} {device['type']:<20} {device['mac']:<18} {ports_str:<15}")
        
        print("=" * 80)
    
    def select_network_device(self):
        """Let user select a device from the network scan."""
        devices = self.scan_network_devices()
        
        if not devices:
            print("❌ No devices found on network!")
            return None
        
        try:
            device_id = int(input(f"\nSelect device (1-{len(devices)}): "))
            if device_id < 1 or device_id > len(devices):
                print("❌ Invalid device selection!")
                return None
            
            selected_device = devices[device_id - 1]
            
            # Set phone info
            self.phone_ip = selected_device['ip']
            self.phone_mac = selected_device['mac']
            
            # Save phone info to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT OR REPLACE INTO phone (id, mac_address, ip_address, last_seen)
            VALUES (1, ?, ?, ?)
            ''', (self.phone_mac, self.phone_ip, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            print(f"✅ Device selected: {selected_device['ip']} ({selected_device['type']})")
            print(f"📱 Phone IP: {self.phone_ip}")
            print(f"📱 Phone MAC: {self.phone_mac}")
            
            return selected_device
            
        except ValueError:
            print("❌ Invalid device selection!")
            return None
    
    def scan_iot_devices(self):
        """Scan for IoT devices on the network."""
        print("\n🤖 === Scanning for IoT Devices ===")
        
        iot_devices = []
        
        try:
            # Scan for common IoT device ports and services
            iot_devices = self._scan_iot_services()
            
            if iot_devices:
                self._save_iot_devices(iot_devices)
                self._display_iot_devices(iot_devices)
            else:
                print("❌ No IoT devices found")
                
        except Exception as e:
            print(f"❌ Error scanning IoT devices: {e}")
            # Use simulated IoT devices for testing
            iot_devices = self._get_simulated_iot_devices()
            self._save_iot_devices(iot_devices)
            self._display_iot_devices(iot_devices)
        
        return iot_devices
    
    def _scan_iot_services(self):
        """Scan for IoT device services."""
        iot_devices = []
        
        # Common IoT device ports and services
        iot_services = {
            1883: "MQTT Broker",
            8883: "MQTT SSL",
            5683: "CoAP",
            5684: "CoAP DTLS",
            8080: "HTTP API",
            4840: "OPC UA",
            502: "Modbus TCP",
            102: "S7 Protocol",
            161: "SNMP",
            162: "SNMP Trap",
            5353: "mDNS",
            1900: "UPnP",
            9123: "Home Assistant",
            3000: "Node.js App",
            5000: "Flask App"
        }
        
        # Get local network
        local_ip = self._get_local_ip()
        network_prefix = '.'.join(local_ip.split('.')[:-1]) + '.'
        
        print(f"🔍 Scanning network {network_prefix}0/24 for IoT services...")
        
        # Scan first 100 IP addresses
        for i in range(1, 101):
            ip = network_prefix + str(i)
            
            if self._ping_host(ip):
                open_ports = self._check_ports(ip, list(iot_services.keys()))
                
                if open_ports:
                    for port in open_ports:
                        device_info = {
                            'device_id': f"IoT_{ip}_{port}",
                            'ip_address': ip,
                            'port': port,
                            'service': iot_services.get(port, "Unknown"),
                            'device_type': self._classify_iot_device(port),
                            'rssi_values': {},
                            'coordinates': None
                        }
                        iot_devices.append(device_info)
        
        return iot_devices
    
    def _classify_iot_device(self, port):
        """Classify IoT device based on port."""
        if port in [1883, 8883]:
            return "MQTT Device"
        elif port in [5683, 5684]:
            return "CoAP Device"
        elif port in [502, 102]:
            return "Industrial Device"
        elif port in [161, 162]:
            return "Network Device"
        elif port in [8080, 3000, 5000]:
            return "Web API Device"
        elif port in [5353, 1900]:
            return "Discovery Device"
        else:
            return "IoT Device"
    
    def _get_simulated_iot_devices(self):
        """Get simulated IoT devices for testing."""
        devices = [
            {
                'device_id': 'IoT_SmartLight_001',
                'ip_address': '192.168.1.101',
                'port': 8080,
                'service': 'HTTP API',
                'device_type': 'Smart Light',
                'rssi_values': {'Anchor_1': -45, 'Anchor_2': -52, 'Anchor_3': -67},
                'coordinates': {'x': 2.5, 'y': 1.8, 'z': 0.0}
            },
            {
                'device_id': 'IoT_Thermostat_001',
                'ip_address': '192.168.1.102',
                'port': 1883,
                'service': 'MQTT Broker',
                'device_type': 'Smart Thermostat',
                'rssi_values': {'Anchor_1': -58, 'Anchor_2': -45, 'Anchor_3': -72},
                'coordinates': {'x': 4.2, 'y': 0.5, 'z': 0.0}
            },
            {
                'device_id': 'IoT_SecurityCam_001',
                'ip_address': '192.168.1.103',
                'port': 5000,
                'service': 'Flask App',
                'device_type': 'Security Camera',
                'rssi_values': {'Anchor_1': -72, 'Anchor_2': -58, 'Anchor_3': -45},
                'coordinates': {'x': 0.8, 'y': 3.2, 'z': 0.0}
            }
        ]
        return devices
    
    def _save_iot_devices(self, devices):
        """Save IoT devices to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            rssi_json = json.dumps(device.get('rssi_values', {}))
            coords = device.get('coordinates', {})
            
            cursor.execute('''
            INSERT OR REPLACE INTO iot_devices (device_id, device_type, x_coord, y_coord, z_coord, rssi_values, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                device['device_id'],
                device['device_type'],
                coords.get('x'),
                coords.get('y'),
                coords.get('z'),
                rssi_json,
                datetime.now()
            ))
        
        conn.commit()
        conn.close()
    
    def _display_iot_devices(self, devices):
        """Display found IoT devices."""
        print(f"\n🤖 Found {len(devices)} IoT devices:")
        print("=" * 100)
        print(f"{'#':<3} {'Device ID':<25} {'Type':<20} {'IP':<15} {'Service':<15} {'Coordinates':<20}")
        print("-" * 100)
        
        for i, device in enumerate(devices, 1):
            coords = device.get('coordinates', {})
            coord_str = f"({coords.get('x', 'N/A')}, {coords.get('y', 'N/A')})" if coords else "Unknown"
            
            print(f"{i:<3} {device['device_id']:<25} {device['device_type']:<20} {device['ip_address']:<15} {device['service']:<15} {coord_str:<20}")
        
        print("=" * 100)
    
    def create_rssi_mapping(self):
        """Create RSSI mapping between anchors and WiFi networks."""
        print("\n📊 === Creating RSSI Mapping ===")
        
        if not self.anchors:
            print("❌ No anchors available! Create anchors first.")
            return False
        
        # Get all WiFi networks from our scan
        print("🔍 Scanning for WiFi networks...")
        wifi_networks = self.scan_wifi_networks()
        
        if not wifi_networks:
            print("❌ No WiFi networks found! Scan for WiFi networks first.")
            return False
        
        print(f"📍 Found {len(self.anchors)} anchors and {len(wifi_networks)} WiFi networks")
        print("🔍 Creating RSSI mapping...")
        
        # Generate RSSI values based on distance and signal propagation
        for anchor in self.anchors:
            for network in wifi_networks:
                # Skip if this is the same network as the anchor
                if network['bssid'] == anchor.get('bssid'):
                    continue
                
                # Generate coordinates for networks that don't have anchors
                network_x = random.uniform(0, 30)  # Random position
                network_y = random.uniform(0, 30)
                network_z = 0
                
                # Calculate distance between anchor and WiFi network
                distance = self._calculate_distance(
                    anchor['x_coord'], anchor['y_coord'], anchor['z_coord'],
                    network_x, network_y, network_z
                )
                
                # Calculate RSSI based on distance (free space path loss model)
                rssi = self._calculate_rssi_from_distance(distance, anchor.get('signal_strength', -50))
                
                # Save RSSI mapping
                self._save_rssi_mapping(anchor['id'], network['ssid'], rssi, distance)
                
                print(f"   📡 {anchor['name']} → {network['ssid']}: {rssi:.1f} dBm ({distance:.1f}m)")
        
        print("✅ RSSI mapping created successfully!")
        return True
    
    def _calculate_distance(self, x1, y1, z1, x2, y2, z2):
        """Calculate Euclidean distance between two points."""
        return math.sqrt((x2 - x1)**2 + (y2 - y1)**2 + (z2 - z1)**2)
    
    def _calculate_rssi_from_distance(self, distance, base_signal):
        """Calculate RSSI based on distance using path loss model."""
        # Free space path loss model
        # RSSI = BaseSignal - 20*log10(distance) - 20*log10(frequency) + 147.55
        # For 2.4GHz WiFi, frequency = 2.4e9 Hz
        
        if distance <= 0:
            return base_signal
        
        # Simplified path loss model
        path_loss = 20 * math.log10(distance) + 20 * math.log10(2.4e9) - 147.55
        rssi = base_signal - path_loss
        
        # Add some realistic noise
        noise = random.uniform(-5, 5)
        rssi += noise
        
        return max(-100, min(-30, rssi))  # Clamp between -100 and -30 dBm
    
    def _save_rssi_mapping(self, anchor_id, device_id, rssi, distance):
        """Save RSSI mapping to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT OR REPLACE INTO rssi_mapping (anchor_id, device_id, rssi_value, distance, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ''', (anchor_id, device_id, rssi, distance, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def generate_digital_map(self):
        """Generate a digital map visualization."""
        print("\n🗺️  === Generating Digital Map ===")
        
        if not self.anchors:
            print("❌ No anchors available! Create anchors first.")
            return False
        
        try:
            # Get all anchors
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM anchors ORDER BY anchor_number')
            anchors = cursor.fetchall()
            conn.close()
            
            # Get all WiFi networks from our scan
            print("🔍 Scanning for WiFi networks...")
            wifi_networks = self.scan_wifi_networks()
            
            if not wifi_networks:
                print("⚠️  No WiFi networks found, showing only anchors")
                wifi_networks = []
            
            # Create the map
            self._create_map_visualization(anchors, wifi_networks)
            
            print("✅ Digital map generated successfully!")
            print("📁 Map saved as 'digital_map.png'")
            return True
            
        except Exception as e:
            print(f"❌ Error generating digital map: {e}")
            return False
    
    def _create_map_visualization(self, anchors, network_devices):
        """Create the actual map visualization."""
        plt.figure(figsize=(12, 10))
        
        # Plot anchors
        anchor_x = [anchor[2] for anchor in anchors]
        anchor_y = [anchor[3] for anchor in anchors]
        anchor_names = [anchor[1] for anchor in anchors]
        
        plt.scatter(anchor_x, anchor_y, c='red', s=200, marker='^', label='Anchors', zorder=5)
        
        # Label anchors
        for i, name in enumerate(anchor_names):
            plt.annotate(name, (anchor_x[i], anchor_y[i]), 
                        xytext=(5, 5), textcoords='offset points',
                        fontsize=10, fontweight='bold')
        
        # Plot network devices
        if network_devices:
            device_x = [device.get('x_coord', 0) for device in network_devices]
            device_y = [device.get('y_coord', 0) for device in network_devices]
            device_ips = [device['ip'] for device in network_devices]
            
            if device_x and device_y:
                plt.scatter(device_x, device_y, c='blue', s=150, marker='o', label='Network Devices', zorder=4)
                
                # Label network devices
                for i, ip in enumerate(device_ips):
                    plt.annotate(ip, (device_x[i], device_y[i]), 
                                xytext=(5, 5), textcoords='offset points',
                                fontsize=8, alpha=0.8)
        
        # Create RSSI heatmap if we have RSSI data
        if anchors and network_devices:
            self._add_rssi_heatmap(anchors, network_devices)
        
        # Add anchor connection lines
        if len(anchors) > 1:
            self._add_anchor_connections(anchors)
        
        # Setup the map
        plt.xlabel('X Coordinate (meters)', fontsize=12)
        plt.ylabel('Y Coordinate (meters)', fontsize=12)
        plt.title('WiFi-Based Location System - Digital Map', fontsize=16, fontweight='bold')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.axis('equal')
        
        # Add scale and grid
        max_x = max(anchor_x) if anchor_x else 10
        max_y = max(anchor_y) if anchor_y else 10
        plt.xlim(-2, max_x + 2)
        plt.ylim(-2, max_y + 2)
        
        # Save the map
        plt.tight_layout()
        plt.savefig('digital_map.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def _add_rssi_heatmap(self, anchors, network_devices):
        """Add RSSI heatmap to the digital map."""
        try:
            # Create a grid for RSSI values
            x_min, x_max = -2, max([a[2] for a in anchors]) + 2
            y_min, y_max = -2, max([a[3] for a in anchors]) + 2
            
            grid_size = 50
            x_grid = np.linspace(x_min, x_max, grid_size)
            y_grid = np.linspace(y_min, y_max, grid_size)
            X, Y = np.meshgrid(x_grid, y_grid)
            
            # Calculate RSSI values for each grid point
            Z = np.zeros_like(X)
            
            for i in range(grid_size):
                for j in range(grid_size):
                    x, y = X[i, j], Y[i, j]
                    
                    # Calculate RSSI from all anchors
                    total_rssi = 0
                    anchor_count = 0
                    
                    for anchor in anchors:
                        distance = self._calculate_distance(x, y, 0, anchor[2], anchor[3], anchor[4])
                        rssi = self._calculate_rssi_from_distance(distance, anchor[11] or -50)
                        total_rssi += rssi
                        anchor_count += 1
                    
                    if anchor_count > 0:
                        Z[i, j] = total_rssi / anchor_count
            
            # Plot heatmap
            heatmap = plt.contourf(X, Y, Z, levels=20, alpha=0.3, cmap='viridis')
            plt.colorbar(heatmap, label='Average RSSI (dBm)', shrink=0.8)
            
        except Exception as e:
            print(f"⚠️  Could not create RSSI heatmap: {e}")
    
    def scan_wifi_devices(self):
        """This method is deprecated - use scan_for_devices instead."""
        print("⚠️  This method is deprecated. Use 'scan_for_devices' instead.")
        return self.scan_for_devices()
    
    def scan_wifi_networks(self):
        """Scan for real WiFi networks in the area (like phone WiFi settings)."""
        print("\n📶 === Scanning WiFi Networks ===")
        
        try:
            if platform.system() == "Windows":
                networks = self._scan_windows_wifi()
            elif platform.system() == "Linux":
                networks = self._scan_linux_wifi()
            elif platform.system() == "Darwin":  # macOS
                networks = self._scan_macos_wifi()
            else:
                print("❌ Unsupported operating system for WiFi scanning")
                return []
            
            if networks:
                print(f"\n📶 Found {len(networks)} WiFi networks:")
                print("=" * 80)
                print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<8} {'Channel':<8} {'Security':<12}")
                print("-" * 80)
                
                for i, network in enumerate(networks, 1):
                    ssid = network.get('ssid', 'Hidden')[:24]
                    bssid = network.get('bssid', 'Unknown')[:17]
                    signal = network.get('signal', 'N/A')
                    channel = network.get('channel', 'N/A')
                    security = network.get('security', 'Unknown')[:11]
                    
                    print(f"{i:<3} {ssid:<25} {bssid:<18} {signal:<8} {channel:<8} {security:<12}")
                
                print("=" * 80)
                return networks
            else:
                print("❌ No WiFi networks found")
                return []
                
        except Exception as e:
            print(f"❌ Error scanning WiFi networks: {e}")
            return []
    
    def _scan_windows_wifi(self):
        """Scan WiFi networks on Windows using netsh."""
        try:
            print("   🔍 Scanning with Windows netsh...")
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode != 0:
                raise Exception("netsh command failed")
            
            networks = []
            lines = result.stdout.split('\n')
            current_network = {}
            
            for line in lines:
                line = line.strip()
                
                if 'SSID' in line and 'BSSID' not in line and 'Number' not in line:
                    # New network found
                    if current_network and 'ssid' in current_network:
                        networks.append(current_network)
                    
                    current_network = {}
                    ssid_part = line.split(':')
                    if len(ssid_part) > 1:
                        current_network['ssid'] = ssid_part[1].strip()
                
                elif 'BSSID' in line:
                    bssid_part = line.split(':')
                    if len(bssid_part) > 1:
                        current_network['bssid'] = bssid_part[1].strip()
                
                elif 'Signal' in line:
                    signal_part = line.split(':')
                    if len(signal_part) > 1:
                        signal_str = signal_part[1].strip().replace('%', '')
                        try:
                            signal_percent = int(signal_str)
                            # More accurate conversion from percentage to dBm
                            if signal_percent >= 90:
                                signal_dbm = -30 + (signal_percent - 90) * 0.5
                            elif signal_percent >= 70:
                                signal_dbm = -50 + (signal_percent - 70) * 1.0
                            elif signal_percent >= 50:
                                signal_dbm = -70 + (signal_percent - 50) * 1.5
                            else:
                                signal_dbm = -90 + signal_percent * 1.0
                            
                            current_network['signal'] = f"{int(signal_dbm)} dBm"
                        except:
                            current_network['signal'] = signal_str + '%'
                
                elif 'Channel' in line:
                    channel_part = line.split(':')
                    if len(channel_part) > 1:
                        try:
                            current_network['channel'] = int(channel_part[1].strip())
                        except:
                            current_network['channel'] = 'N/A'
                
                elif 'Authentication' in line:
                    auth_part = line.split(':')
                    if len(auth_part) > 1:
                        current_network['security'] = auth_part[1].strip()
            
            # Add the last network
            if current_network and 'ssid' in current_network:
                networks.append(current_network)
            
            return networks[:20]  # Limit to 20 networks
            
        except Exception as e:
            print(f"   ❌ Windows WiFi scan error: {e}")
            return []
    
    def _scan_linux_wifi(self):
        """Scan WiFi networks on Linux using iwlist or nmcli."""
        try:
            print("   🔍 Scanning with Linux WiFi tools...")
            
            # Try iwlist first
            try:
                result = subprocess.run(
                    ['iwlist', 'wlan0', 'scan'],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                
                if result.returncode == 0:
                    return self._parse_iwlist_output(result.stdout)
            except:
                pass
            
            # Try nmcli as fallback
            try:
                result = subprocess.run(
                    ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'device', 'wifi', 'list'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if result.returncode == 0:
                    return self._parse_nmcli_output(result.stdout)
            except:
                pass
            
            print("   ❌ No Linux WiFi scanning tools available")
            return []
            
        except Exception as e:
            print(f"   ❌ Linux WiFi scan error: {e}")
            return []
    
    def _scan_macos_wifi(self):
        """Scan WiFi networks on macOS using airport command."""
        try:
            print("   🔍 Scanning with macOS airport...")
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                return self._parse_airport_output(result.stdout)
            else:
                print("   ❌ macOS airport command failed")
                return []
                
        except Exception as e:
            print(f"   ❌ macOS WiFi scan error: {e}")
            return []
    
    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output."""
        networks = []
        lines = output.split('\n')
        current_network = {}
        
        for line in lines:
            line = line.strip()
            
            if 'ESSID:' in line:
                if current_network and 'ssid' in current_network:
                    networks.append(current_network)
                current_network = {}
                ssid = line.split('"')[1] if '"' in line else 'Hidden'
                current_network['ssid'] = ssid
            
            elif 'Address:' in line:
                bssid = line.split(':')[1].strip()
                current_network['bssid'] = bssid
            
            elif 'Channel:' in line:
                try:
                    channel = int(line.split(':')[1].strip())
                    current_network['channel'] = channel
                except:
                    current_network['channel'] = 'N/A'
            
            elif 'Quality=' in line:
                try:
                    quality = line.split('=')[1].split()[0]
                    quality_percent = int(quality.split('/')[0]) * 100 // int(quality.split('/')[1])
                    signal_dbm = -100 + (quality_percent * 0.5)
                    current_network['signal'] = f"{int(signal_dbm)} dBm"
                except:
                    current_network['signal'] = 'N/A'
            
            elif 'Encryption key:' in line:
                security = 'WPA/WPA2' if 'on' in line else 'Open'
                current_network['security'] = security
        
        if current_network and 'ssid' in current_network:
            networks.append(current_network)
        
        return networks[:20]
    
    def _parse_nmcli_output(self, output):
        """Parse nmcli wifi list output."""
        networks = []
        lines = output.split('\n')
        
        for line in lines:
            if line.strip():
                parts = line.split(':')
                if len(parts) >= 5:
                    network = {
                        'ssid': parts[0] or 'Hidden',
                        'bssid': parts[1] or 'Unknown',
                        'channel': parts[2] or 'N/A',
                        'signal': parts[3] or 'N/A',
                        'security': parts[4] or 'Unknown'
                    }
                    networks.append(network)
        
        return networks[:20]
    
    def _parse_airport_output(self, output):
        """Parse macOS airport scan output."""
        networks = []
        lines = output.split('\n')
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 6:
                    network = {
                        'ssid': parts[0] or 'Hidden',
                        'bssid': parts[1] or 'Unknown',
                        'signal': parts[2] or 'N/A',
                        'channel': parts[3] or 'N/A',
                        'security': parts[6] if len(parts) > 6 else 'Unknown'
                    }
                    networks.append(network)
        
        return networks[:20]
    
    def _add_anchor_connections(self, anchors):
        """Add connection lines between anchors to show network topology."""
        try:
            # Get anchor coordinates
            anchor_x = [anchor[2] for anchor in anchors]
            anchor_y = [anchor[3] for anchor in anchors]
            
            # Connect all anchors with lines
            for i in range(len(anchors)):
                for j in range(i + 1, len(anchors)):
                    # Draw line between anchors
                    plt.plot([anchor_x[i], anchor_x[j]], [anchor_y[i], anchor_y[j]], 
                            'g--', alpha=0.4, linewidth=1)
                    
                    # Calculate distance
                    distance = math.sqrt((anchor_x[i] - anchor_x[j])**2 + (anchor_y[i] - anchor_y[j])**2)
                    
                    # Add distance label at midpoint
                    mid_x = (anchor_x[i] + anchor_x[j]) / 2
                    mid_y = (anchor_y[i] + anchor_y[j]) / 2
                    plt.annotate(f'{distance:.1f}m', (mid_x, mid_y), 
                                xytext=(2, 2), textcoords='offset points',
                                fontsize=8, alpha=0.7, color='green')
            
            # Add legend entry for connections
            plt.plot([], [], 'g--', alpha=0.4, linewidth=1, label='Anchor Connections')
            
        except Exception as e:
            print(f"⚠️  Could not create anchor connections: {e}")
    
    def _get_simulated_devices(self):
        """Get simulated WiFi devices for testing."""
        devices = [
            {'ssid': 'Home_WiFi_5G', 'bssid': 'AA:BB:CC:DD:EE:01', 'signal': -45, 'channel': 36},
            {'ssid': 'Office_Network', 'bssid': 'AA:BB:CC:DD:EE:02', 'signal': -52, 'channel': 1},
            {'ssid': 'Guest_WiFi', 'bssid': 'AA:BB:CC:DD:EE:03', 'signal': -67, 'channel': 6},
            {'ssid': 'IoT_Network', 'bssid': 'AA:BB:CC:DD:EE:04', 'signal': -58, 'channel': 11},
            {'ssid': 'Mobile_Hotspot', 'bssid': 'AA:BB:CC:DD:EE:05', 'signal': -72, 'channel': 40},
            {'ssid': 'Security_Camera', 'bssid': 'AA:BB:CC:DD:EE:06', 'signal': -63, 'channel': 9},
            {'ssid': 'Neighbor_WiFi', 'bssid': 'AA:BB:CC:DD:EE:07', 'signal': -78, 'channel': 3},
            {'ssid': 'Public_Hotspot', 'bssid': 'AA:BB:CC:DD:EE:08', 'signal': -81, 'channel': 7}
        ]
        return devices
    
    def _save_scanned_devices(self, devices):
        """Save scanned devices to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            cursor.execute('''
            INSERT OR REPLACE INTO scanned_devices (ssid, bssid, signal_strength, channel, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ''', (device['ssid'], device['bssid'], device['signal'], device['channel'], datetime.now()))
        
        conn.commit()
        conn.close()
    
    def _display_devices(self, devices):
        """Display scanned devices in a formatted table."""
        print(f"\n📱 Found {len(devices)} WiFi devices:")
        print("=" * 80)
        print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<8} {'Channel':<8} {'Quality':<10}")
        print("-" * 80)
        
        for i, device in enumerate(devices, 1):
            signal = device['signal']
            quality = self._get_signal_quality(signal)
            print(f"{i:<3} {device['ssid']:<25} {device['bssid']:<18} {signal:<8} {device['channel']:<8} {quality:<10}")
        
        print("=" * 80)
    
    def _get_signal_quality(self, signal):
        """Get signal quality description."""
        if signal >= -50:
            return "Excellent"
        elif signal >= -60:
            return "Good"
        elif signal >= -70:
            return "Fair"
        elif signal >= -80:
            return "Poor"
        else:
            return "Very Poor"
    
    def create_anchor_from_device(self):
        """Create an anchor from the currently selected device."""
        print("\n📍 === Create Anchor from Device ===")
        
        if not self.phone_ip:
            print("❌ Please scan and select a network device first (option 1)")
            return False
        
        try:
            # Use the currently selected device info
            selected_device = {
                'ip': self.phone_ip,
                'mac': self.phone_mac or 'Unknown',
                'type': 'Network Device',
                'ssid': 'Local Network'
            }
            
            # Check if device already exists as anchor
            existing = [a for a in self.anchors if a['phone_ip'] == selected_device['ip']]
            if existing:
                print(f"⚠️  Device {selected_device['ip']} already exists as an anchor!")
                return False
            
            print(f"\n✅ Selected: {selected_device['ip']} ({selected_device['mac']})")
            print(f"📱 Device Type: {selected_device['type']}")
            print(f"🌐 Network: {selected_device['ssid']}")
            
            # Generate automatic coordinates based on device position
            coordinates = self._generate_simple_coordinates(selected_device)
            
            # Create anchor name
            anchor_name = f"Anchor_{selected_device['ip'].replace('.', '_')}"
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO anchors (name, x_coord, y_coord, z_coord, anchor_number, phone_mac, phone_ip, bssid, ssid, signal_strength, channel)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (anchor_name, coordinates['x'], coordinates['y'], coordinates['z'], 
                  len(self.anchors) + 1, self.phone_mac, self.phone_ip, 
                  selected_device['mac'], selected_device['ssid'], 
                  -50, 1))  # Default signal strength and channel
            
            anchor_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Add to local list
            self.anchors.append({
                'id': anchor_id,
                'name': anchor_name,
                'x_coord': coordinates['x'],
                'y_coord': coordinates['y'],
                'z_coord': coordinates['z'],
                'anchor_number': len(self.anchors),
                'created_at': datetime.now().isoformat(),
                'phone_mac': self.phone_mac,
                'phone_ip': self.phone_ip,
                'bssid': selected_device['mac'],
                'ssid': selected_device['ssid'],
                'signal_strength': -50,
                'channel': 1
            })
            
            print(f"✅ Anchor created: {anchor_name}")
            print(f"📍 Position: ({coordinates['x']:.2f}, {coordinates['y']:.2f}, {coordinates['z']:.2f})")
            print(f"📱 IP: {selected_device['ip']}")
            print(f"🔗 MAC: {selected_device['mac']}")
            print(f"🌐 Network: {selected_device['ssid']}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error creating anchor: {e}")
            return False
    
    def _generate_coordinates(self, device):
        """Generate automatic coordinates based on device properties."""
        # Use signal strength to determine distance from center
        signal_strength = abs(device['signal'])
        
        # Stronger signal = closer to center
        if signal_strength < 50:  # Very strong signal
            base_distance = 2.0
        elif signal_strength < 60:  # Strong signal
            base_distance = 5.0
        elif signal_strength < 70:  # Medium signal
            base_distance = 8.0
        else:  # Weak signal
            base_distance = 12.0
        
        # Generate coordinates in a grid pattern
        anchor_count = len(self.anchors)
        
        if anchor_count == 0:
            # First anchor at origin
            x, y = 0.0, 0.0
        elif anchor_count == 1:
            # Second anchor at distance
            x, y = base_distance, 0.0
        elif anchor_count == 2:
            # Third anchor
            x, y = 0.0, base_distance
        elif anchor_count == 3:
            # Fourth anchor
            x, y = base_distance, base_distance
        else:
            # Additional anchors in expanding pattern
            row = anchor_count // 4
            col = anchor_count % 4
            x = col * base_distance
            y = row * base_distance
        
        # Add some randomness based on signal strength
        noise = random.uniform(-1.0, 1.0) * (signal_strength / 100.0)
        x += noise
        y += noise
        
        # Z coordinate based on device type (usually 0 for ground level)
        z = 0.0
        
        return {'x': x, 'y': y, 'z': z}
    
    def _generate_simple_coordinates(self, device):
        """Generate simple coordinates for network devices."""
        # Simple coordinate generation based on anchor count
        anchor_count = len(self.anchors)
        
        if anchor_count == 0:
            # First anchor at origin
            x_coord = 0.0
            y_coord = 0.0
        elif anchor_count == 1:
            # Second anchor at a distance
            x_coord = 10.0
            y_coord = 0.0
        elif anchor_count == 2:
            # Third anchor forming a triangle
            x_coord = 5.0
            y_coord = 8.66  # sqrt(3) * 5 for equilateral triangle
        else:
            # Additional anchors in a grid pattern
            row = anchor_count // 3
            col = anchor_count % 3
            x_coord = col * 10.0
            y_coord = row * 10.0
        
        z_coord = 0.0  # Ground level
        
        return {
            'x': x_coord,
            'y': y_coord,
            'z': z_coord
        }
    
    def send_location_to_phone(self, anchor_number):
        """Send location coordinates to the phone."""
        anchor = None
        for a in self.anchors:
            if a['anchor_number'] == anchor_number:
                anchor = a
                break
        
        if not anchor:
            print(f"❌ Anchor {anchor_number} not found!")
            return False
        
        print(f"\n📡 === Sending Location to Phone ===")
        print(f"📍 Anchor: {anchor['name']}")
        print(f"📶 SSID: {anchor.get('ssid', 'N/A')}")
        print(f"🔗 BSSID: {anchor.get('bssid', 'N/A')}")
        print(f"📍 Coordinates: ({anchor['x_coord']:.2f}, {anchor['y_coord']:.2f}, {anchor['z_coord']:.2f})")
        print(f"📱 Phone IP: {anchor['phone_ip']}")
        
        # Send coordinates via WiFi to the phone
        try:
            # Create socket connection to phone
            phone_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            phone_socket.settimeout(5)  # 5 second timeout
            
            # Prepare coordinate data
            coordinate_data = {
                'anchor_name': anchor['name'],
                'anchor_number': anchor['anchor_number'],
                'x': anchor['x_coord'],
                'y': anchor['y_coord'],
                'z': anchor['z_coord'],
                'ssid': anchor.get('ssid', ''),
                'bssid': anchor.get('bssid', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            print("📡 Sending coordinates via WiFi...")
            print(f"📱 Attempting to connect to {anchor['phone_ip']}:8080...")
            
            # Connect to phone simulator
            phone_socket.connect((anchor['phone_ip'], 8080))
            
            # Send coordinates
            phone_socket.send(json.dumps(coordinate_data).encode('utf-8'))
            
            # Wait for acknowledgment
            response = phone_socket.recv(1024).decode('utf-8')
            response_data = json.loads(response)
            
            if response_data.get('status') == 'received':
                print("✅ Coordinates sent successfully!")
                print("📱 The phone should now display the location coordinates")
            else:
                print("⚠️  Phone received coordinates but status unclear")
            
            phone_socket.close()
            return True
            
        except socket.timeout:
            print("❌ Timeout: Phone not responding")
            return False
        except ConnectionRefusedError:
            print("❌ Connection refused: Make sure phone simulator is running")
            return False
        except Exception as e:
            print(f"❌ Error sending coordinates: {e}")
            print("Make sure the phone simulator is running on the correct IP and port")
            return False
    
    def list_anchors(self):
        """List all created anchors."""
        print("\n📋 === Current Anchors ===")
        if not self.anchors:
            print("No anchors created yet.")
            return
        
        print(f"{'#':<3} {'Name':<20} {'Position':<15} {'SSID':<15} {'Signal':<8} {'Channel':<8}")
        print("-" * 80)
        
        for anchor in self.anchors:
            position = f"({anchor['x_coord']:.1f}, {anchor['y_coord']:.1f})"
            signal = anchor.get('signal_strength', 'N/A')
            ssid = anchor.get('ssid', 'Unknown')[:14]
            channel = anchor.get('channel', 'N/A')
            print(f"{anchor['anchor_number']:<3} {anchor['name']:<20} {position:<15} {ssid:<15} {signal:<8} {channel:<8}")
        
        print("-" * 80)
        print(f"Total anchors: {len(self.anchors)}")
    
    def remove_anchor(self, anchor_number):
        """Remove an anchor (but keep the position)."""
        anchor = None
        for a in self.anchors:
            if a['anchor_number'] == anchor_number:
                anchor = a
                break
        
        if not anchor:
            print(f"❌ Anchor {anchor_number} not found!")
            return False
        
        print(f"\n🗑️  === Removing Anchor ===")
        print(f"📍 Anchor {anchor_number} ({anchor['name']}) will be removed but position will be preserved.")
        print(f"📶 SSID: {anchor.get('ssid', 'N/A')}")
        confirm = input("Are you sure? (y/N): ").lower()
        
        if confirm != 'y':
            print("❌ Cancelled.")
            return False
        
        # Remove from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM anchors WHERE anchor_number = ?', (anchor_number,))
        conn.commit()
        conn.close()
        
        # Remove from local list
        self.anchors = [a for a in self.anchors if a['anchor_number'] != anchor_number]
        
        print(f"✅ Anchor {anchor_number} removed (position preserved)")
        return True
    
    def export_anchors(self):
        """Export anchors to JSON file."""
        if not self.anchors:
            print("❌ No anchors to export!")
            return False
        
        export_file = f"data/anchors_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs(os.path.dirname(export_file), exist_ok=True)
        
        with open(export_file, 'w') as f:
            json.dump(self.anchors, f, indent=2, default=str)
        
        print(f"✅ Anchors exported to: {export_file}")
        return True
    
    def show_menu(self):
        """Show the main menu."""
        print("============================================================")
        print("           🌐 WiFi-Based Location System")
        print("============================================================")
        print("1. 📶 Scan WiFi networks")
        print("2. 📍 Create anchor from WiFi network")
        print("3. 📊 Create RSSI mapping")
        print("4. 🗺️  Generate digital map")
        print("5. 📤 Send location to phone")
        print("6. 📋 List all anchors")
        print("7. 🗑️  Remove anchor")
        print("8. 💾 Export anchors")
        print("9. 📊 System status")
        print("10. 🏠 Create room from anchors")
        print("11. 🔎 Find networks in room")
        print("12. ❌ Exit")
        print("------------------------------------------------------------")
    
    def show_status(self):
        """Show system status summary."""
        print("\n📊 === System Status ===")
        print(f"📍 Total anchors: {len(self.anchors)}")
        print(f"📱 Phone IP: {self.phone_ip or 'Not set'}")
        print(f"📱 Phone MAC: {self.phone_mac or 'Not set'}")
        print(f"💾 Database: {self.db_path}")
        
        if self.anchors:
            print("\n📍 Recent anchors:")
            for anchor in self.anchors[-3:]:  # Show last 3 anchors
                print(f"  • {anchor['name']} at ({anchor['x_coord']:.1f}, {anchor['y_coord']:.1f}) - {anchor.get('bssid', 'Unknown')}")
    
    def run(self):
        """Run the main CLI loop."""
        print("🌐 Welcome to WiFi-Based Location System!")
        print("📍 This system helps you create location anchors using WiFi devices.")
        
        while self.running:
            self.show_menu()
            
            try:
                choice = input("Select option (1-12): ").strip()
                
                if choice == '1':
                    print("\n📶 === Scanning WiFi Networks ===")
                    wifi_networks = self.scan_wifi_networks()
                
                elif choice == '2':
                    self.create_anchor_from_wifi_network()
                
                elif choice == '3':
                    self.create_rssi_mapping()
                
                elif choice == '4':
                    self.generate_digital_map()
                
                elif choice == '5':
                    if not self.anchors:
                        print("❌ No anchors created yet!")
                        continue
                    
                    try:
                        anchor_num = int(input("Enter anchor number to send: "))
                        self.send_location_to_phone(anchor_num)
                    except ValueError:
                        print("❌ Invalid anchor number!")
                
                elif choice == '6':
                    self.list_anchors()
                
                elif choice == '7':
                    if not self.anchors:
                        print("❌ No anchors to remove!")
                        continue
                    
                    try:
                        anchor_num = int(input("Enter anchor number to remove: "))
                        self.remove_anchor(anchor_num)
                    except ValueError:
                        print("❌ Invalid anchor number!")
                
                elif choice == '8':
                    self.export_anchors()
                
                elif choice == '9':
                    self.show_status()
                
                elif choice == '10':
                    print("🏠 Creating room from anchors...")
                    self.create_room_from_anchors()
                
                elif choice == '11':
                    self.find_networks_in_room()
                
                elif choice == '12':
                    print("👋 Goodbye!")
                    self.running = False
                    break
                
                else:
                    print("❌ Invalid option! Please select 1-12.")
                
                if self.running:
                    input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                if self.running:
                    input("Press Enter to continue...")
    
    def create_room_from_anchors(self):
        """Create a room based on the area covered by selected anchors."""
        print("\n🏠 === Create Room from Anchors ===")
        
        if len(self.anchors) < 3:
            print("❌ Need at least 3 anchors to create a room!")
            print("   Create more anchors first (option 2)")
            return False
        
        print(f"📍 Available anchors: {len(self.anchors)}")
        self.list_anchors()
        
        try:
            # Let user select anchors to define room boundaries
            print("\n🏠 Select anchors to define room boundaries:")
            print("   (Select 3 or more anchors to create a room)")
            
            selected_anchor_numbers = []
            while True:
                try:
                    anchor_num = input("Enter anchor number (or 'done' to finish): ").strip()
                    if anchor_num.lower() == 'done':
                        break
                    
                    anchor_num = int(anchor_num)
                    # Find anchor by the displayed number (index + 1)
                    if anchor_num < 1 or anchor_num > len(self.anchors):
                        print("❌ Invalid anchor number!")
                        continue
                    
                    # Get anchor by index (anchor_num - 1)
                    anchor = self.anchors[anchor_num - 1]
                    actual_anchor_number = anchor['anchor_number']
                    
                    if actual_anchor_number in selected_anchor_numbers:
                        print("⚠️  Anchor already selected!")
                        continue
                    
                    selected_anchor_numbers.append(actual_anchor_number)
                    print(f"✅ Selected: {anchor['name']} at ({anchor['x_coord']:.1f}, {anchor['y_coord']:.1f})")
                    
                    if len(selected_anchor_numbers) >= 3:
                        print("   (Minimum anchors selected. You can add more or type 'done')")
                        
                except ValueError:
                    print("❌ Invalid input! Enter a number or 'done'")
            
            if len(selected_anchor_numbers) < 3:
                print("❌ Need at least 3 anchors to create a room!")
                return False
            
            # Get room details
            room_name = input("\n🏠 Enter room name: ").strip()
            if not room_name:
                room_name = f"Room_{len(selected_anchor_numbers)}_anchors"
            
            room_type = input("🏠 Enter room type (office, conference, lobby, etc.): ").strip()
            if not room_type:
                room_type = "General"
            
            # Calculate room properties
            room_info = self._calculate_room_properties(selected_anchor_numbers)
            
            # Save room to database
            room_id = self._save_room_to_database(room_name, room_type, room_info)
            
            # Associate anchors with room
            self._associate_anchors_with_room(selected_anchor_numbers, room_id)
            
            print(f"\n✅ Room '{room_name}' created successfully!")
            print(f"🏠 Room ID: {room_id}")
            print(f"📍 Area: {room_info['area']:.1f} m²")
            print(f"📏 Perimeter: {room_info['perimeter']:.1f} m")
            print(f"📍 Center: ({room_info['center_x']:.1f}, {room_info['center_y']:.1f})")
            print(f"🔗 Anchors: {len(selected_anchor_numbers)} anchors")
            
            return True
            
        except Exception as e:
            print(f"❌ Error creating room: {e}")
            return False
    
    def _calculate_room_properties(self, selected_anchor_numbers):
        """Calculate room properties from selected anchors."""
        selected_anchors = [a for a in self.anchors if a['anchor_number'] in selected_anchor_numbers]
        
        # Calculate bounding box
        x_coords = [anchor['x_coord'] for anchor in selected_anchors]
        y_coords = [anchor['y_coord'] for anchor in selected_anchors]
        
        min_x, max_x = min(x_coords), max(x_coords)
        min_y, max_y = min(y_coords), max(y_coords)
        
        # Calculate center
        center_x = (min_x + max_x) / 2
        center_y = (min_y + max_y) / 2
        
        # Calculate dimensions
        width = max_x - min_x
        height = max_y - min_y
        
        # Calculate area (approximate - using bounding box)
        area = width * height
        
        # Calculate perimeter
        perimeter = 2 * (width + height)
        
        # Calculate coverage radius (distance from center to farthest anchor)
        max_distance = 0
        for anchor in selected_anchors:
            distance = math.sqrt((anchor['x_coord'] - center_x)**2 + (anchor['y_coord'] - center_y)**2)
            max_distance = max(max_distance, distance)
        
        return {
            'min_x': min_x,
            'max_x': max_x,
            'min_y': min_y,
            'max_y': max_y,
            'center_x': center_x,
            'center_y': center_y,
            'width': width,
            'height': height,
            'area': area,
            'perimeter': perimeter,
            'coverage_radius': max_distance,
            'anchor_count': len(selected_anchors)
        }
    
    def _save_room_to_database(self, room_name, room_type, room_info):
        """Save room information to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create rooms table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            room_type TEXT,
            center_x REAL,
            center_y REAL,
            width REAL,
            height REAL,
            area REAL,
            perimeter REAL,
            coverage_radius REAL,
            anchor_count INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Insert room
        cursor.execute('''
        INSERT INTO rooms (name, room_type, center_x, center_y, width, height, area, perimeter, coverage_radius, anchor_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (room_name, room_type, room_info['center_x'], room_info['center_y'], 
              room_info['width'], room_info['height'], room_info['area'], 
              room_info['perimeter'], room_info['coverage_radius'], room_info['anchor_count']))
        
        room_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return room_id
    
    def _associate_anchors_with_room(self, selected_anchor_numbers, room_id):
        """Associate selected anchors with the created room."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create anchor_rooms table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS anchor_rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_id INTEGER,
            room_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (anchor_id) REFERENCES anchors (id),
            FOREIGN KEY (room_id) REFERENCES rooms (id)
        )
        ''')
        
        # Associate each anchor with the room
        for anchor_num in selected_anchor_numbers:
            anchor = next(a for a in self.anchors if a['anchor_number'] == anchor_num)
            cursor.execute('''
            INSERT INTO anchor_rooms (anchor_id, room_id)
            VALUES (?, ?)
            ''', (anchor['id'], room_id))
        
        conn.commit()
        conn.close()
    
    def create_anchor_from_wifi_network(self):
        """Create an anchor from a WiFi network."""
        print("\n📍 === Create Anchor from WiFi Network ===")
        
        # First scan for available WiFi networks
        print("🔍 Scanning for available WiFi networks...")
        wifi_networks = self.scan_wifi_networks()
        
        if not wifi_networks:
            print("❌ No WiFi networks found! Please scan for WiFi networks first (option 11)")
            return False
        
        try:
            # Let user select a WiFi network
            print(f"\n📍 Select a WiFi network to create an anchor:")
            network_id = int(input(f"Enter network number (1-{len(wifi_networks)}): "))
            
            if network_id < 1 or network_id > len(wifi_networks):
                print("❌ Invalid network selection!")
                return False
            
            selected_network = wifi_networks[network_id - 1]
            
            print(f"\n✅ Selected: {selected_network['ssid']} ({selected_network['bssid']})")
            print(f"📶 Signal: {selected_network['signal']}")
            print(f"📡 Channel: {selected_network['channel']}")
            print(f"🔒 Security: {selected_network['security']}")
            
            # Generate automatic coordinates based on WiFi network properties
            print(f"\n📍 Generating automatic coordinates based on WiFi properties...")
            coordinates = self._generate_wifi_coordinates(selected_network)
            x_coord = coordinates['x']
            y_coord = coordinates['y']
            z_coord = coordinates['z']
            
            print(f"📍 Auto-generated position: ({x_coord:.1f}, {y_coord:.1f}, {z_coord:.1f})")
            
            # Option to override with custom coordinates
            custom_coords = input("Use custom coordinates instead? (y/N): ").lower()
            if custom_coords == 'y':
                try:
                    x_coord = float(input("X coordinate (meters): "))
                    y_coord = float(input("Y coordinate (meters): "))
                    z_coord = float(input("Z coordinate (meters, default 0): ") or "0")
                except ValueError:
                    print("❌ Invalid coordinate format! Using auto-generated coordinates.")
            
            # Generate anchor name
            anchor_name = f"Anchor_{selected_network['ssid'].replace(' ', '_')}"
            
            # Check if this WiFi network already exists as an anchor
            existing_anchors = [a for a in self.anchors if a.get('bssid') == selected_network['bssid']]
            if existing_anchors:
                print(f"⚠️  This WiFi network already has {len(existing_anchors)} anchor(s):")
                for anchor in existing_anchors:
                    print(f"   • {anchor['name']} at ({anchor['x_coord']:.1f}, {anchor['y_coord']:.1f})")
                
                confirm = input("Create another anchor for this network? (y/N): ").lower()
                if confirm != 'y':
                    print("❌ Cancelled.")
                    return False
                
                # Add suffix to name for multiple anchors
                anchor_name = f"{anchor_name}_{len(existing_anchors) + 1}"
            
            # Extract signal strength as number
            signal_str = selected_network['signal']
            if 'dBm' in signal_str:
                signal_dbm = float(signal_str.replace(' dBm', ''))
            else:
                signal_dbm = -50  # Default if can't parse
            
            # Save to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Add security column if it doesn't exist
            try:
                cursor.execute('ALTER TABLE anchors ADD COLUMN security TEXT')
            except:
                pass  # Column already exists
            
            cursor.execute('''
            INSERT INTO anchors (name, x_coord, y_coord, z_coord, anchor_number, phone_mac, phone_ip, bssid, ssid, signal_strength, channel, security)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (anchor_name, x_coord, y_coord, z_coord, 
                  len(self.anchors) + 1, self.phone_mac, self.phone_ip, 
                  selected_network['bssid'], selected_network['ssid'], 
                  signal_dbm, selected_network['channel'], selected_network['security']))
            
            anchor_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Add to local list
            self.anchors.append({
                'id': anchor_id,
                'name': anchor_name,
                'x_coord': x_coord,
                'y_coord': y_coord,
                'z_coord': z_coord,
                'anchor_number': len(self.anchors),
                'created_at': datetime.now().isoformat(),
                'phone_mac': self.phone_mac,
                'phone_ip': self.phone_ip,
                'bssid': selected_network['bssid'],
                'ssid': selected_network['ssid'],
                'signal_strength': signal_dbm,
                'channel': selected_network['channel'],
                'security': selected_network['security']
            })
            
            print(f"\n✅ Anchor created successfully!")
            print(f"📍 Name: {anchor_name}")
            print(f"📍 Position: ({x_coord:.2f}, {y_coord:.2f}, {z_coord:.2f})")
            print(f"📶 SSID: {selected_network['ssid']}")
            print(f"🔗 BSSID: {selected_network['bssid']}")
            print(f"📡 Channel: {selected_network['channel']}")
            print(f"🔒 Security: {selected_network['security']}")
            
            return True
            
        except ValueError:
            print("❌ Invalid input! Please enter a valid number.")
            return False
        except Exception as e:
            print(f"❌ Error creating anchor: {e}")
            return False
    
    def _generate_wifi_coordinates(self, wifi_network):
        """Generate automatic coordinates based on WiFi network properties."""
        # Extract signal strength
        signal_str = wifi_network['signal']
        if 'dBm' in signal_str:
            signal_dbm = float(signal_str.replace(' dBm', ''))
        else:
            signal_dbm = -50  # Default
        
        # Get channel and other properties
        channel = wifi_network['channel']
        ssid = wifi_network['ssid']
        security = wifi_network['security']
        
        # Calculate coordinates based on multiple factors
        anchor_count = len(self.anchors)
        
        # More accurate positioning logic based on signal strength and channel
        if anchor_count == 0:
            # First anchor - place at origin
            x_coord = 0.0
            y_coord = 0.0
            z_coord = 0.0
        elif anchor_count == 1:
            # Second anchor - place based on signal strength and channel
            if signal_dbm > -50:  # Very strong signal
                x_coord = 3.0
                y_coord = 0.0
            elif signal_dbm > -60:  # Strong signal
                x_coord = 5.0
                y_coord = 2.0
            elif signal_dbm > -70:  # Medium signal
                x_coord = 8.0
                y_coord = 4.0
            else:  # Weak signal
                x_coord = 12.0
                y_coord = 6.0
            z_coord = 0.0
        elif anchor_count == 2:
            # Third anchor - form optimal triangle based on signal
            if signal_dbm > -50:
                x_coord = 1.5
                y_coord = 2.6  # sqrt(3) * 1.5
            elif signal_dbm > -60:
                x_coord = 2.5
                y_coord = 4.33  # sqrt(3) * 2.5
            elif signal_dbm > -70:
                x_coord = 4.0
                y_coord = 6.93  # sqrt(3) * 4
            else:
                x_coord = 6.0
                y_coord = 10.39  # sqrt(3) * 6
            z_coord = 0.0
        else:
            # Additional anchors - intelligent grid with signal-based positioning
            row = anchor_count // 3
            col = anchor_count % 3
            
            # Base grid position with better spacing
            base_x = col * 8.0
            base_y = row * 8.0
            
            # Intelligent adjustment based on signal strength
            if signal_dbm > -50:  # Very strong signal - close positioning
                x_coord = base_x + random.uniform(-1.5, 1.5)
                y_coord = base_y + random.uniform(-1.5, 1.5)
            elif signal_dbm > -60:  # Strong signal
                x_coord = base_x + random.uniform(-2.0, 2.0)
                y_coord = base_y + random.uniform(-2.0, 2.0)
            elif signal_dbm > -70:  # Medium signal
                x_coord = base_x + random.uniform(-2.5, 2.5)
                y_coord = base_y + random.uniform(-2.5, 2.5)
            else:  # Weak signal - more spread out
                x_coord = base_x + random.uniform(-3.0, 3.0)
                y_coord = base_y + random.uniform(-3.0, 3.0)
            
            z_coord = 0.0
        
        # Add some randomness based on channel and security
        channel_factor = (channel % 10) * 0.1  # Small variation based on channel
        security_factor = len(security) * 0.05  # Small variation based on security type
        
        x_coord += channel_factor
        y_coord += security_factor
        
        # Ensure coordinates are reasonable
        x_coord = max(0, min(50, x_coord))  # Clamp between 0 and 50
        y_coord = max(0, min(50, y_coord))  # Clamp between 0 and 50
        z_coord = max(0, min(10, z_coord))  # Clamp between 0 and 10
        
        return {
            'x': round(x_coord, 2),
            'y': round(y_coord, 2),
            'z': round(z_coord, 2)
        }
    
    def _get_last_room(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, center_x, center_y, width, height FROM rooms ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            return {
                'id': row[0],
                'name': row[1],
                'center_x': row[2],
                'center_y': row[3],
                'width': row[4],
                'height': row[5],
            }
        except Exception:
            return None
    
    def _get_room_bbox(self, room):
        half_w = max(0.0, float(room['width']) / 2.0)
        half_h = max(0.0, float(room['height']) / 2.0)
        min_x = float(room['center_x']) - half_w
        max_x = float(room['center_x']) + half_w
        min_y = float(room['center_y']) - half_h
        max_y = float(room['center_y']) + half_h
        return (min_x, min_y, max_x, max_y)
    
    def _estimate_network_xy(self, network_signal_dbm, anchors_center_x, anchors_center_y):
        # Convert RSSI to approximate distance using a simple model around 1m reference
        # Stronger (closer to -30) => shorter distance; weaker (closer to -90) => longer distance
        rssi = float(network_signal_dbm)
        rssi = max(-95.0, min(-30.0, rssi))
        # Map RSSI to distance in meters: -30dBm => ~1m, -90dBm => ~20m
        t = (rssi + 30.0) / 60.0  # -30 -> 0, -90 -> -1
        dist = 1.0 + (1.0 - abs(t)) * 19.0  # 1..20m roughly
        # Place on a circle around anchors center with deterministic angle by hashing
        seed = int(abs(rssi) * 1000) % 360
        angle_rad = (seed % 360) * math.pi / 180.0
        x = anchors_center_x + dist * math.cos(angle_rad)
        y = anchors_center_y + dist * math.sin(angle_rad)
        return (x, y)
    
    def find_networks_in_room(self):
        print("\n🔎 === Find Networks in Room ===")
        room = self._get_last_room()
        if not room:
            print("❌ No rooms found. Create a room first (option 10).")
            return False
        
        print(f"🏠 Using room: {room['name']} (center=({room['center_x']:.1f},{room['center_y']:.1f}), w={room['width']:.1f}, h={room['height']:.1f})")
        min_x, min_y, max_x, max_y = self._get_room_bbox(room)
        
        # Compute anchors center as reference
        if not self.anchors:
            print("❌ No anchors available. Create anchors first.")
            return False
        anchors_cx = sum(a['x_coord'] for a in self.anchors) / len(self.anchors)
        anchors_cy = sum(a['y_coord'] for a in self.anchors) / len(self.anchors)
        
        # Scan WiFi networks
        networks = self.scan_wifi_networks()
        if not networks:
            print("❌ No WiFi networks detected.")
            return False
        
        inside = []
        for net in networks:
            sig = net.get('signal', '')
            if isinstance(sig, str) and 'dBm' in sig:
                try:
                    sig_dbm = float(sig.replace(' dBm', ''))
                except Exception:
                    continue
            else:
                # If signal is percent or unknown, skip
                continue
            nx, ny = self._estimate_network_xy(sig_dbm, anchors_cx, anchors_cy)
            net['est_x'] = nx
            net['est_y'] = ny
            if (nx >= min_x and nx <= max_x and ny >= min_y and ny <= max_y):
                inside.append(net)
        
        if not inside:
            print("⚠️  No networks estimated inside the room boundary.")
            return True
        
        print(f"\n✅ Networks likely inside '{room['name']}':")
        print("=" * 80)
        print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<10} {'X':>6} {'Y':>6}")
        print("-" * 80)
        for idx, net in enumerate(inside, 1):
            ssid = net.get('ssid', 'Hidden')[:24]
            bssid = net.get('bssid', 'Unknown')[:17]
            sig = net.get('signal', 'N/A')
            print(f"{idx:<3} {ssid:<25} {bssid:<18} {sig:<10} {net['est_x']:>6.1f} {net['est_y']:>6.1f}")
        print("=" * 80)
        return True


def main():
    """Main entry point."""
    try:
        system = WiFiLocationSystem()
        system.run()
    except Exception as e:
        print(f"❌ System error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
