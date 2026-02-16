# 📡 DeauthX v1.0
**The Ultimate Wi-Fi Deauthentication & Audit Tool**

Developed by **Amishck**, DeauthX is a streamlined Python-based tool designed for security researchers and authorized penetration testers to audit wireless network stability using deauthentication frames.



---

## 🛠 Features
* **Automated Interface Management**: Switches your wireless card into Monitor Mode automatically.
* **Smart Network Scanning**: Real-time SSID discovery with signal strength indicators.
* **Targeted Deauth**: Disconnect specific clients from a network.
* **Broadcast Attack**: Deauthenticate all clients on a specific Access Point.
* **Safety Auto-Cleanup**: Restores your network stack and restarts NetworkManager upon exit.

---

## 🚀 Installation & Requirements

### Prerequisites
You must be running **Linux** (Kali Linux, Parrot OS, or Arch recommended) and have the **Aircrack-ng** suite installed.

```bash
sudo apt update && sudo apt install aircrack-ng network-manager python3 -y
