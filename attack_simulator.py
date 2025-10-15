# attack_simulator.py
import nmap
from scapy.all import sendp
from scapy.layers.l2 import ARP, Ether
import time
import socket
import os
import ctypes


def is_admin():
    """Checks for administrator privileges, works on Windows and Unix-like systems."""
    try:
        # On Windows, use the shell32 library to check
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # On other systems (Linux, macOS), check for root user
        else:
            return os.geteuid() == 0
    except AttributeError:
        # If geteuid doesn't exist (like on some non-standard systems)
        return False


def get_local_ip():
    """Finds the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def simulate_port_scan(target_ip):
    """Simulates a fast Nmap scan against the target."""
    print(f"\n[+] Simulating a port scan against {target_ip}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(target_ip, '22,80,443', '-sS')
        print(f"[+] Scan simulation complete.")
    except nmap.nmap.PortScannerError:
        print("[-] Nmap error. Ensure Nmap is installed and you are running this script with administrator privileges.")


def simulate_arp_spoof(target_ip, spoof_ip):
    """Simulates an ARP spoofing attack by sending a malicious ARP reply."""
    print(f"\n[+] Simulating ARP spoof attack...")
    print(f"[+] Sending malicious ARP reply: Telling {target_ip} that {spoof_ip} is at our MAC address.")
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    sendp(arp_packet, verbose=False)
    print(f"[+] Malicious ARP packet sent.")


if __name__ == '__main__':
    # --- THIS IS THE CORRECTED ADMIN CHECK ---
    if not is_admin():
        print("\n[WARNING] This script needs administrator privileges to run correctly.")
        print("Please re-run your Command Prompt or PyCharm as an Administrator.")
        exit()
    # ----------------------------------------

    YOUR_IP = get_local_ip()
    GATEWAY_IP = '.'.join(YOUR_IP.split('.')[:-1]) + '.1'

    print("--- Attack Simulator for Educational Purposes ---")
    print(f"Detected Your IP: {YOUR_IP}")
    print(f"Assuming Gateway IP: {GATEWAY_IP}")
    print("This script will perform attacks against your own machine to test the monitor.")

    time.sleep(3)

    simulate_port_scan(target_ip=YOUR_IP)

    simulate_arp_spoof(target_ip=YOUR_IP, spoof_ip=GATEWAY_IP)