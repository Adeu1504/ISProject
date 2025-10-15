# monitor.py
import nmap
import time
import socket
from getmac import get_mac_address
from scapy.all import sniff
from scapy.layers.l2 import ARP
from threading import Thread
import socketio
from socketio.exceptions import ConnectionError

arp_table = {}
sio = socketio.Client()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def arp_spoof_detector(packet):
    if ARP in packet and packet[ARP].op == 2:
        source_ip, source_mac = packet[ARP].psrc, packet[ARP].hwsrc
        if source_ip in arp_table and arp_table[source_ip].lower() != source_mac.lower():
            alert_message = f"Potential ARP Spoofing! IP {source_ip} is sending from a new MAC {source_mac}. Original MAC was {arp_table[source_ip]}."
            print(f"[ALERT] {alert_message}")

            # vvv --- THIS IS THE LINE WE ARE CHANGING --- vvv
            # Send to the new relay event instead of the generic 'alert'
            sio.emit('alert_from_monitor', {'type': 'ARP Spoof', 'message': alert_message, 'severity': 'High'})
            # ^^^ ---------------------------------------- ^^^

        elif source_ip not in arp_table:
            arp_table[source_ip] = source_mac
            print(f"[INFO] New device discovered via ARP: IP={source_ip}, MAC={source_mac}")


def start_arp_sniffing():
    print("[INFO] Starting ARP spoofing detector...")
    sniff(store=False, prn=arp_spoof_detector, filter="arp")


def discover_devices():
    nm = nmap.PortScanner()
    local_ip = get_local_ip()
    while True:
        print("[INFO] Scanning for active devices on the network using ARP scan...")
        nm.scan(hosts='172.20.10.0/28', arguments='-PR')
        scanned_hosts = {}
        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'N/A')
            vendor = nm[host]['vendor'].get(mac, 'N/A') if mac != 'N/A' else 'N/A'
            scanned_hosts[host] = {'ip': host, 'mac': mac, 'vendor': vendor}
        if local_ip not in scanned_hosts or scanned_hosts[local_ip]['mac'] == 'N/A':
            print("[INFO] Nmap failed to get local MAC. Using direct method.")
            local_mac = get_mac_address(ip=local_ip)
            if local_mac:
                scanned_hosts[local_ip] = {'ip': local_ip, 'mac': local_mac.upper(), 'vendor': 'This Computer'}
        current_hosts = list(scanned_hosts.values())
        for host in current_hosts:
            if host['ip'] not in arp_table and host['mac'] != 'N/A':
                arp_table[host['ip']] = host['mac']
        sio.emit('update_from_monitor', {'devices': current_hosts})
        print(f"[INFO] Discovery complete. Found {len(current_hosts)} devices.")
        time.sleep(30)


if __name__ == '__main__':
    try:
        sio.connect('http://localhost:5000')
    except ConnectionError as e:
        print(f"Error: Could not connect to the server. Is app.py running? \n{e}")
        exit()
    discovery_thread = Thread(target=discover_devices, daemon=True)
    discovery_thread.start()
    start_arp_sniffing()
    sio.disconnect()