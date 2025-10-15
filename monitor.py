# monitor.py
import nmap
import time
import socket
from collections import defaultdict
from getmac import get_mac_address
from scapy.all import sniff, RandIP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dot11 import Dot11, Dot11Deauth
from scapy.arch.windows import get_windows_if_list
from threading import Thread
import socketio
from socketio.exceptions import ConnectionError

# CONFIGURATION
PORT_SCAN_THRESHOLD = 15
DNS_SPOOF_CACHE = {}
TIME_WINDOW = 10
port_scan_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': time.time()})
arp_table = {}
sio = socketio.Client()
LOCAL_IP = ""


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP_ADDR = s.getsockname()[0]
    except Exception:
        IP_ADDR = '127.0.0.1'
    finally:
        s.close()
    return IP_ADDR


def get_active_interface_name():
    local_ip = get_local_ip()
    all_interfaces = get_windows_if_list()
    for iface in all_interfaces:
        if local_ip in iface.get('ipv4_addrs', []):
            return iface.get('name')
    print("[WARN] Could not find interface by IP. Falling back to search by name 'WiFi'.")
    for iface in all_interfaces:
        if iface.get('name') == 'WiFi':
            return iface.get('name')
    return None


def arp_spoof_detector(packet):
    if ARP in packet and packet[ARP].op == 2:
        source_ip, source_mac = packet[ARP].psrc, packet[ARP].hwsrc
        if source_ip in arp_table and arp_table[source_ip].lower() != source_mac.lower():
            alert_message = f"Potential ARP Spoofing! IP {source_ip} is sending from a new MAC {source_mac}. Original MAC was {arp_table[source_ip]}."
            print(f"[ALERT] {alert_message}")
            sio.emit('alert_from_monitor', {'type': 'ARP Spoof', 'message': alert_message, 'severity': 'High'})
        elif source_ip not in arp_table:
            arp_table[source_ip] = source_mac


def port_scan_detector(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        if src_ip == LOCAL_IP: return
        dst_port = packet[TCP].dport
        current_time = time.time()
        if current_time - port_scan_tracker[src_ip]['first_seen'] > TIME_WINDOW:
            port_scan_tracker[src_ip]['ports'] = {dst_port}
            port_scan_tracker[src_ip]['first_seen'] = current_time
        else:
            port_scan_tracker[src_ip]['ports'].add(dst_port)
        if len(port_scan_tracker[src_ip]['ports']) > PORT_SCAN_THRESHOLD:
            alert_message = f"Potential Port Scan from {src_ip}. Probed {len(port_scan_tracker[src_ip]['ports'])} ports in {TIME_WINDOW}s."
            print(f"[ALERT] {alert_message}")
            sio.emit('alert_from_monitor', {'type': 'Port Scan', 'message': alert_message, 'severity': 'High'})
            del port_scan_tracker[src_ip]


# --- vvv THIS IS THE ROBUST, CORRECTED DNS DETECTOR vvv ---
def dns_spoof_detector(packet):
    # Check for DNS, ensure it's a response, AND ensure it has a question section (DNSQR)
    if DNS in packet and packet[DNS].qr == 1 and DNSQR in packet:
        try:
            # It's now safe to access qname
            qname = packet[DNSQR].qname.decode()

            if qname in DNS_SPOOF_CACHE:
                # Also check that an answer section exists
                if DNSRR in packet:
                    real_ip = DNS_SPOOF_CACHE[qname]
                    response_ip = packet[DNSRR].rdata
                    if real_ip != response_ip:
                        alert_message = f"Potential DNS Spoofing! Request for '{qname}' was answered with a fake IP: {response_ip} (Expected: {real_ip})."
                        print(f"[ALERT] {alert_message}")
                        sio.emit('alert_from_monitor',
                                 {'type': 'DNS Spoof', 'message': alert_message, 'severity': 'High'})
                        del DNS_SPOOF_CACHE[qname]
        except (IndexError, AttributeError) as e:
            # Catch potential errors for malformed packets just in case
            # print(f"[DEBUG] Ignoring malformed DNS packet: {e}")
            pass


# --- ^^^ END OF CORRECTED DETECTOR ^^^ ---

def deauth_detector(packet):
    if packet.haslayer(Dot11Deauth):
        victim_mac = packet.addr2
        router_mac = packet.addr1
        alert_message = f"Potential Deauthentication Attack detected! Target: {victim_mac} from AP: {router_mac}."
        print(f"[ALERT] {alert_message}")
        sio.emit('alert_from_monitor', {'type': 'Deauth Attack', 'message': alert_message, 'severity': 'High'})


def inject_arp_spoof():
    print("[SIMULATION] Injecting fake ARP packet...")
    gateway_ip = '.'.join(LOCAL_IP.split('.')[:-1]) + '.1'
    if gateway_ip not in arp_table:
        print("[SIMULATION] Cannot run ARP spoof, gateway not yet discovered.")
        return
    fake_packet = Ether() / ARP(op=2, psrc=gateway_ip, pdst=LOCAL_IP, hwsrc="00:11:22:33:44:55")
    arp_spoof_detector(fake_packet)


def inject_port_scan():
    print("[SIMULATION] Injecting fake Port Scan packets...")
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 5900, 8080, 8443, 1, 2, 3, 4, 5]
    spoofed_source_ip = str(RandIP())
    for port in ports_to_scan:
        fake_packet = IP(src=spoofed_source_ip, dst=LOCAL_IP) / TCP(dport=port)
        port_scan_detector(fake_packet)


def inject_dns_spoof():
    print("[SIMULATION] Injecting fake DNS response...")
    target_domain = "example.com."
    real_ip = "93.184.216.34"
    fake_ip = "127.0.0.1"
    DNS_SPOOF_CACHE[target_domain] = real_ip
    fake_packet = IP(src=str(RandIP()), dst=LOCAL_IP) / \
                  DNS(qr=1, qd=DNSQR(qname=target_domain), an=DNSRR(rrname=target_domain, rdata=fake_ip))
    dns_spoof_detector(fake_packet)


def inject_deauth_attack():
    print("[SIMULATION] Injecting fake Deauthentication packet...")
    gateway_ip = '.'.join(LOCAL_IP.split('.')[:-1]) + '.1'
    if gateway_ip not in arp_table or LOCAL_IP not in arp_table:
        print("[SIMULATION] Cannot run Deauth attack, device MACs not yet discovered.")
        return
    router_mac = arp_table[gateway_ip]
    local_mac = arp_table[LOCAL_IP]
    fake_packet = Dot11(addr1=local_mac, addr2=router_mac, addr3=router_mac) / Dot11Deauth()
    deauth_detector(fake_packet)


def start_sniffing(iface_name_str):
    print("[INFO] Starting all network sniffers...")

    def packet_handler(packet):
        arp_spoof_detector(packet)
        port_scan_detector(packet)
        dns_spoof_detector(packet)
        deauth_detector(packet)

    sniff(store=False, prn=packet_handler, iface=iface_name_str)


def discover_devices():
    nm = nmap.PortScanner()
    while True:
        network_range = '.'.join(LOCAL_IP.split('.')[:-1]) + '.0/24'
        print(f"[INFO] Scanning for active devices on network: {network_range}")
        nm.scan(hosts=network_range, arguments='-PR')
        scanned_hosts = {}
        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'N/A')
            vendor = nm[host]['vendor'].get(mac, 'N/A') if mac != 'N/A' else 'N/A'
            scanned_hosts[host] = {'ip': host, 'mac': mac, 'vendor': vendor}
        if LOCAL_IP not in scanned_hosts or scanned_hosts[LOCAL_IP]['mac'] == 'N/A':
            local_mac = get_mac_address(ip=LOCAL_IP)
            if local_mac:
                scanned_hosts[LOCAL_IP] = {'ip': LOCAL_IP, 'mac': local_mac.upper(), 'vendor': 'This Computer'}
        current_hosts = list(scanned_hosts.values())
        for host in current_hosts:
            if host['ip'] not in arp_table and host['mac'] != 'N/A':
                arp_table[host['ip']] = host['mac'].lower()
        sio.emit('update_from_monitor', {'devices': current_hosts})
        print(f"[INFO] Discovery complete. Found {len(current_hosts)} devices.")
        time.sleep(60)


if __name__ == '__main__':
    LOCAL_IP = get_local_ip()
    interface_to_use = get_active_interface_name()
    if not interface_to_use:
        print(f"[ERROR] Could not find a usable network interface. Exiting.")
        exit()

    print(f"[INFO] Monitoring on interface: '{interface_to_use}' (IP: {LOCAL_IP})")

    sio.on('simulate_arp_from_server', inject_arp_spoof)
    sio.on('simulate_scan_from_server', inject_port_scan)
    sio.on('simulate_dns_from_server', inject_dns_spoof)
    sio.on('simulate_deauth_from_server', inject_deauth_attack)

    try:
        sio.connect('http://localhost:5000')
    except ConnectionError as e:
        print(f"Error: Could not connect to the server. Is app.py running? \n{e}")
        exit()

    discovery_thread = Thread(target=discover_devices, daemon=True)
    discovery_thread.start()

    start_sniffing(interface_to_use)

    sio.disconnect()
