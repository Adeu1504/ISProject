# app.py
from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key!'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('[SERVER] Browser client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('[SERVER] Browser client disconnected')

@socketio.on('update_from_monitor')
def handle_monitor_update(data):
    """Relays device list from monitor to browser."""
    print('[SERVER] Relaying device list to browser...')
    socketio.emit('device_list', data)

@socketio.on('alert_from_monitor')
def handle_monitor_alert(data):
    """Relays alert from monitor to browser."""
    print('[SERVER] Relaying alert to browser...')
    socketio.emit('alert', data)

@socketio.on('run_arp_spoof')
def run_arp_spoof():
    """Relays command to monitor to simulate an ARP spoof."""
    print("[SERVER] Relaying ARP Spoof command to monitor.")
    socketio.emit('simulate_arp_from_server')

@socketio.on('run_port_scan')
def run_port_scan():
    """Relays command to monitor to simulate a Port Scan."""
    print("[SERVER] Relaying Port Scan command to monitor.")
    socketio.emit('simulate_scan_from_server')

@socketio.on('run_dns_spoof')
def run_dns_spoof():
    """Relays command to monitor to simulate a DNS Spoof."""
    print("[SERVER] Relaying DNS Spoof command to monitor.")
    socketio.emit('simulate_dns_from_server')

# --- NEW: Handler for Deauthentication Attack ---
@socketio.on('run_deauth_attack')
def run_deauth_attack():
    """Relays command to monitor to simulate a Deauthentication Attack."""
    print("[SERVER] Relaying Deauth Attack command to monitor.")
    socketio.emit('simulate_deauth_from_server')


if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
