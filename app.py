# app.py
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key!'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# --- THIS IS THE DEVICE LIST RELAY ---
@socketio.on('update_from_monitor')
def handle_monitor_update(data):
    print('Received device list from monitor.py. Relaying to browser...')
    socketio.emit('device_list', data)

# --- vvv NEW FUNCTION ADDED HERE vvv ---
# --- THIS IS THE ALERT RELAY ---
@socketio.on('alert_from_monitor')
def handle_monitor_alert(data):
    """
    Receives an alert from monitor.py and relays it to all browser clients.
    """
    print('Received alert from monitor.py. Relaying to browser...')
    # We broadcast it using the 'alert' event name the browser is listening for
    socketio.emit('alert', data)
# --- ^^^ END OF NEW FUNCTION ^^^ ---

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)