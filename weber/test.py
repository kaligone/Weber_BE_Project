from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO()

socketio.init_app(app)

@socketio.on('message')
def handleMessage(msg):
    print(f"Message: {msg}")
    send(msg, broadcast=True)

if __name__ == "__main__":
    socketio.run(
        app, host='0.0.0.0', port="5000", debug=True)

if __name__ == "__main__":
    socketio.run(app)
