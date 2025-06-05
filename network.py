#network.py

import socket

class SecureP2PClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port))

    def send(self, data: bytes):
        if not self.sock:
            raise ConnectionError("Not connected")
        self.sock.sendall(data)

    def receive(self, bufsize: int = 8192) -> bytes:
        if not self.sock:
            raise ConnectionError("Not connected")
        return self.sock.recv(bufsize)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
