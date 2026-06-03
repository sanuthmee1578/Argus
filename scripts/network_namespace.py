import socket

try:
    socket.create_connection(("google.com", 80), timeout=3)
    print("Network works")
except Exception as e:
    print("Network blocked:", e)