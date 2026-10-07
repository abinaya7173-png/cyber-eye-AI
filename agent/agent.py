import os
import socket
import time
import requests

API_URL = os.getenv("CYBER_EYE_API_URL", "https://YOUR-RENDER-SERVICE.onrender.com/api/events")
AGENT_API_KEY = os.getenv("CYBER_EYE_AGENT_KEY", "PASTE_YOUR_AGENT_API_KEY_HERE")

device = socket.gethostname()

print("====================================")
print("      CYBER EYE SECURITY AGENT")
print("====================================")
print("Device:", device)
print("Sending a SAFE simulated security event.")
print("This is for authorized project testing only.\n")

payload = {
    "device_id": device,
    "event_type": "failed_login",
    "source_ip": "192.0.2.10",
    "failed_attempts": 12,
    "message": "Simulated repeated failed login activity for authorized security testing."
}

try:
    r = requests.post(
        API_URL,
        json=payload,
        headers={"X-Agent-Key": AGENT_API_KEY},
        timeout=30
    )
    print("HTTP:", r.status_code)
    print(r.text)
except requests.RequestException as exc:
    print("Connection error:", exc)
