import os
from scapy.all import sniff
from scapy.layers.inet import IP
from backend import FirewallXBackend

backend = FirewallXBackend()

def block_ip(ip):
    cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=out action=block remoteip={ip}'
    os.system(cmd)
    print(f" Blocked IP: {ip}")

# -------- SAFETY --------
SAFE_PREFIXES = ["192.168.", "10.", "127.0.0.1"]

def is_safe(ip):
    return any(ip.startswith(p) for p in SAFE_PREFIXES)

# -------- PACKET HANDLER --------
def handle_packet(packet):
    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src

            event = {
                "user": "network",
                "type": "network",
                "hour_utc": 0,
                "risk_score": 0.8,
                "ip_address": ip_src,
                "failed_attempts": 0,
                "location": "unknown",
                "device": "network_interface"
            }

            result = backend.process_event(event)

            if result["analysis"]["is_threat"]:
                print(f"⚠ THREAT DETECTED FROM: {ip_src}")

                # 🔥 block only unsafe external IPs
                if not is_safe(ip_src):
                    block_ip(ip_src)

    except Exception as e:
        print("Error:", e)

# -------- START --------
print("Monitoring network... (Run as Administrator)")

sniff(prn=handle_packet, store=False, iface="Wi-Fi")