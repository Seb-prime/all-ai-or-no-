import random
from datetime import datetime, timedelta
 
USERS = [
    {"id": "u001", "name": "Cpl. Sai'goat'krishna",    "clearance": 1, "dept": "Logistics"},
    {"id": "u002", "name": "Lt. Yadav Madhav",  "clearance": 2, "dept": "Intelligence"},
    {"id": "u003", "name": "Maj. shiva reddy",       "clearance": 3, "dept": "Operations"},
    {"id": "u004", "name": "Sgt. vishal bum",    "clearance": 1, "dept": "Communications"},
    {"id": "u005", "name": "Col. Shashank DON",   "clearance": 4, "dept": "Command"},
    {"id": "u006", "name": "Pvt. Black Jack",      "clearance": 0, "dept": "Admin"},
]
 
CLEARANCE_LABELS = {0: "UNCLASSIFIED", 1: "RESTRICTED", 2: "SECRET", 3: "TOP SECRET", 4: "COSMIC SUPER MEGA TOP SECRET"}
 
FILES = [
    {"name": "logistics_schedule.xlsx",     "clearance": 1},
    {"name": "agent_identities_2046.pdf",   "clearance": 3},
    {"name": "super_mega_ultra_secret.docx",     "clearance": 3},
    {"name": "comms_frequencies.enc",       "clearance": 2},
    {"name": "command_override_codes.bin",  "clearance": 4},
    {"name": "admin_roster.csv",            "clearance": 0},
    {"name": "satellite_imagery_q3.zip",    "clearance": 3},
    {"name": "budget_report_fy25.xlsx",     "clearance": 1},
]
 
KNOWN_IPS = ["10.0.1.{0}".format(i) for i in range(10, 30)]
SUSPICIOUS_IPS = ["185.220.101.47", "91.108.4.200", "77.88.55.60", "198.54.117.212"]
 
 
def _user():
    return random.choice(USERS)
 
 
def _now_str():
    jitter = random.randint(0, 300)
    return (datetime.utcnow() - timedelta(seconds=jitter)).isoformat()
 
 
def generate_login_event(force_anomaly=False):
    user = _user()
    hour = random.randint(0, 23)
    ip = random.choice(KNOWN_IPS)
    failed_attempts = 0
    anomaly = False
    reasons = []
 
    if force_anomaly or random.random() < 0.2:
        anomaly_type = random.choice(["odd_hour", "suspicious_ip", "brute_force"])
        if anomaly_type == "odd_hour":
            hour = random.choice([0, 1, 2, 3, 4, 23])
            reasons.append("login outside business hours ({0}:00 UTC)".format(hour))
            anomaly = True
        elif anomaly_type == "suspicious_ip":
            ip = random.choice(SUSPICIOUS_IPS)
            reasons.append("login from flagged external IP {0}".format(ip))
            anomaly = True
        elif anomaly_type == "brute_force":
            failed_attempts = random.randint(7, 15)
            reasons.append("{0} failed attempts before success".format(failed_attempts))
            anomaly = True
 
    return {
        "type": "login",
        "timestamp": _now_str(),
        "user_id": user["id"],
        "user_name": user["name"],
        "department": user["dept"],
        "clearance_level": user["clearance"],
        "clearance_label": CLEARANCE_LABELS[user["clearance"]],
        "ip_address": ip,
        "hour_utc": hour,
        "failed_attempts": failed_attempts,
        "success": True,
        "anomaly": anomaly,
        "risk_score": round(random.uniform(0.6, 0.95), 2) if anomaly else round(random.uniform(0.01, 0.25), 2),
        "reasons": reasons
    }
 
 
def generate_file_event(force_anomaly=False):
    user = _user()
    file = random.choice(FILES)
    anomaly = False
    reasons = []
 
    clearance_breach = user["clearance"] < file["clearance"]
 
    if force_anomaly or clearance_breach or random.random() < 0.1:
        if clearance_breach or force_anomaly:
            file = random.choice([f for f in FILES if f["clearance"] > user["clearance"]] or FILES)
            anomaly = True
            reasons.append(
                "user clearance {0} ({1}) attempted access to {2} file ({3})".format(
                    user["clearance"],
                    CLEARANCE_LABELS[user["clearance"]],
                    CLEARANCE_LABELS.get(file["clearance"], "UNKNOWN"),
                    file["name"]
                )
            )
 
    return {
        "type": "file_access",
        "timestamp": _now_str(),
        "user_id": user["id"],
        "user_name": user["name"],
        "department": user["dept"],
        "user_clearance": user["clearance"],
        "user_clearance_label": CLEARANCE_LABELS[user["clearance"]],
        "file_name": file["name"],
        "file_clearance": file["clearance"],
        "file_clearance_label": CLEARANCE_LABELS[file["clearance"]],
        "access_granted": not anomaly,
        "anomaly": anomaly,
        "risk_score": round(random.uniform(0.7, 0.99), 2) if anomaly else round(random.uniform(0.01, 0.2), 2),
        "reasons": reasons
    }
 
 
def generate_network_event(force_anomaly=False):
    user = _user()
    src_ip = random.choice(KNOWN_IPS)
    dst_ip = random.choice(KNOWN_IPS + SUSPICIOUS_IPS)
    protocol = random.choice(["TCP", "UDP", "HTTPS", "DNS"])
    bytes_sent = random.randint(1_000, 50_000)
    anomaly = False
    reasons = []
 
    if force_anomaly or random.random() < 0.15:
        anomaly_type = random.choice(["exfil", "port_scan", "ext_beacon"])
        if anomaly_type == "exfil":
            bytes_sent = random.randint(500_000, 5_000_000)
            dst_ip = random.choice(SUSPICIOUS_IPS)
            reasons.append("unusually large outbound transfer ({0} KB) to external IP {1}".format(
                bytes_sent // 1024, dst_ip))
            anomaly = True
        elif anomaly_type == "port_scan":
            protocol = "TCP"
            reasons.append("rapid sequential port probing detected from {0}".format(src_ip))
            anomaly = True
        elif anomaly_type == "ext_beacon":
            dst_ip = random.choice(SUSPICIOUS_IPS)
            reasons.append("repeated beaconing to known C2 IP {0}".format(dst_ip))
            anomaly = True
 
    return {
        "type": "network",
        "timestamp": _now_str(),
        "user_id": user["id"],
        "user_name": user["name"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "bytes_sent": bytes_sent,
        "bytes_kb": round(bytes_sent / 1024, 1),
        "anomaly": anomaly,
        "risk_score": round(random.uniform(0.65, 0.98), 2) if anomaly else round(random.uniform(0.01, 0.3), 2),
        "reasons": reasons
    }
 
 
def generate_batch(n=10):
    generators = [generate_login_event, generate_file_event, generate_network_event]
    return [random.choice(generators)() for _ in range(n)]