import json
import streamlit as st
import random
import time
from backend import FirewallXBackend

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="FirewallX | MoD Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@400;600;700&family=Barlow:wght@300;400;500&display=swap');

/* ── Base ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080d14 !important;
    color: #c8d8e8 !important;
    font-family: 'Barlow', sans-serif !important;
}

[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 255, 128, 0.012) 2px,
        rgba(0, 255, 128, 0.012) 4px
    );
    pointer-events: none;
    z-index: 0;
}

[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { background: #0b1320 !important; }

/* ── Typography ── */
h1, h2, h3, h4 {
    font-family: 'Barlow Condensed', sans-serif !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}

code, .stJson, pre {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
}

/* ── Header banner ── */
.fwx-header {
    background: linear-gradient(135deg, #0d1b2a 0%, #0a1628 60%, #071020 100%);
    border: 1px solid #1e3a5f;
    border-left: 4px solid #00ff88;
    border-radius: 4px;
    padding: 20px 32px 16px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
}
.fwx-header::after {
    content: "CLASSIFIED // SECRET";
    position: absolute;
    top: 10px; right: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    color: #ff4444;
    letter-spacing: 0.2em;
    opacity: 0.7;
}
.fwx-header h1 {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-size: 2.2rem !important;
    font-weight: 700 !important;
    color: #00ff88 !important;
    margin: 0 0 4px !important;
    letter-spacing: 0.12em !important;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
}
.fwx-header p {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #4a7fa5;
    margin: 0;
    letter-spacing: 0.15em;
}

/* ── Section labels ── */
.fwx-section {
    font-family: 'Barlow Condensed', sans-serif;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.25em;
    color: #4a7fa5;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 6px;
    margin: 28px 0 14px;
}

/* ── Cards / panels ── */
.fwx-card {
    background: #0d1b2a;
    border: 1px solid #1e3a5f;
    border-radius: 4px;
    padding: 18px 22px;
    margin-bottom: 12px;
}

/* ── Metric tiles ── */
[data-testid="stMetric"] {
    background: #0d1b2a !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 4px !important;
    padding: 14px 18px !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.65rem !important;
    color: #4a7fa5 !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    color: #00ff88 !important;
}

/* ── Buttons ── */
.stButton > button {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-weight: 600 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    font-size: 0.82rem !important;
    border-radius: 3px !important;
    border: 1px solid #1e3a5f !important;
    background: #0d1b2a !important;
    color: #7ab3d4 !important;
    padding: 8px 18px !important;
    transition: all 0.15s ease !important;
    width: 100% !important;
}
.stButton > button:hover {
    border-color: #00ff88 !important;
    color: #00ff88 !important;
    background: #0a2010 !important;
    box-shadow: 0 0 12px rgba(0,255,136,0.15) !important;
}

/* ── Slider ── */
[data-testid="stSlider"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    color: #4a7fa5 !important;
    letter-spacing: 0.1em !important;
}
[data-testid="stSlider"] [data-baseweb="slider"] div[role="slider"] {
    background: #00ff88 !important;
}

/* ── Alerts ── */
[data-testid="stAlert"] {
    border-radius: 3px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.04em !important;
}
div[data-baseweb="notification"][kind="positive"] {
    background: rgba(0,255,136,0.06) !important;
    border-left: 3px solid #00ff88 !important;
}
div[data-baseweb="notification"][kind="negative"] {
    background: rgba(255,60,60,0.07) !important;
    border-left: 3px solid #ff3c3c !important;
}
div[data-baseweb="notification"][kind="warning"] {
    background: rgba(255,180,0,0.06) !important;
    border-left: 3px solid #ffb400 !important;
}
div[data-baseweb="notification"][kind="info"] {
    background: rgba(0,120,255,0.06) !important;
    border-left: 3px solid #0078ff !important;
}

/* ── JSON viewer ── */
[data-testid="stJson"] {
    background: #060e18 !important;
    border: 1px solid #132035 !important;
    border-radius: 3px !important;
    font-size: 0.72rem !important;
}

/* ── Threat list rows ── */
.threat-row {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #ff6b6b;
    background: rgba(255,60,60,0.04);
    border-left: 3px solid #ff3c3c;
    padding: 6px 12px;
    margin-bottom: 6px;
    border-radius: 0 3px 3px 0;
    letter-spacing: 0.06em;
}

/* ── Status badge ── */
.status-ok {
    display: inline-block;
    background: rgba(0,255,136,0.08);
    border: 1px solid #00ff88;
    color: #00ff88;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    padding: 6px 16px;
    border-radius: 3px;
}
.status-bad {
    display: inline-block;
    background: rgba(255,60,60,0.08);
    border: 1px solid #ff3c3c;
    color: #ff3c3c;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    padding: 6px 16px;
    border-radius: 3px;
}
.period-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    padding: 5px 14px;
    border-radius: 3px;
    display: inline-block;
    margin-bottom: 12px;
}
.period-off    { background:rgba(255,180,0,0.08); border:1px solid #ffb400; color:#ffb400; }
.period-peak   { background:rgba(0,255,136,0.07); border:1px solid #00ff88; color:#00ff88; }
.period-shoulder{ background:rgba(0,120,255,0.07); border:1px solid #0078ff; color:#0078ff; }

/* ── Divider ── */
hr { border-color: #1e3a5f !important; margin: 24px 0 !important; }

/* ── Hide default streamlit chrome ── */
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
if "backend" not in st.session_state:
    st.session_state.backend = FirewallXBackend()
if "auto" not in st.session_state:
    st.session_state.auto = False

backend = st.session_state.backend

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="fwx-header">
    <h1>🛡 FirewallX</h1>
    <p>AI THREAT DETECTION &amp; BLOCKCHAIN AUDIT SYSTEM &nbsp;·&nbsp; MINISTRY OF DEFENCE PROTOTYPE &nbsp;·&nbsp; RESTRICTED ACCESS</p>
</div>
""", unsafe_allow_html=True)

# ── Event generator ────────────────────────────────────────────────────────────
def generate_event(force_type=None):
    hour = time.localtime().tm_hour

    if force_type == "normal":
        risk = round(random.uniform(0.1, 0.35), 2)
        failed = random.randint(0, 2)
        ip = "10.0.1.12"
        location = "india"
        device = "known_device"
    elif force_type == "high_risk":
        risk = round(random.uniform(0.75, 0.95), 2)
        failed = random.randint(8, 15)
        ip = "185.220.101.47"
        location = "unknown"
        device = "new_device"
    else:
        if hour >= 22 or hour < 6:
            attack_chance = 0.6
        elif 9 <= hour < 18:
            attack_chance = 0.15
        else:
            attack_chance = 0.35

        is_attack = random.random() < attack_chance
        risk = round(random.uniform(0.65, 0.95) if is_attack else random.uniform(0.1, 0.4), 2)
        failed = random.randint(5, 15) if is_attack else random.randint(0, 2)
        ip = "185.220.101.47" if is_attack else "10.0.1.12"
        location = "unknown" if is_attack else "india"
        device = "new_device" if is_attack else "known_device"

    return {
        "user": random.choice(["admin", "user1", "user2"]),
        "type": random.choice(["login", "file_access", "network"]),
        "hour_utc": hour,
        "risk_score": risk,
        "ip_address": ip,
        "failed_attempts": failed,
        "location": location,
        "device": device,
        "bytes_sent": random.randint(1000, 500000),
        "bytes_kb": random.randint(1, 500),
        "user_clearance": random.randint(0, 3),
        "file_clearance": random.randint(0, 4),
        "user_clearance_label": "LOW",
        "file_clearance_label": "HIGH",
        "dst_ip": ip,
    }

# ── Layout: left column (controls) | right column (status + logs) ──────────────
left, right = st.columns([1.1, 1.9], gap="large")

with left:

    # ── Manual controls ────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Manual Event Injection</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)

    with c1:
        if st.button("Normal"):
            result = backend.process_event(generate_event("normal"))
            if result["analysis"]["is_threat"]:
                st.error("THREAT")
            else:
                st.success("CLEAR")
            st.json(result["analysis"])

    with c2:
        if st.button("High Risk"):
            result = backend.process_event(generate_event("high_risk"))
            st.error("THREAT DETECTED")
            st.json(result["analysis"])

    with c3:
        if st.button("Burst ×5"):
            for _ in range(5):
                backend.process_event(generate_event("high_risk"))
            st.warning("BURST INJECTED")
            st.rerun()

    # ── Automated monitoring ───────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Automated Monitoring</div>', unsafe_allow_html=True)

    interval = st.slider("Interval (seconds)", min_value=1, max_value=10, value=3)

    ca, cb = st.columns(2)
    with ca:
        if st.button("▶ Start"):
            st.session_state.auto = True
    with cb:
        if st.button("⏹ Stop"):
            st.session_state.auto = False

    hour_now = time.localtime().tm_hour
    if hour_now >= 22 or hour_now < 6:
        period_html = '<span class="period-badge period-off"> OFF-HOURS · HIGH RISK</span>'
    elif 9 <= hour_now < 18:
        period_html = '<span class="period-badge period-peak"> PEAK HOURS · LOW RISK</span>'
    else:
        period_html = '<span class="period-badge period-shoulder"> SHOULDER HOURS · MODERATE RISK</span>'

    st.markdown(period_html, unsafe_allow_html=True)

    placeholder = st.empty()

placeholder = st.empty()

if st.session_state.auto:
    st.info("⬤ MONITORING ACTIVE")

    for _ in range(1000):  # long loop (acts like continuous stream)

        if not st.session_state.auto:
            break

        event = generate_event()
        result = backend.process_event(event)

        with placeholder.container():
            if result["analysis"]["is_threat"]:
                st.error("⚠ THREAT DETECTED")
            else:
                st.success("✓ NOMINAL")

            st.json(result["analysis"])

        time.sleep(interval)
else:
    st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;letter-spacing:0.1em;">⏸ &nbsp;MONITORING INACTIVE</div>', unsafe_allow_html=True)

    # ── Tamper simulation ──────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Integrity Testing</div>', unsafe_allow_html=True)
    if st.button("⚠ Simulate Chain Tampering"):
        backend.tamper()
        st.warning("TAMPER EVENT INJECTED")
        st.rerun()

with right:

    # ── Blockchain status ──────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Blockchain Integrity</div>', unsafe_allow_html=True)

    if backend.is_secure():
        st.markdown('<span class="status-ok">● CHAIN VALID — INTEGRITY CONFIRMED</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-bad">▲ CHAIN COMPROMISED — TAMPERING DETECTED</span>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Stats ──────────────────────────────────────────────────────────────────
    stats = backend.get_stats()
    m1, m2 = st.columns(2)
    m1.metric("TOTAL EVENTS", stats["total_events"])
    m2.metric("THREATS DETECTED", stats["total_threats"])

    # ── Recent threats ─────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Recent Threat Log</div>', unsafe_allow_html=True)
    import json
import streamlit as st
import random
import time
from backend import FirewallXBackend

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="FirewallX | MoD Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow+Condensed:wght@400;600;700&family=Barlow:wght@300;400;500&display=swap');

/* ── Base ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080d14 !important;
    color: #c8d8e8 !important;
    font-family: 'Barlow', sans-serif !important;
}

[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 255, 128, 0.012) 2px,
        rgba(0, 255, 128, 0.012) 4px
    );
    pointer-events: none;
    z-index: 0;
}

[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { background: #0b1320 !important; }

/* ── Typography ── */
h1, h2, h3, h4 {
    font-family: 'Barlow Condensed', sans-serif !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}

code, .stJson, pre {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
}

/* ── Header banner ── */
.fwx-header {
    background: linear-gradient(135deg, #0d1b2a 0%, #0a1628 60%, #071020 100%);
    border: 1px solid #1e3a5f;
    border-left: 4px solid #00ff88;
    border-radius: 4px;
    padding: 20px 32px 16px;
    margin-bottom: 28px;
    position: relative;
    overflow: hidden;
}
.fwx-header::after {
    content: "CLASSIFIED // SECRET";
    position: absolute;
    top: 10px; right: 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    color: #ff4444;
    letter-spacing: 0.2em;
    opacity: 0.7;
}
.fwx-header h1 {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-size: 2.2rem !important;
    font-weight: 700 !important;
    color: #00ff88 !important;
    margin: 0 0 4px !important;
    letter-spacing: 0.12em !important;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
}
.fwx-header p {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #4a7fa5;
    margin: 0;
    letter-spacing: 0.15em;
}

/* ── Section labels ── */
.fwx-section {
    font-family: 'Barlow Condensed', sans-serif;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.25em;
    color: #4a7fa5;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 6px;
    margin: 28px 0 14px;
}

/* ── Cards / panels ── */
.fwx-card {
    background: #0d1b2a;
    border: 1px solid #1e3a5f;
    border-radius: 4px;
    padding: 18px 22px;
    margin-bottom: 12px;
}

/* ── Metric tiles ── */
[data-testid="stMetric"] {
    background: #0d1b2a !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 4px !important;
    padding: 14px 18px !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.65rem !important;
    color: #4a7fa5 !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
    color: #00ff88 !important;
}

/* ── Buttons ── */
.stButton > button {
    font-family: 'Barlow Condensed', sans-serif !important;
    font-weight: 600 !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    font-size: 0.82rem !important;
    border-radius: 3px !important;
    border: 1px solid #1e3a5f !important;
    background: #0d1b2a !important;
    color: #7ab3d4 !important;
    padding: 8px 18px !important;
    transition: all 0.15s ease !important;
    width: 100% !important;
}
.stButton > button:hover {
    border-color: #00ff88 !important;
    color: #00ff88 !important;
    background: #0a2010 !important;
    box-shadow: 0 0 12px rgba(0,255,136,0.15) !important;
}

/* ── Slider ── */
[data-testid="stSlider"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    color: #4a7fa5 !important;
    letter-spacing: 0.1em !important;
}
[data-testid="stSlider"] [data-baseweb="slider"] div[role="slider"] {
    background: #00ff88 !important;
}

/* ── Alerts ── */
[data-testid="stAlert"] {
    border-radius: 3px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.04em !important;
}
div[data-baseweb="notification"][kind="positive"] {
    background: rgba(0,255,136,0.06) !important;
    border-left: 3px solid #00ff88 !important;
}
div[data-baseweb="notification"][kind="negative"] {
    background: rgba(255,60,60,0.07) !important;
    border-left: 3px solid #ff3c3c !important;
}
div[data-baseweb="notification"][kind="warning"] {
    background: rgba(255,180,0,0.06) !important;
    border-left: 3px solid #ffb400 !important;
}
div[data-baseweb="notification"][kind="info"] {
    background: rgba(0,120,255,0.06) !important;
    border-left: 3px solid #0078ff !important;
}

/* ── JSON viewer ── */
[data-testid="stJson"] {
    background: #060e18 !important;
    border: 1px solid #132035 !important;
    border-radius: 3px !important;
    font-size: 0.72rem !important;
}

/* ── Threat list rows ── */
.threat-row {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #ff6b6b;
    background: rgba(255,60,60,0.04);
    border-left: 3px solid #ff3c3c;
    padding: 6px 12px;
    margin-bottom: 6px;
    border-radius: 0 3px 3px 0;
    letter-spacing: 0.06em;
}

/* ── Status badge ── */
.status-ok {
    display: inline-block;
    background: rgba(0,255,136,0.08);
    border: 1px solid #00ff88;
    color: #00ff88;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    padding: 6px 16px;
    border-radius: 3px;
}
.status-bad {
    display: inline-block;
    background: rgba(255,60,60,0.08);
    border: 1px solid #ff3c3c;
    color: #ff3c3c;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    padding: 6px 16px;
    border-radius: 3px;
}
.period-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    padding: 5px 14px;
    border-radius: 3px;
    display: inline-block;
    margin-bottom: 12px;
}
.period-off    { background:rgba(255,180,0,0.08); border:1px solid #ffb400; color:#ffb400; }
.period-peak   { background:rgba(0,255,136,0.07); border:1px solid #00ff88; color:#00ff88; }
.period-shoulder{ background:rgba(0,120,255,0.07); border:1px solid #0078ff; color:#0078ff; }

/* ── Divider ── */
hr { border-color: #1e3a5f !important; margin: 24px 0 !important; }

/* ── Hide default streamlit chrome ── */
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
if "backend" not in st.session_state:
    st.session_state.backend = FirewallXBackend()
if "auto" not in st.session_state:
    st.session_state.auto = False

backend = st.session_state.backend

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="fwx-header">
    <h1>🛡 FirewallX</h1>
    <p>AI THREAT DETECTION &amp; BLOCKCHAIN AUDIT SYSTEM &nbsp;·&nbsp; MINISTRY OF DEFENCE PROTOTYPE &nbsp;·&nbsp; RESTRICTED ACCESS</p>
</div>
""", unsafe_allow_html=True)

# ── Event generator ────────────────────────────────────────────────────────────
def generate_event(force_type=None):
    hour = time.localtime().tm_hour

    if force_type == "normal":
        risk = round(random.uniform(0.1, 0.35), 2)
        failed = random.randint(0, 2)
        ip = "10.0.1.12"
        location = "india"
        device = "known_device"
    elif force_type == "high_risk":
        risk = round(random.uniform(0.75, 0.95), 2)
        failed = random.randint(8, 15)
        ip = "185.220.101.47"
        location = "unknown"
        device = "new_device"
    else:
        if hour >= 22 or hour < 6:
            attack_chance = 0.6
        elif 9 <= hour < 18:
            attack_chance = 0.15
        else:
            attack_chance = 0.35

        is_attack = random.random() < attack_chance
        risk = round(random.uniform(0.65, 0.95) if is_attack else random.uniform(0.1, 0.4), 2)
        failed = random.randint(5, 15) if is_attack else random.randint(0, 2)
        ip = "185.220.101.47" if is_attack else "10.0.1.12"
        location = "unknown" if is_attack else "india"
        device = "new_device" if is_attack else "known_device"

    return {
        "user": random.choice(["admin", "user1", "user2"]),
        "type": random.choice(["login", "file_access", "network"]),
        "hour_utc": hour,
        "risk_score": risk,
        "ip_address": ip,
        "failed_attempts": failed,
        "location": location,
        "device": device,
        "bytes_sent": random.randint(1000, 500000),
        "bytes_kb": random.randint(1, 500),
        "user_clearance": random.randint(0, 3),
        "file_clearance": random.randint(0, 4),
        "user_clearance_label": "LOW",
        "file_clearance_label": "HIGH",
        "dst_ip": ip,
    }

# ── Layout: left column (controls) | right column (status + logs) ──────────────
left, right = st.columns([1.1, 1.9], gap="large")

with left:

    # ── Manual controls ────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Manual Event Injection</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)

    with c1:
        if st.button("Normal"):
            result = backend.process_event(generate_event("normal"))
            if result["analysis"]["is_threat"]:
                st.error("THREAT")
            else:
                st.success("CLEAR")
            st.json(result["analysis"])

    with c2:
        if st.button("High Risk"):
            result = backend.process_event(generate_event("high_risk"))
            st.error("THREAT DETECTED")
            st.json(result["analysis"])

    with c3:
        if st.button("Burst ×5"):
            for _ in range(5):
                backend.process_event(generate_event("high_risk"))
            st.warning("BURST INJECTED")
            st.rerun()

    # ── Automated monitoring ───────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Automated Monitoring</div>', unsafe_allow_html=True)

    interval = st.slider("Interval (seconds)", min_value=1, max_value=10, value=3)

    ca, cb = st.columns(2)
    with ca:
        if st.button("▶ Start"):
            st.session_state.auto = True
    with cb:
        if st.button("⏹ Stop"):
            st.session_state.auto = False

    hour_now = time.localtime().tm_hour
    if hour_now >= 22 or hour_now < 6:
        period_html = '<span class="period-badge period-off"> OFF-HOURS · HIGH RISK</span>'
    elif 9 <= hour_now < 18:
        period_html = '<span class="period-badge period-peak"> PEAK HOURS · LOW RISK</span>'
    else:
        period_html = '<span class="period-badge period-shoulder"> SHOULDER HOURS · MODERATE RISK</span>'

    st.markdown(period_html, unsafe_allow_html=True)

    placeholder = st.empty()

placeholder = st.empty()

if st.session_state.auto:
    st.info("⬤ MONITORING ACTIVE")

    for _ in range(1000):  # long loop (acts like continuous stream)

        if not st.session_state.auto:
            break

        event = generate_event()
        result = backend.process_event(event)

        with placeholder.container():
            if result["analysis"]["is_threat"]:
                st.error("⚠ THREAT DETECTED")
            else:
                st.success("✓ NOMINAL")

            st.json(result["analysis"])

        time.sleep(interval)
else:
    st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;letter-spacing:0.1em;">⏸ &nbsp;MONITORING INACTIVE</div>', unsafe_allow_html=True)

    # ── Tamper simulation ──────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Integrity Testing</div>', unsafe_allow_html=True)
    if st.button("⚠ Simulate Chain Tampering"):
        backend.tamper()
        st.warning("TAMPER EVENT INJECTED")
        st.rerun()

with right:

    # ── Blockchain status ──────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Blockchain Integrity</div>', unsafe_allow_html=True)

    if backend.is_secure():
        st.markdown('<span class="status-ok">● CHAIN VALID — INTEGRITY CONFIRMED</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-bad">▲ CHAIN COMPROMISED — TAMPERING DETECTED</span>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Stats ──────────────────────────────────────────────────────────────────
    stats = backend.get_stats()
    m1, m2 = st.columns(2)
    m1.metric("TOTAL EVENTS", stats["total_events"])
    m2.metric("THREATS DETECTED", stats["total_threats"])

    # ── Recent threats ─────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Recent Threat Log</div>', unsafe_allow_html=True)
    threats = backend.get_threats()

    if threats:
        for t in threats[:5]:
            st.markdown(
                f'<div class="threat-row">'
                f'▲ &nbsp;{str(t.get("type","unknown")).upper()} &nbsp;|&nbsp; '
                f'RISK: {t.get("final_risk", 0):.2f} &nbsp;|&nbsp; '
                f'USER: {t.get("user","—")}'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;">NO THREATS RECORDED</div>', unsafe_allow_html=True)

    # ── Blockchain logs ────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Blockchain Audit Trail</div>', unsafe_allow_html=True)
    logs = backend.get_logs()
    data = json.dumps(logs, indent=4)

    st.download_button(
    label="⬇ Export Audit Log",
    data=data,
    file_name="firewallx_audit.json",
    mime="application/json"
)
    if logs:
        for block in reversed(logs):
            st.json(block)
    else:
        st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;">NO BLOCKS RECORDED</div>', unsafe_allow_html=True)
    if threats:
        for t in threats[:5]:
            st.markdown(
                f'<div class="threat-row">'
                f'▲ &nbsp;{str(t.get("type","unknown")).upper()} &nbsp;|&nbsp; '
                f'RISK: {t.get("final_risk", 0):.2f} &nbsp;|&nbsp; '
                f'USER: {t.get("user","—")}'
                f'</div>',
                unsafe_allow_html=True
            )
    else:
        st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;">NO THREATS RECORDED</div>', unsafe_allow_html=True)

    # ── Blockchain logs ────────────────────────────────────────────────────────
    st.markdown('<div class="fwx-section">Blockchain Audit Trail</div>', unsafe_allow_html=True)
    logs = backend.get_logs()
    data = json.dumps(logs, indent=4)

    st.download_button(
    label="⬇ Export Audit Log",
    data=data,
    file_name="firewallx_audit.json",
    mime="application/json"
)
    if logs:
        for block in reversed(logs):
            st.json(block)
    else:
        st.markdown('<div class="fwx-card" style="color:#4a7fa5;font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;">NO BLOCKS RECORDED</div>', unsafe_allow_html=True)