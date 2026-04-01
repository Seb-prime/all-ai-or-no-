import streamlit as st
from blockchain import Blockchain

if "bc" not in st.session_state:
    st.session_state.bc = Blockchain()

bc = st.session_state.bc

st.title("FirewallX - AI Threat Detection and Blockchain Audit System")

st.subheader("Generate Threat Event")

col1, col2 = st.columns(2)

with col1:
    user = st.selectbox("User", ["admin", "user1", "user2"])
    action = st.selectbox("Action", ["login", "multiple_failed_logins"])

with col2:
    location = st.selectbox("Location", ["india", "unknown"])
    device = st.selectbox("Device", ["known_device", "new_device"])

if st.button("Add Event"):
    event = {
        "user": user,
        "action": action,
        "location": location,
        "device": device
    }

    block = bc.add_threat(event)

    st.success(f"Block {block.index} added | Risk: {block.data['risk_level']}")

    if block.data["risk_level"] == "HIGH":
        st.error("High Threat Detected")

st.subheader("Blockchain Status")

if bc.is_valid():
    st.success("Blockchain is VALID")
else:
    st.error("Blockchain has been TAMPERED")
    
if st.button("Simulate Tampering"):
    if len(bc.chain) > 1:
        bc.chain[1].data["event"]["user"] = "HACKER"
        st.warning("Blockchain has been tampered")
        
st.subheader("Blockchain Logs")

for block in reversed(bc.to_list()):
    st.json(block)
