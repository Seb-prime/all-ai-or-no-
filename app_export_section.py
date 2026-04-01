"""
Paste this block into app.py — inside the `right` column,
just before the Blockchain Logs section.
"""

from reporter import generate_reports
import os

# ── Export / Physical File Access ─────────────────────────────────────────────
st.markdown('<div class="fwx-section">Export &amp; Physical File Access</div>',
            unsafe_allow_html=True)

col_exp1, col_exp2, col_exp3 = st.columns(3)

with col_exp1:
    if st.button("⬇ Generate Report Files"):
        json_path, pdf_path = generate_reports()
        st.session_state["export_ready"] = True
        st.success("Files generated")

with col_exp2:
    if os.path.exists("firewallx_audit.json"):
        with open("firewallx_audit.json") as f:
            json_bytes = f.read()
        st.download_button(
            label="📄 Download JSON",
            data=json_bytes,
            file_name="firewallx_audit.json",
            mime="application/json",
        )
    else:
        st.button("📄 Download JSON", disabled=True)

with col_exp3:
    if os.path.exists("firewallx_report.pdf"):
        with open("firewallx_report.pdf", "rb") as f:
            pdf_bytes = f.read()
        st.download_button(
            label="📑 Download PDF",
            data=pdf_bytes,
            file_name="firewallx_report.pdf",
            mime="application/pdf",
        )
    else:
        st.button("📑 Download PDF", disabled=True)

# Show where files live on disk (for physical access demo)
st.markdown(
    '<div class="fwx-card" style="font-family:\'Share Tech Mono\',monospace;font-size:0.72rem;color:#4a7fa5;">'
    '📁 &nbsp;Files written to disk in the app working directory:<br>'
    '&nbsp;&nbsp;• <span style="color:#00ff88">firewallx_events.json</span> — every event (live, auto-updated)<br>'
    '&nbsp;&nbsp;• <span style="color:#00ff88">firewallx_chain.json</span> — full blockchain + tamper log (live)<br>'
    '&nbsp;&nbsp;• <span style="color:#7ab3d4">firewallx_audit.json</span> — clean audit export (on demand)<br>'
    '&nbsp;&nbsp;• <span style="color:#7ab3d4">firewallx_report.pdf</span> — formatted PDF report (on demand)'
    '</div>',
    unsafe_allow_html=True
)
