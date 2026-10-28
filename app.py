import streamlit as st
from vibesafe.scanner import scan_code
from vibesafe.auditor import audit_requirements_text
from vibesafe.patcher import remediate_code

st.set_page_config(page_title="VibeSafe - Security Compiler", page_icon="🛡️", layout="wide")

# Custom CSS for dark security theme
st.markdown("""
    <style>
    .main { background-color: #0b1120; color: #f8fafc; }
    .stButton>button { width: 100%; background-color: #10b981; color: white; font-weight: bold; border-radius: 8px; border: none; }
    .stButton>button:hover { background-color: #059669; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ VibeSafe: Deterministic Security Compiler")
st.markdown("### *Continuous AST analysis, PyPI supply-chain auditing, and closed-loop verification for AI-generated code.*")

tab1, tab2 = st.tabs(["⚡ AST Security Scanner & Remediation", "📦 AI Slopsquatting Supply-Chain Auditor"])

with tab1:
    st.markdown("### Python AST Code Vulnerability Scanner & Verification Loop")
    st.info("Paste your Python code below. VibeSafe parses the AST, identifies dangerous code constructs, applies deterministic patches, and re-scans to verify remediation.")

    sample_code = """import os
import sqlite3

API_KEY = 'sk_live_99812739182739182739'

def execute_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    os.system("echo " + user_input)
    val = eval(user_input)
    return cursor.fetchall()"""

    code_input = st.text_area("Source Code Editor", value=sample_code, height=240)

    col1, col2 = st.columns(2)
    with col1:
        scan_clicked = st.button("🔍 Scan AST Vulnerabilities")
    with col2:
        patch_clicked = st.button("⚡ Run Autonomous Remediation & Verify")

    if scan_clicked:
        vulns, err = scan_code(code_input)
        if err:
            st.error(err)
        else:
            st.metric("Vulnerabilities Detected", len(vulns))
            if len(vulns) == 0:
                st.success("✅ Clean code! No findings reported by active AST rules.")
            else:
                for v in vulns:
                    st.error(f"**[{v['severity']}] Line {v['line']}**: {v['msg']}")

    if patch_clicked:
        result = remediate_code(code_input)
        if result['error'] and not result['initial_vulns']:
            st.error(result['error'])
        else:
            col_a, col_b = st.columns(2)
            with col_a:
                st.metric("Findings Before Remediation", len(result['initial_vulns']))
            with col_b:
                st.metric("Findings After Remediation", len(result['final_vulns']))

            st.markdown("### Patched Code")
            st.code(result['patched_code'], language='python')

            if result['diff']:
                st.markdown("### Unified Diff")
                st.code(result['diff'], language='diff')

            if result['is_verified']:
                st.success(f"✅ VERIFICATION COMPLETE: {result['message']}")
            else:
                st.warning(f"⚠️ {result['message']}")

with tab2:
    st.markdown("### AI Slopsquatting & Dependency Auditor")
    st.markdown("Audits `requirements.txt` dependencies against the live PyPI registry to catch hallucinated package names before installation.")

    sample_reqs = "requests\nastroid\nstreamlit\nfake_ai_hallucinated_pkg_xyz123"
    reqs_input = st.text_area("Dependencies Manifest (`requirements.txt`)", value=sample_reqs, height=160)

    if st.button("📦 Audit Live Dependencies on PyPI"):
        results = audit_requirements_text(reqs_input)
        for res in results:
            if res['risk'] == 'CRITICAL':
                st.error(f"❌ `{res['package']}`: **SLOPSQUATTED / HALLUCINATED** ({res['summary']})")
            elif res['exists']:
                st.success(f"✅ `{res['package']}`: Valid PyPI package (v{res['version']}) - {res['summary']}")
            else:
                st.warning(f"⚠️ `{res['package']}`: {res['status']} - {res['summary']}")

st.markdown("---")
st.caption("VibeSafe — Deterministic AST Analysis & Verification Loop for AI-Generated Code.")
