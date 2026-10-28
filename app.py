import streamlit as st
from aegis_patch.scanner import scan_code
from aegis_patch.auditor import audit_requirements_text
from aegis_patch.patcher import generate_patch, apply_patch

st.set_page_config(page_title="AegisPatch - Security Compiler", page_icon="🛡️", layout="wide")

# Custom CSS for a sleek dark/security theme
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #ffffff; }
    .stButton>button { width: 100%; background-color: #ff4b4b; color: white; font-weight: bold; border-radius: 6px; }
    .stButton>button:hover { background-color: #ff2b2b; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ AegisPatch: AI Security Compiler")
st.markdown("### *The deterministic security layer and verification loop for AI-generated code.*")

tab1, tab2 = st.tabs(["⚡ AST Security Scanner & Auto-Patcher", "📦 Slopsquatting Supply-Chain Auditor"])

with tab1:
    st.markdown("### Code Vulnerability Scanner & Verification Loop")
    st.info("Paste your Python code below. AegisPatch parses the AST, detects critical vulnerabilities, auto-patches them, and re-scans to prove the bug count drops to zero.")

    sample_code = """import os
password = 'supersecretpassword12345'
os.system('rm -rf /tmp/' + user_input)
result = eval(user_input)"""

    code_input = st.text_area("Source Code Editor", value=sample_code, height=220)

    col1, col2 = st.columns(2)
    with col1:
        scan_clicked = st.button("🔍 Scan Vulnerabilities")
    with col2:
        patch_clicked = st.button("⚡ Run Auto-Patch & Verify Loop")

    if scan_clicked:
        vulns, err = scan_code(code_input)
        if err:
            st.error(err)
        else:
            st.metric("Vulnerabilities Detected", len(vulns))
            if len(vulns) == 0:
                st.success("✅ Clean code! No vulnerabilities detected.")
            else:
                for v in vulns:
                    st.error(f"**[{v['severity']}] Line {v['line']}**: {v['msg']}")

    if patch_clicked:
        vulns, err = scan_code(code_input)
        if err:
            st.error(err)
        else:
            st.metric("Vulnerabilities Before Patch", len(vulns))

            patched = code_input
            for v in vulns:
                patch_data = generate_patch(v)
                patched = apply_patch(patched, v, patch_data['patch'])

            final_vulns, _ = scan_code(patched)
            st.metric("Vulnerabilities After Patch", len(final_vulns))

            st.markdown("### Secure Patched Code (Diff Output)")
            st.code(patched, language='python')

            if len(final_vulns) == 0:
                st.success("✅ VERIFICATION PROOF: Vulnerability count successfully reduced from {} to 0.".format(len(vulns)))
            else:
                st.warning("⚠️ Partial fix applied. Remaining: {}".format(len(final_vulns)))

with tab2:
    st.markdown("### AI Slopsquatting & Dependency Auditor")
    st.markdown("Checks `requirements.txt` packages against the live PyPI registry to catch AI-hallucinated package names before installation.")

    sample_reqs = "requests\nastroid\nstreamlit\nfake_ai_hallucinated_pkg_xyz123"
    reqs_input = st.text_area("Dependencies List (`requirements.txt`)", value=sample_reqs, height=150)

    if st.button("📦 Audit Live Dependencies"):
        results = audit_requirements_text(reqs_input)
        for res in results:
            if res['risk'] == 'CRITICAL':
                st.error(f"❌ `{res['package']}`: **SLOPSQUATTED / HALLUCINATED** (Package does not exist on live PyPI. Do not `pip install`!)")
            else:
                st.success(f"✅ `{res['package']}`: Valid PyPI package.")

st.markdown("---")
st.caption("AegisPatch — Built for PromptWars 2026. Deterministic AST Analysis & Live Verification Loop.")
