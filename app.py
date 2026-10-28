import streamlit as st
from aegis_patch.scanner import scan_code
from aegis_patch.auditor import audit_requirements_text
from aegis_patch.patcher import generate_patch, apply_patch

st.set_page_config(page_title="AegisPatch", layout="wide")

st.title("🛡️ AegisPatch: AI Security Compiler")
st.subheader("The 'Vibe Coding' Security Compiler & Verification Engine.")

tab1, tab2 = st.tabs(["⚡ AST Security Scanner & Auto-Patcher", "📦 Slopsquatting Supply-Chain Auditor"])

with tab1:
    st.markdown("### Code Vulnerability Scanner & Verification Loop")

    sample_code = """import os
password = 'supersecretpassword12345'
os.system('rm -rf /tmp/' + user_input)
result = eval(user_input)"""

    code_input = st.text_area("Paste Python Code", value=sample_code, height=200)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Scan Vulnerabilities"):
            vulns, err = scan_code(code_input)
            if err:
                st.error(err)
            else:
                st.metric("Vulnerabilities Detected", len(vulns))
                for v in vulns:
                    st.error(f"**[{v['severity']}] Line {v['line']}**: {v['msg']}")

    with col2:
        if st.button("⚡ Run Auto-Patch & Verify Loop"):
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

                st.markdown("### Secure Patched Output")
                st.code(patched, language='python')

                if len(final_vulns) == 0:
                    st.success("✅ PROOF: Vulnerability count successfully reduced to 0.")
                else:
                    st.warning("⚠️ Partial fix applied.")

with tab2:
    st.markdown("### AI Slopsquatting & Dependency Auditor")
    st.markdown("Checks requirements.txt against live PyPI registry to catch AI-hallucinated packages.")

    sample_reqs = "requests\nastroid\nstreamlit\nfake_ai_hallucinated_pkg_xyz123"
    reqs_input = st.text_area("Paste requirements.txt", value=sample_reqs, height=150)

    if st.button("Audit Live Dependencies"):
        results = audit_requirements_text(reqs_input)
        for res in results:
            if res['risk'] == 'CRITICAL':
                st.error(f"❌ `{res['package']}`: **SLOPSQUATTED / HALLUCINATED** (Package does not exist on live PyPI. Do not install!)")
            else:
                st.success(f"✅ `{res['package']}`: Valid PyPI package.")

st.markdown("---")
st.caption("AegisPatch — Built for PromptWars 2026. Deterministic AST Analysis & Live Verification.")
