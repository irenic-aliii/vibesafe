import streamlit as st
from aegis_patch.scanner import scan_code
from aegis_patch.auditor import audit_requirements_text

st.set_page_config(page_title="AegisPatch", layout="wide")

st.title("🛡️ AegisPatch: AI Security Compiler")
st.subheader("Securing the future of Vibe Coding.")

col1, col2 = st.columns(2)

with col1:
    st.markdown("### 1. Code Scanner")
    code = st.text_area("Paste Python Code", height=300)
    if st.button("Scan Code Vulnerabilities"):
        vulnerabilities, err = scan_code(code)
        if err:
            st.error(err)
        else:
            st.metric("Vulnerabilities Found", len(vulnerabilities))
            for v in vulnerabilities:
                st.error(f"**[{v['severity']}] Line {v['line']}**: {v['msg']}")

with col2:
    st.markdown("### 2. Supply-Chain Auditor")
    reqs = st.text_area("Paste requirements.txt", height=300)
    if st.button("Audit Dependencies"):
        results = audit_requirements_text(reqs)
        st.write("### Auditor Results")
        for res in results:
            if res['risk'] == 'CRITICAL':
                st.error(f"❌ {res['package']}: {res['status']}")
            else:
                st.success(f"✅ {res['package']}: {res['status']}")

st.markdown("---")
st.caption("AegisPatch — Deterministic Static Analysis & Live Registry Verification")
