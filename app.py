import streamlit as st
from aegis_patch.scanner import scan_code
from aegis_patch.auditor import audit_requirements

st.title("AegisPatch: AI Security Compiler")

code = st.text_area("Paste Python Code Here")
if st.button("Scan Code"):
    results = scan_code(code)
    st.write(f"Found {len(results)} vulnerabilities.")
    for v in results:
        st.error(f"Line {v['line']}: {v['msg']}")
