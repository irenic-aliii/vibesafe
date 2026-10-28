import streamlit as st
from aegis_patch.scanner import scan_code
from aegis_patch.auditor import audit_requirements_text
from aegis_patch.patcher import generate_patch, apply_patch

st.set_page_config(page_title="AegisPatch", layout="wide")

st.title("🛡️ AegisPatch: AI Security Compiler")
st.subheader("The 'Vibe Coding' Security Compiler.")

# State management for live loop
if 'source_code' not in st.session_state:
    st.session_state.source_code = ""

st.markdown("### 1. Code Scanner & Auto-Patcher")
code_input = st.text_area("Paste Python Code", height=300, value=st.session_state.source_code)
st.session_state.source_code = code_input

if st.button("Scan & Auto-Patch"):
    vulnerabilities, err = scan_code(st.session_state.source_code)

    if err:
        st.error(err)
    else:
        st.metric("Vulnerabilities Before Patch", len(vulnerabilities))

        # Apply Patches
        patched_code = st.session_state.source_code
        for v in vulnerabilities:
            st.warning(f"Found {v['type']} at line {v['line']}. Patching...")
            patch_data = generate_patch(v, patched_code.split('\n')[v['line']-1])
            patched_code = apply_patch(patched_code, v, patch_data['patch'])

        # Re-Verify Loop
        final_vulnerabilities, err2 = scan_code(patched_code)
        st.metric("Vulnerabilities After Patch", len(final_vulnerabilities))

        st.markdown("### Patched Code")
        st.code(patched_code, language='python')

        if len(final_vulnerabilities) < len(vulnerabilities):
            st.success("✅ Verification Loop Complete: Vulnerabilities Reduced.")
        else:
            st.error("❌ Verification Failed: Code still vulnerable.")

st.markdown("---")
st.caption("AegisPatch — Deterministic Static Analysis & Live Registry Verification")
