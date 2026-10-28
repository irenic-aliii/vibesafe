"""
AegisPatch AI Patch Agent
"""
import os

def generate_patch(vulnerability, code_snippet=""):
    return generate_deterministic_patch(vulnerability)

def generate_deterministic_patch(vulnerability):
    patches = {
        "DANGEROUS_FUNC": "# Safe alternative: ast.literal_eval()",
        "COMMAND_INJECTION": "# Safe alternative: subprocess.run(list_args, shell=False)",
        "HARDCODED_SECRET": "# Safe alternative: os.environ.get('SECRET')"
    }
    return {
        "patch": patches.get(vulnerability['type'], "# Manual review required"),
        "model": "deterministic_fallback",
        "status": "FALLBACK_DETERMINISTIC"
    }

def apply_patch(code, vulnerability, patch):
    lines = code.split('\n')
    line_idx = vulnerability['line'] - 1
    if 0 <= line_idx < len(lines):
        lines[line_idx] = patch
    return '\n'.join(lines)