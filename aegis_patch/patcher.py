"""
AegisPatch AI Patch Agent
Uses an LLM to rewrite vulnerable code into secure code.
"""
import os

def generate_patch(vulnerability, code_snippet, model="claude-3-5-sonnet-20241022"):
    """
    Generates a secure code patch for a specific vulnerability.
    Returns a dict with the patch and explanation.
    """
    prompt = f"""You are a senior security engineer. Fix this vulnerability.

VULNERABILITY TYPE: {vulnerability['type']}
SEVERITY: {vulnerability['severity']}
LINE: {vulnerability['line']}

VULNERABLE CODE:
```python
{code_snippet}
```

INSTRUCTIONS:
1. Rewrite ONLY the vulnerable line(s) into secure code.
2. Use parameterized queries for SQL injection.
3. Use subprocess.run with list args (no shell=True) for command injection.
4. Remove hardcoded secrets and use environment variables.
5. Replace eval/exec with safe alternatives.
6. Output ONLY the fixed code, no explanation.
"""

    # Use Claude API if available, otherwise return a deterministic fallback
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model=model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            return {
                "patch": message.content[0].text,
                "model": model,
                "status": "AI_GENERATED"
            }
        except Exception as e:
            return {
                "patch": f"# AI patch failed: {str(e)}",
                "model": model,
                "status": "FALLBACK_DETERMINISTIC"
            }
    else:
        # Deterministic fallback patches
        return generate_deterministic_patch(vulnerability)

def generate_deterministic_patch(vulnerability):
    """Fallback deterministic patches when no API key is available."""
    patches = {
        "DANGEROUS_FUNC": "# Safe alternative: use ast.literal_eval() for data parsing\n# Replace eval() with ast.literal_eval()",
        "COMMAND_INJECTION": "# Safe alternative: use subprocess.run() with list arguments\n# subprocess.run(['command', 'arg1', 'arg2']) - NO shell=True",
        "HARDCODED_SECRET": "# Safe alternative: use environment variables\n# import os\n# secret = os.environ.get('SECRET_KEY')"
    }
    return {
        "patch": patches.get(vulnerability['type'], "# Manual review required"),
        "model": "deterministic_fallback",
        "status": "FALLBACK_DETERMINISTIC"
    }

def apply_patch(code, vulnerability, patch):
    """Apply a generated patch to the code."""
    lines = code.split('\n')
    line_idx = vulnerability['line'] - 1
    if 0 <= line_idx < len(lines):
        lines[line_idx] = patch.split('\n')[0]
    return '\n'.join(lines)