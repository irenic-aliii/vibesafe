"""
VibeSafe AST Security Scanner
Deterministic Python Abstract Syntax Tree (AST) Analysis Engine
"""
import ast
import re
import math

def calculate_shannon_entropy(data):
    """
    Calculate Shannon entropy (measure of unpredictability/randomness) of a string.
    """
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

SECRET_KEYWORD_PATTERNS = re.compile(
    r'(?i)(api[_-]?key|secret|token|password|passwd|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)'
)

KNOWN_PREFIX_PATTERNS = re.compile(
    r'^(sk_live_[0-9a-zA-Z]{16,}|sk_test_[0-9a-zA-Z]{16,}|ghp_[0-9a-zA-Z]{20,}|gho_[0-9a-zA-Z]{20,}|AKIA[0-9A-Z]{16}|xoxb-[0-9a-zA-Z\-]{20,}|glpat-[0-9a-zA-Z\-]{20,})'
)

class VibeSafeASTScanner(ast.NodeVisitor):
    def __init__(self, source_code):
        self.source_code = source_code
        self.lines = source_code.splitlines() if source_code else []
        self.vulnerabilities = []
        # Track variable names assigned to dangerous concatenated strings (e.g. query = f"SELECT...")
        self.tainted_strings = {}

    def _get_line_snippet(self, lineno):
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_Assign(self, node):
        # 1. Track variables assigned f-strings or concatenated strings (for SQLi taint tracking)
        is_dynamic_str = False
        if isinstance(node.value, ast.JoinedStr):
            is_dynamic_str = True
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
            is_dynamic_str = True
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'format':
            is_dynamic_str = True

        if is_dynamic_str:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_strings[target.id] = node.lineno

        # 2. Hardcoded Secret Detection
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            entropy = calculate_shannon_entropy(val)
            is_secret = False
            matched_var = "Secret"
            reason = ""

            for target in node.targets:
                target_name = target.id if isinstance(target, ast.Name) else ""
                # Check A: Variable name matches secret naming convention
                if target_name and SECRET_KEYWORD_PATTERNS.search(target_name) and len(val) >= 6:
                    is_secret = True
                    matched_var = target_name
                    reason = f"Credential variable '{matched_var}' assigned literal secret value"
                    break

            # Check B: Known token prefix (e.g. Stripe, GitHub, AWS, Slack)
            if not is_secret and KNOWN_PREFIX_PATTERNS.search(val):
                is_secret = True
                matched_var = "API Token"
                reason = f"String matches known high-risk API credential signature"

            # Check C: Very high Shannon entropy with minimum length and character diversity
            if not is_secret and len(val) >= 20 and entropy >= 3.7:
                has_digits = any(c.isdigit() for c in val)
                has_alpha = any(c.isalpha() for c in val)
                # Ensure it's not normal spaced natural language prose
                space_ratio = val.count(' ') / len(val)
                if has_digits and has_alpha and space_ratio < 0.1:
                    is_secret = True
                    matched_var = "High Entropy Value"
                    reason = f"High Shannon entropy string ({entropy:.2f}) without whitespace"

            if is_secret:
                self.vulnerabilities.append({
                    'id': f'SECRET-{node.lineno}-{len(self.vulnerabilities) + 1}',
                    'type': 'HARDCODED_SECRET',
                    'line': node.lineno,
                    'col': node.col_offset,
                    'severity': 'HIGH',
                    'cwe': 'CWE-798: Use of Hard-coded Credentials',
                    'msg': f'Hardcoded secret detected: {reason}. Should be loaded from environment variables.',
                    'snippet': self._get_line_snippet(node.lineno),
                    'can_remediate': True
                })

        self.generic_visit(node)

    def visit_Call(self, node):
        # 1. Dangerous Functions (eval, exec)
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                self.vulnerabilities.append({
                    'id': f'DANGEROUS-FUNC-{node.lineno}-{len(self.vulnerabilities) + 1}',
                    'type': 'DANGEROUS_FUNC',
                    'line': node.lineno,
                    'col': node.col_offset,
                    'severity': 'HIGH',
                    'cwe': 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)',
                    'msg': f'Critical: Direct use of {node.func.id}() enables arbitrary code execution.',
                    'snippet': self._get_line_snippet(node.lineno),
                    'can_remediate': True
                })

        # 2. Command Injection
        # A: os.system, os.popen
        if isinstance(node.func, ast.Attribute):
            is_os_call = False
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                is_os_call = True
            elif node.func.attr in ('system', 'popen'):
                is_os_call = True

            if is_os_call and node.func.attr in ('system', 'popen'):
                self.vulnerabilities.append({
                    'id': f'CMD-INJECT-{node.lineno}-{len(self.vulnerabilities) + 1}',
                    'type': 'COMMAND_INJECTION',
                    'line': node.lineno,
                    'col': node.col_offset,
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
                    'msg': f'Command Injection Risk: os.{node.func.attr}() invokes shell without parameter isolation.',
                    'snippet': self._get_line_snippet(node.lineno),
                    'can_remediate': True
                })

            # B: subprocess with shell=True
            if (isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess') or \
               node.func.attr in ('Popen', 'run', 'call', 'check_output', 'check_call'):
                for kw in node.keywords:
                    if kw.arg == 'shell':
                        if (isinstance(kw.value, ast.Constant) and kw.value.value is True) or \
                           (isinstance(kw.value, ast.Name) and kw.value.id == 'True'):
                            self.vulnerabilities.append({
                                'id': f'CMD-INJECT-{node.lineno}-{len(self.vulnerabilities) + 1}',
                                'type': 'COMMAND_INJECTION',
                                'line': node.lineno,
                                'col': node.col_offset,
                                'severity': 'CRITICAL',
                                'cwe': 'CWE-78: OS Command Injection via shell=True',
                                'msg': f'Command Injection Risk: subprocess.{node.func.attr}() called with shell=True.',
                                'snippet': self._get_line_snippet(node.lineno),
                                'can_remediate': True
                            })

            # 3. SQL Injection Detection
            if node.func.attr in ('execute', 'executemany', 'query'):
                if node.args:
                    arg = node.args[0]
                    is_sqli = False
                    reason = ""

                    # Check direct f-string argument
                    if isinstance(arg, ast.JoinedStr):
                        is_sqli = True
                        reason = "f-string string interpolation"
                    # Check direct concatenation (+) or modulo formatting (%)
                    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                        is_sqli = True
                        reason = "concatenated string operator (+ or %)"
                    # Check .format() call
                    elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                        is_sqli = True
                        reason = "unparameterized .format() string formatting"
                    # Check variable that was assigned an f-string or concatenation earlier
                    elif isinstance(arg, ast.Name) and arg.id in self.tainted_strings:
                        is_sqli = True
                        reason = f"dynamically constructed variable '{arg.id}' (line {self.tainted_strings[arg.id]})"

                    if is_sqli:
                        self.vulnerabilities.append({
                            'id': f'SQL-INJECT-{node.lineno}-{len(self.vulnerabilities) + 1}',
                            'type': 'SQL_INJECTION',
                            'line': node.lineno,
                            'col': node.col_offset,
                            'severity': 'CRITICAL',
                            'cwe': 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
                            'msg': f'SQL Injection Risk: {node.func.attr}() executed with {reason}. Use parameterized queries.',
                            'snippet': self._get_line_snippet(node.lineno),
                            'can_remediate': True
                        })

        self.generic_visit(node)


def scan_code(source_code):
    """
    Parses and deterministically analyzes source code with AST.
    Returns: (list_of_vulnerabilities, error_string_or_None)
    """
    if not source_code or not source_code.strip():
        return [], None

    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        err_msg = f"Syntax Error on line {e.lineno or 1}: {e.msg or 'Invalid syntax'}"
        return [], err_msg
    except Exception as e:
        return [], f"Failed to parse AST: {str(e)}"

    scanner = VibeSafeASTScanner(source_code)
    scanner.visit(tree)
    return scanner.vulnerabilities, None
