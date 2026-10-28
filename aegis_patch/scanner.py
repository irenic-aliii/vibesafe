import ast
import re
import math

def calculate_shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

class AegisScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        # 1. Dangerous Functions (eval, exec)
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    'type': 'DANGEROUS_FUNC',
                    'line': node.lineno,
                    'severity': 'HIGH',
                    'msg': f'Critical: Use of {node.func.id}() allows arbitrary code execution.'
                })

        # 2. Command Injection (os.system, subprocess.Popen/run with shell=True)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ['system', 'popen']:
                self.vulnerabilities.append({
                    'type': 'COMMAND_INJECTION',
                    'line': node.lineno,
                    'severity': 'CRITICAL',
                    'msg': f'Command Injection Risk: {node.func.attr}() executed with unverified string.'
                })

        self.generic_visit(node)

    def visit_Assign(self, node):
        # 3. Hardcoded Secrets & High Entropy Strings
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            entropy = calculate_shannon_entropy(val)
            # High entropy string (> 4.5) with length > 12 usually indicates API keys/tokens
            if len(val) >= 12 and entropy > 4.2:
                for target in node.targets:
                    var_name = target.id if isinstance(target, ast.Name) else "Secret"
                    self.vulnerabilities.append({
                        'type': 'HARDCODED_SECRET',
                        'line': node.lineno,
                        'severity': 'HIGH',
                        'msg': f'Hardcoded Secret Detected: {var_name} has high Shannon Entropy ({entropy:.2f}).'
                    })
        self.generic_visit(node)

def scan_code(source_code):
    try:
        tree = ast.parse(source_code)
        scanner = AegisScanner()
        scanner.visit(tree)
        return scanner.vulnerabilities, None
    except SyntaxError as e:
        return [], f"Syntax Error on line {e.lineno}: {e.msg}"
