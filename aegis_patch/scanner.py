import ast
import re

class AegisScanner(ast.NodeVisitor):
    def __init__(self):
        self.vulnerabilities = []

    def visit_Call(self, node):
        # Check for dangerous functions
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.vulnerabilities.append({
                    'type': 'DANGEROUS_FUNC',
                    'line': node.lineno,
                    'msg': f'Use of {node.func.id} is dangerous.'
                })
        self.generic_visit(node)

def scan_code(source_code):
    tree = ast.parse(source_code)
    scanner = AegisScanner()
    scanner.visit(tree)
    return scanner.vulnerabilities
