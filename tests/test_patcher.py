"""
Unit tests for VibeSafe Deterministic Patch Engine & Verification Loop
"""
import unittest
from vibesafe.patcher import remediate_code, generate_patch_for_line, apply_patch
from vibesafe.scanner import scan_code

class TestPatcher(unittest.TestCase):

    def test_indentation_preserved_in_patches(self):
        code_line = "        os.system('echo ' + user_input)"
        vuln = {'type': 'COMMAND_INJECTION', 'line': 1, 'snippet': code_line.strip()}
        patch_result = generate_patch_for_line(code_line, vuln)
        lines = patch_result['patch'].split('\n')
        # Each non-empty line of the patch must start with the exact 8 spaces of indentation
        for line in lines:
            if line.strip():
                self.assertTrue(line.startswith("        "), f"Line missing indent: {line}")

    def test_end_to_end_remediation_reduces_vulns_to_zero(self):
        vulnerable_code = '''import os
import sqlite3

API_KEY = 'sk_live_99812739182739182739'

def execute_query(user_input):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    os.system("echo " + user_input)
    val = eval(user_input)
    return cursor.fetchall()
'''
        result = remediate_code(vulnerable_code)

        self.assertTrue(result['is_verified'])
        self.assertIsNone(result['error'])
        self.assertGreater(len(result['initial_vulns']), 0)
        self.assertEqual(len(result['final_vulns']), 0)
        self.assertTrue(len(result['diff']) > 0)

        # Patched code must be valid Python
        rescan_vulns, rescan_err = scan_code(result['patched_code'])
        self.assertIsNone(rescan_err, f"Patched code should not produce syntax error: {rescan_err}")
        self.assertEqual(len(rescan_vulns), 0)

    def test_remediate_empty_or_clean_code(self):
        clean_code = "def hello():\n    return 'world'\n"
        result = remediate_code(clean_code)
        self.assertTrue(result['is_verified'])
        self.assertEqual(len(result['initial_vulns']), 0)
        self.assertEqual(result['patched_code'], clean_code)

    def test_remediate_syntax_error_returns_clean_error(self):
        broken_code = "def broken(:\n    pass"
        result = remediate_code(broken_code)
        self.assertFalse(result['is_verified'])
        self.assertIsNotNone(result['error'])
        self.assertIn("Syntax Error", result['message'])

    def test_auto_import_injection(self):
        code_without_imports = '''
API_KEY = "sk_live_123456789012345678"

def run(cmd):
    eval(cmd)
'''
        result = remediate_code(code_without_imports)
        patched = result['patched_code']
        self.assertIn("import os", patched)
        self.assertIn("import ast", patched)

if __name__ == '__main__':
    unittest.main()
