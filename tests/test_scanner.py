"""
Unit tests for VibeSafe AST Security Scanner
"""
import unittest
from vibesafe.scanner import scan_code, calculate_shannon_entropy

class TestScanner(unittest.TestCase):

    def test_clean_code_reports_zero_findings(self):
        clean_code = '''
def add(a, b):
    return a + b

class Calculator:
    def __init__(self):
        self.total = 0

    def compute(self, values):
        return sum(values)
'''
        vulns, err = scan_code(clean_code)
        self.assertIsNone(err)
        self.assertEqual(len(vulns), 0, "Clean code should produce 0 findings")

    def test_syntax_error_handled_gracefully(self):
        malformed = "def broken_func(:\n    pass"
        vulns, err = scan_code(malformed)
        self.assertEqual(len(vulns), 0)
        self.assertIsNotNone(err)
        self.assertIn("Syntax Error", err)

    def test_command_injection_detection(self):
        code = '''import os
import subprocess

def run_cmd(user_arg):
    os.system("ls " + user_arg)
    os.popen("cat " + user_arg)
    subprocess.run(["echo", user_arg], shell=True)
    subprocess.Popen("rm -rf " + user_arg, shell=True)
'''
        vulns, err = scan_code(code)
        self.assertIsNone(err)
        cmd_vulns = [v for v in vulns if v['type'] == 'COMMAND_INJECTION']
        self.assertEqual(len(cmd_vulns), 4)
        for v in cmd_vulns:
            self.assertEqual(v['severity'], 'CRITICAL')
            self.assertIn('CWE-78', v['cwe'])

    def test_dangerous_functions_eval_exec(self):
        code = '''
def run_dynamic(code_str):
    eval(code_str)
    exec(code_str)
'''
        vulns, err = scan_code(code)
        self.assertIsNone(err)
        dangerous = [v for v in vulns if v['type'] == 'DANGEROUS_FUNC']
        self.assertEqual(len(dangerous), 2)
        for v in dangerous:
            self.assertEqual(v['severity'], 'HIGH')
            self.assertIn('CWE-95', v['cwe'])

    def test_sql_injection_detection(self):
        code = '''
import sqlite3

def find_user(username, conn):
    cursor = conn.cursor()
    # 1. Direct f-string
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    # 2. String concatenation
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    # 3. Modulo formatting
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    # 4. .format() call
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(username))
    # 5. Tainted variable
    query = f"SELECT * FROM accounts WHERE id = {username}"
    cursor.execute(query)
'''
        vulns, err = scan_code(code)
        self.assertIsNone(err)
        sqli_vulns = [v for v in vulns if v['type'] == 'SQL_INJECTION']
        self.assertEqual(len(sqli_vulns), 5)
        for v in sqli_vulns:
            self.assertEqual(v['severity'], 'CRITICAL')
            self.assertIn('CWE-89', v['cwe'])

    def test_hardcoded_secrets_detection(self):
        code = '''
API_KEY = "sk_live_99812739182739182739"
DB_PASSWORD = "supersecretpassword12345"
AUTH_TOKEN = "ghp_123456789012345678901234567890"

# Normal prose string should NOT be flagged as secret
description = "This is a detailed documentation string describing module behavior."
'''
        vulns, err = scan_code(code)
        self.assertIsNone(err)
        secret_vulns = [v for v in vulns if v['type'] == 'HARDCODED_SECRET']
        self.assertEqual(len(secret_vulns), 3)
        # Verify description is NOT flagged
        snippets = [v['snippet'] for v in secret_vulns]
        self.assertFalse(any('description' in s for s in snippets))

    def test_shannon_entropy(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaaaa"), 0.0)
        # Random string should have higher entropy than repetitive string
        self.assertGreater(
            calculate_shannon_entropy("aB3$kL9#mP0!xZ8@"),
            calculate_shannon_entropy("abababababababab")
        )

if __name__ == '__main__':
    unittest.main()
