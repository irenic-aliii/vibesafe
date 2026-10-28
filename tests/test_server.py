"""
Integration tests for VibeSafe API Server & Endpoints
"""
import unittest
import io
import json
from unittest.mock import patch, MagicMock
import server

class TestServerEndpoints(unittest.TestCase):

    def setUp(self):
        server.app.config['TESTING'] = True
        self.client = server.app.test_client()

    def test_health_endpoint(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('VibeSafe', data['engine'])

    def test_index_page_served(self):
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'VibeSafe', res.data)

    def test_scan_endpoint_detects_vulnerabilities(self):
        payload = {
            'code': '''import os
API_KEY = "sk_live_123456789012345678"
def test(x):
    os.system("echo " + x)
'''
        }
        res = self.client.post('/api/scan', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsNone(data['error'])
        self.assertEqual(len(data['vulns']), 2)
        self.assertEqual(data['metrics']['findings'], 2)

    def test_scan_endpoint_handles_empty_code(self):
        res = self.client.post('/api/scan', json={'code': ''})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data['vulns']), 0)

    def test_remediate_endpoint(self):
        payload = {
            'code': '''import os
API_KEY = "sk_live_123456789012345678"
def test(x):
    os.system("echo " + x)
'''
        }
        res = self.client.post('/api/remediate', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['is_verified'])
        self.assertEqual(len(data['final_vulns']), 0)
        self.assertIn('remediated_source.py', data['diff'])
        self.assertIn('subprocess.run', data['patched_code'])

    def test_upload_valid_python_file(self):
        file_content = b'import os\nAPI_KEY = "sk_live_999999999999999999"\n'
        data = {
            'file': (io.BytesIO(file_content), 'sample.py')
        }
        res = self.client.post('/api/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertEqual(json_data['file_type'], 'python')
        self.assertEqual(json_data['filename'], 'sample.py')
        self.assertEqual(len(json_data['vulns']), 1)

    def test_upload_invalid_file_extension_rejected(self):
        data = {
            'file': (io.BytesIO(b'binary data'), 'exploit.exe')
        }
        res = self.client.post('/api/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 400)
        json_data = res.get_json()
        self.assertIn('Unsupported file type', json_data['error'])

    def test_upload_missing_file_rejected(self):
        res = self.client.post('/api/upload', data={}, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 400)

    def test_audit_logs_lifecycle(self):
        # 1. Trigger an upload to log an event
        data = {
            'file': (io.BytesIO(b'x = 1\n'), 'clean_code.py')
        }
        self.client.post('/api/upload', data=data, content_type='multipart/form-data')

        # 2. Query logs
        res = self.client.get('/api/logs')
        self.assertEqual(res.status_code, 200)
        logs_data = res.get_json()
        self.assertIn('logs', logs_data)
        self.assertGreater(len(logs_data['logs']), 0)

        # 3. Ensure no source code stored in log metadata
        for log in logs_data['logs']:
            self.assertNotIn('code', log)

        # 4. Clear logs
        del_res = self.client.delete('/api/logs')
        self.assertEqual(del_res.status_code, 200)
        res_after = self.client.get('/api/logs')
        self.assertEqual(len(res_after.get_json()['logs']), 0)

if __name__ == '__main__':
    unittest.main()
