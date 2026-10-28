"""
Unit tests for VibeSafe PyPI Dependency Auditor
Uses unittest.mock to test deterministically without depending on external network.
"""
import unittest
from unittest.mock import patch, MagicMock
from vibesafe.auditor import clean_package_name, check_pypi_package, audit_requirements_text, _PYPI_CACHE

class TestAuditor(unittest.TestCase):

    def setUp(self):
        _PYPI_CACHE.clear()

    def test_clean_package_name(self):
        self.assertEqual(clean_package_name("requests>=2.31.0"), "requests")
        self.assertEqual(clean_package_name("urllib3[socks] < 2.0"), "urllib3")
        self.assertEqual(clean_package_name("flask-cors ~= 3.0.10; sys_platform == 'linux'"), "flask-cors")
        self.assertEqual(clean_package_name("numpy == 1.24.0"), "numpy")
        self.assertEqual(clean_package_name("  scipy  "), "scipy")
        self.assertIsNone(clean_package_name("# comment line"))
        self.assertIsNone(clean_package_name(""))
        self.assertIsNone(clean_package_name("   "))

    @patch('requests.get')
    def test_valid_pypi_package(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'info': {
                'version': '2.31.0',
                'summary': 'Python HTTP for Humans.',
                'license': 'Apache 2.0',
                'project_url': 'https://pypi.org/project/requests/'
            }
        }
        mock_get.return_value = mock_resp

        result = check_pypi_package("requests>=2.31.0")
        self.assertIsNotNone(result)
        self.assertTrue(result['exists'])
        self.assertEqual(result['status'], 'VALID')
        self.assertEqual(result['risk'], 'LOW')
        self.assertEqual(result['version'], '2.31.0')

    @patch('requests.get')
    def test_slopsquatted_hallucinated_package(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        result = check_pypi_package("fake_ai_hallucinated_pkg_xyz")
        self.assertIsNotNone(result)
        self.assertFalse(result['exists'])
        self.assertEqual(result['status'], 'SLOPSQUATTED_HALLUCINATION')
        self.assertEqual(result['risk'], 'CRITICAL')

    @patch('requests.get')
    def test_caching_prevents_duplicate_network_calls(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'info': {'version': '1.0.0'}}
        mock_get.return_value = mock_resp

        # First call
        res1 = check_pypi_package("requests")
        # Second call with variation
        res2 = check_pypi_package("requests>=2.0.0")

        self.assertEqual(res1, res2)
        # Network request should only have occurred once
        self.assertEqual(mock_get.call_count, 1)

    @patch('requests.Session.get')
    def test_audit_requirements_text(self, mock_session_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            if 'fake-hallucination' in url:
                resp.status_code = 404
            else:
                resp.status_code = 200
                resp.json.return_value = {'info': {'version': '1.0'}}
            return resp

        mock_session_get.side_effect = side_effect

        req_text = """
# Production requirements
requests>=2.31.0
fake-hallucination-pkg==0.1
astroid
"""
        results = audit_requirements_text(req_text)
        self.assertEqual(len(results), 3)

        packages = {r['package']: r for r in results}
        self.assertEqual(packages['requests']['risk'], 'LOW')
        self.assertEqual(packages['astroid']['risk'], 'LOW')
        self.assertEqual(packages['fake-hallucination-pkg']['risk'], 'CRITICAL')

if __name__ == '__main__':
    unittest.main()
