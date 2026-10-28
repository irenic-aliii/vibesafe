"""
VibeSafe PyPI Dependency Auditor
Detects AI-Hallucinated Package Names (AI Slopsquatting) and Supply Chain Risks
"""
import re
import requests

# Local cache to prevent redundant network requests and improve performance
_PYPI_CACHE = {}

def clean_package_name(raw_line):
    """
    Extracts the canonical package name from a requirements.txt entry line.
    Handles version specifiers, extras, environment markers, and comments.
    Examples:
      'requests>=2.31.0' -> 'requests'
      'urllib3[socks] < 2.0' -> 'urllib3'
      'flask-cors ~= 3.0.10; python_version > "3.8"' -> 'flask-cors'
    """
    if not raw_line:
        return None
    # Strip comments
    line = raw_line.split('#')[0].strip()
    if not line:
        return None

    # Strip environment markers (e.g. ; sys_platform == 'win32')
    line = line.split(';')[0].strip()

    # Extract package name before any version specifier or bracketed extra
    match = re.match(r'^([a-zA-Z0-9_.\-]+)', line)
    if not match:
        return None

    name = match.group(1).strip()
    # Strip trailing bracket if extra was part of the regex
    name = name.split('[')[0].strip()
    return name if name else None

def check_pypi_package(package_name, session=None):
    """
    Queries live PyPI JSON API to verify package existence.
    Returns structured metadata or slopsquatting alert.
    """
    clean_name = clean_package_name(package_name)
    if not clean_name:
        return None

    normalized_key = clean_name.lower().replace('_', '-')
    if normalized_key in _PYPI_CACHE:
        return _PYPI_CACHE[normalized_key]

    url = f"https://pypi.org/pypi/{clean_name}/json"
    http = session or requests

    try:
        response = http.get(url, timeout=3.5, headers={'User-Agent': 'VibeSafe-SupplyChain-Auditor/1.0'})
        if response.status_code == 200:
            data = response.json()
            info = data.get('info', {})
            result = {
                'package': clean_name,
                'exists': True,
                'status': 'VALID',
                'risk': 'LOW',
                'version': info.get('version', 'unknown'),
                'summary': info.get('summary', 'Registered PyPI package'),
                'license': info.get('license', 'Unspecified') or 'Unspecified',
                'url': info.get('project_url', f"https://pypi.org/project/{clean_name}/")
            }
        elif response.status_code == 404:
            result = {
                'package': clean_name,
                'exists': False,
                'status': 'SLOPSQUATTED_HALLUCINATION',
                'risk': 'CRITICAL',
                'version': 'N/A',
                'summary': 'Package does NOT exist on PyPI registry! High risk of AI hallucination / dependency confusion.',
                'license': 'N/A',
                'url': None
            }
        else:
            result = {
                'package': clean_name,
                'exists': False,
                'status': f'PYPI_HTTP_{response.status_code}',
                'risk': 'MEDIUM',
                'version': 'N/A',
                'summary': f'PyPI returned HTTP status {response.status_code}',
                'license': 'N/A',
                'url': None
            }
    except requests.exceptions.Timeout:
        result = {
            'package': clean_name,
            'exists': False,
            'status': 'REGISTRY_TIMEOUT',
            'risk': 'MEDIUM',
            'version': 'N/A',
            'summary': 'Connection to PyPI registry timed out after 3.5s.',
            'license': 'N/A',
            'url': None
        }
    except Exception as e:
        result = {
            'package': clean_name,
            'exists': False,
            'status': 'NETWORK_ERROR',
            'risk': 'MEDIUM',
            'version': 'N/A',
            'summary': f'Unable to reach PyPI: {str(e)}',
            'license': 'N/A',
            'url': None
        }

    _PYPI_CACHE[normalized_key] = result
    return result

def audit_requirements_text(req_text):
    """
    Audits a multi-line requirements.txt text block against PyPI.
    Returns: list of package audit dictionaries.
    """
    if not req_text or not req_text.strip():
        return []

    lines = req_text.strip().splitlines()
    results = []
    seen = set()

    session = requests.Session()
    for line in lines:
        cleaned = clean_package_name(line)
        if not cleaned:
            continue
        norm = cleaned.lower().replace('_', '-')
        if norm in seen:
            continue
        seen.add(norm)

        res = check_pypi_package(line, session=session)
        if res:
            results.append(res)

    return results
