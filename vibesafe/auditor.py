"""
VibeSafe PyPI Dependency Auditor
Detects AI-Hallucinated Package Names (AI Slopsquatting) and Supply Chain Risks.
High-efficiency concurrent auditing with in-memory caching.
"""
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Process-wide in-memory cache to prevent duplicate network roundtrips
_PYPI_CACHE = {}

def clean_package_name(raw_line):
    """
    Extracts canonical package name from a requirements.txt entry line.
    Handles version specifiers (==, >=, <=, ~=, !=, <, >), extras ([socks]),
    environment markers (; sys_platform == 'linux'), and comments (# ...).
    """
    if not raw_line:
        return None
    # Strip comments
    line = raw_line.split('#')[0].strip()
    if not line:
        return None

    # Strip environment markers
    line = line.split(';')[0].strip()

    # Match package identifier
    match = re.match(r'^([a-zA-Z0-9_.\-]+)', line)
    if not match:
        return None

    name = match.group(1).strip()
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
    headers = {'User-Agent': 'VibeSafe-SupplyChain-Auditor/1.0'}

    try:
        if session:
            response = session.get(url, timeout=3.5, headers=headers)
        else:
            response = requests.get(url, timeout=3.5, headers=headers)

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

def audit_requirements_text(req_text, max_workers=5):
    """
    Audits requirements dependencies against PyPI concurrently.
    Preserves original manifest order in returned results.
    """
    if not req_text or not req_text.strip():
        return []

    lines = req_text.strip().splitlines()
    unique_packages = []
    seen = set()

    for line in lines:
        cleaned = clean_package_name(line)
        if not cleaned:
            continue
        norm = cleaned.lower().replace('_', '-')
        if norm not in seen:
            seen.add(norm)
            unique_packages.append(line)

    if not unique_packages:
        return []

    results_by_pkg = {}
    session = requests.Session()

    # Fast path: check how many are already in cache
    uncached = [p for p in unique_packages if clean_package_name(p).lower().replace('_', '-') not in _PYPI_CACHE]

    if uncached:
        # Run concurrent lookups for uncached items
        workers = min(len(uncached), max_workers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check_pypi_package, pkg, session): pkg for pkg in uncached}
            for future in as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        results_by_pkg[res['package'].lower().replace('_', '-')] = res
                except Exception:
                    pass

    # Build final results in exact input order
    results = []
    for pkg_line in unique_packages:
        cname = clean_package_name(pkg_line).lower().replace('_', '-')
        if cname in results_by_pkg:
            results.append(results_by_pkg[cname])
        elif cname in _PYPI_CACHE:
            results.append(_PYPI_CACHE[cname])
        else:
            # Fallback direct lookup
            res = check_pypi_package(pkg_line, session)
            if res:
                results.append(res)

    return results
