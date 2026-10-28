import requests

def check_pypi_package(package_name):
    """
    Queries live PyPI JSON API to check if a package actually exists.
    Catches AI-hallucinated package names (Slopsquatting).
    """
    clean_name = package_name.split('==')[0].split('>=')[0].split('<=')[0].strip()
    if not clean_name or clean_name.startswith('#'):
        return None

    url = f"https://pypi.org/pypi/{clean_name}/json"
    try:
        response = requests.get(url, timeout=3)
        exists = response.status_code == 200
        return {
            'package': clean_name,
            'exists': exists,
            'status': 'VALID' if exists else 'SLOPSQUATTED_HALLUCINATION',
            'risk': 'LOW' if exists else 'CRITICAL'
        }
    except Exception as e:
        return {
            'package': clean_name,
            'exists': False,
            'status': 'UNKNOWN_NETWORK_ERROR',
            'risk': 'MEDIUM'
        }

def audit_requirements_text(req_text):
    lines = req_text.strip().split('\n')
    results = []
    for line in lines:
        res = check_pypi_package(line)
        if res:
            results.append(res)
    return results
