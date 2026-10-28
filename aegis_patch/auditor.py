import requests

def check_package(package_name):
    # Query PyPI live registry
    response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
    return response.status_code == 200

def audit_requirements(file_path):
    with open(file_path, 'r') as f:
        packages = [line.strip() for line in f if line.strip()]

    results = {}
    for pkg in packages:
        results[pkg] = check_package(pkg)
    return results
