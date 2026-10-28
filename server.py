import os
from flask import Flask, request, jsonify, send_from_directory
from vibesafe.scanner import scan_code
from vibesafe.auditor import audit_requirements_text
from vibesafe.patcher import generate_patch, apply_patch
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    code = data.get('code', '')
    vulns, err = scan_code(code)
    return jsonify({'vulns': vulns, 'error': err})

@app.route('/api/audit', methods=['POST'])
def audit():
    data = request.json
    reqs = data.get('requirements', '')
    results = audit_requirements_text(reqs)
    return jsonify({'results': results})

@app.route('/api/patch', methods=['POST'])
def patch():
    data = request.json
    code = data.get('code', '')
    vuln = data.get('vuln', {})
    patch_data = generate_patch(vuln)
    patched = apply_patch(code, vuln, patch_data['patch'])
    return jsonify({'patched': patched})

if __name__ == '__main__':
    print("Serving VibeSafe Web Studio at http://localhost:8080")
    app.run(port=8080)
