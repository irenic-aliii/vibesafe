"""
VibeSafe Security Server & API Gateway
"""
import os
import uuid
import sqlite3
import json
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from flask_cors import CORS

from vibesafe.scanner import scan_code
from vibesafe.auditor import audit_requirements_text
from vibesafe.patcher import generate_patch, apply_patch, remediate_code

app = Flask(__name__, static_folder='.')
CORS(app)

# Limit request payload size to 4MB
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

DB_PATH = os.path.join(os.path.dirname(__file__), 'vibesafe.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_history (
            id TEXT PRIMARY KEY,
            filename TEXT,
            filesize_bytes INTEGER,
            scan_type TEXT,
            findings_count INTEGER,
            status TEXT,
            summary TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_scan_event(filename, filesize, scan_type, findings_count, status, summary):
    """
    Saves scan metadata into SQLite audit history.
    Never stores confidential source code or plaintext secrets.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        record_id = uuid.uuid4().hex
        cursor.execute(
            '''INSERT INTO audit_history 
               (id, filename, filesize_bytes, scan_type, findings_count, status, summary) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (record_id, filename, filesize, scan_type, findings_count, status, summary)
        )
        conn.commit()
        conn.close()
        return record_id
    except Exception as e:
        print(f"Failed to record audit log: {e}")
        return uuid.uuid4().hex

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'engine': 'VibeSafe AST Compiler v3.9+',
        'pypi_auditor': 'online',
        'database': 'sqlite_connected'
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Secure in-memory file upload handler.
    Validates file format, extracts text, scans without persisting source code to disk.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file was provided in the upload request.'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'No file was selected.'}), 400

    filename = secure_filename(file.filename)
    lower_name = filename.lower()

    # Allowed extensions: python code, requirement manifests, text files
    allowed_exts = ('.py', '.pyw', '.txt', '.json', '.md')
    if not any(lower_name.endswith(ext) for ext in allowed_exts):
        return jsonify({
            'error': f'Unsupported file type: {filename}. Supported formats are .py, .pyw, and .txt manifests.'
        }), 400

    try:
        # Read file directly into memory with safe UTF-8 decoding
        raw_bytes = file.read()
        file_size = len(raw_bytes)

        if file_size == 0:
            return jsonify({'error': 'The uploaded file is empty.'}), 400

        content = raw_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return jsonify({'error': f'Failed to read uploaded file: {str(e)}'}), 500

    # Determine file processing workflow
    is_requirements = ('requirements' in lower_name) or lower_name.endswith('.txt')
    is_python = lower_name.endswith(('.py', '.pyw')) or ('def ' in content or 'import ' in content)

    if is_requirements and not is_python:
        file_type = 'requirements'
        audit_results = audit_requirements_text(content)
        slop_count = sum(1 for r in audit_results if r['risk'] == 'CRITICAL')
        status = 'FLAGGED' if slop_count > 0 else 'VERIFIED'
        summary = f"Audited {len(audit_results)} dependencies; {slop_count} unverified/slopsquatted."

        record_id = log_scan_event(filename, file_size, 'requirements_audit', slop_count, status, summary)

        return jsonify({
            'id': record_id,
            'filename': filename,
            'file_type': file_type,
            'code': content,
            'audit_results': audit_results,
            'vulns': [],
            'error': None,
            'summary': summary
        })
    else:
        file_type = 'python'
        vulns, err = scan_code(content)
        status = 'SYNTAX_ERROR' if err else ('VULNERABLE' if vulns else 'CLEAN')
        summary = f"{len(vulns)} AST security findings" if vulns else ("Syntax error" if err else "Clean - 0 AST findings")

        record_id = log_scan_event(filename, file_size, 'python_ast', len(vulns) if vulns else 0, status, summary)

        return jsonify({
            'id': record_id,
            'filename': filename,
            'file_type': file_type,
            'code': content,
            'vulns': vulns,
            'error': err,
            'summary': summary
        })

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json or {}
    code = data.get('code', '')
    if not code.strip():
        return jsonify({'vulns': [], 'error': None, 'metrics': {'total_lines': 0, 'findings': 0}})

    vulns, err = scan_code(code)
    lines_count = len(code.splitlines())

    return jsonify({
        'vulns': vulns,
        'error': err,
        'metrics': {
            'total_lines': lines_count,
            'findings': len(vulns) if vulns else 0,
            'critical_count': sum(1 for v in vulns if v.get('severity') == 'CRITICAL'),
            'high_count': sum(1 for v in vulns if v.get('severity') == 'HIGH')
        }
    })

@app.route('/api/patch', methods=['POST'])
def patch():
    """
    Legacy single-patch endpoint for backwards compatibility.
    """
    data = request.json or {}
    code = data.get('code', '')
    vuln = data.get('vuln', {})
    patch_data = generate_patch(vuln, code_snippet=vuln.get('snippet', ''))
    patched = apply_patch(code, vuln, patch_data['patch'])
    return jsonify({'patched': patched})

@app.route('/api/remediate', methods=['POST'])
def remediate():
    """
    End-to-end autonomous remediation & closed-loop verification endpoint.
    Scans, generates indentation-preserving patches in reverse order, rescan-verifies,
    and produces a clean diff.
    """
    data = request.json or {}
    code = data.get('code', '')
    result = remediate_code(code)

    # Log remediation event if initial vulnerabilities were found
    if result['initial_vulns']:
        status = 'REMEDIATED' if result['is_verified'] else 'PARTIAL_REMEDIATION'
        summary = (
            f"Remediated {len(result['initial_vulns'])} findings; "
            f"{len(result['final_vulns'])} remaining."
        )
        log_scan_event(
            data.get('filename', 'interactive_editor.py'),
            len(code.encode('utf-8')),
            'python_remediation',
            len(result['final_vulns']),
            status,
            summary
        )

    return jsonify(result)

@app.route('/api/audit', methods=['POST'])
def audit():
    data = request.json or {}
    reqs = data.get('requirements', '')
    results = audit_requirements_text(reqs)

    slop_count = sum(1 for r in results if r['risk'] == 'CRITICAL')
    valid_count = sum(1 for r in results if r['exists'])

    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'valid': valid_count,
            'flagged_slopsquatted': slop_count
        }
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT id, filename, filesize_bytes, scan_type, findings_count, status, summary, timestamp 
               FROM audit_history 
               ORDER BY timestamp DESC 
               LIMIT 25'''
        )
        rows = cursor.fetchall()
        logs = [dict(r) for r in rows]
        conn.close()
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'logs': [], 'error': str(e)})

@app.route('/api/logs', methods=['DELETE'])
def clear_logs():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM audit_history')
        conn.commit()
        conn.close()
        return jsonify({'message': 'Audit logs successfully cleared.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Serving VibeSafe Security Compiler at http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
