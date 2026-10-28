import http.server
import socketserver
import os

PORT = 8080
DIRECTORY = "/Users/alipitthoo/Documents/KTT"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving AegisPatch Web Studio at http://localhost:{PORT}")
    httpd.serve_forever()
