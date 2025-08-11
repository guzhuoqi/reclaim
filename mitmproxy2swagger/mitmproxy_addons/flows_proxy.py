#!/usr/bin/env python3
import http.server
import socketserver
import requests

TARGET = "http://127.0.0.1:8082"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.startswith('/flows/dump'):
                url = TARGET + '/flows/dump'
                with requests.get(url, stream=True, timeout=10) as r:
                    self.send_response(r.status_code)
                    for k, v in r.headers.items():
                        if k.lower() in ['content-length', 'content-type', 'content-disposition', 'etag']:
                            self.send_header(k, v)
                    self.end_headers()
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            self.wfile.write(chunk)
                return
            # health root
            if self.path == '/' or self.path == '/health':
                out = b'{"status":"ok","proxy":"flows_proxy","target":"/flows/dump"}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            self.send_response(404)
            self.end_headers()
        except Exception as e:
            try:
                msg = str(e).encode()
                self.send_response(502)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            except Exception:
                pass

if __name__ == '__main__':
    with socketserver.TCPServer(("0.0.0.0", 8083), Handler) as httpd:
        httpd.serve_forever()


