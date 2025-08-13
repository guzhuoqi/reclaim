#!/usr/bin/env python3
import http.server
import socketserver
import requests
import threading

TARGET = "http://127.0.0.1:8082"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.startswith('/flows/dump'):
                url = TARGET + '/flows/dump'
                print(f"[flows_proxy] 开始代理请求: {url}")
                with requests.get(url, stream=True, timeout=300) as r:
                    print(f"[flows_proxy] 响应状态: {r.status_code}, Content-Length: {r.headers.get('content-length', 'unknown')}")
                    self.send_response(r.status_code)
                    for k, v in r.headers.items():
                        if k.lower() in ['content-length', 'content-type', 'content-disposition', 'etag']:
                            self.send_header(k, v)
                    self.end_headers()

                    total_bytes = 0
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            try:
                                self.wfile.write(chunk)
                                self.wfile.flush()  # 确保数据被发送
                                total_bytes += len(chunk)
                            except BrokenPipeError:
                                print(f"[flows_proxy] 客户端断开连接，已传输: {total_bytes} bytes")
                                break
                            except Exception as e:
                                print(f"[flows_proxy] 写入错误: {e}, 已传输: {total_bytes} bytes")
                                break
                    print(f"[flows_proxy] 传输完成: {total_bytes} bytes")
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

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """多线程TCP服务器，避免并发请求冲突"""
    allow_reuse_address = True

if __name__ == '__main__':
    with ThreadedTCPServer(("0.0.0.0", 8083), Handler) as httpd:
        print("flows_proxy启动在端口8083，支持多线程处理")
        httpd.serve_forever()


