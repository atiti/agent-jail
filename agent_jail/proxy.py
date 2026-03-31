import http.client
import http.server
import select
import socket
import socketserver
import threading
import urllib.parse


class ProxyPolicy:
    def __init__(self, rules, default_allow=True):
        self.rules = [rule for rule in rules if rule.get("kind") == "network"]
        self.default_allow = default_allow

    def decide(self, method, host, port, scheme="tcp"):
        for rule in self.rules:
            if rule.get("host") == host and rule.get("port") in (None, port):
                return {"decision": "allow" if rule.get("allow", False) else "deny", "reason": "matched-rule"}
        return {"decision": "allow" if self.default_allow else "deny", "reason": "default-policy", "scheme": scheme}


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _relay(left, right):
    sockets = [left, right]
    while True:
        ready, _, _ = select.select(sockets, [], [], 0.5)
        if not ready:
            continue
        for src in ready:
            data = src.recv(65536)
            if not data:
                return
            (right if src is left else left).sendall(data)


def make_proxy_server(host, port, policy):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _decision(self, method, host_name, port_num, scheme="tcp"):
            verdict = policy.decide(method, host_name, port_num, scheme=scheme)
            if verdict["decision"] == "deny":
                self.send_error(403, f"blocked by agent-jail policy: {host_name}:{port_num}")
                return None
            return verdict

        def do_CONNECT(self):
            host_name, _, port = self.path.partition(":")
            port_num = int(port or "443")
            if not self._decision("CONNECT", host_name, port_num):
                return
            upstream = socket.create_connection((host_name, port_num), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            try:
                _relay(self.connection, upstream)
            finally:
                upstream.close()

        def do_GET(self):
            self._forward()

        def do_POST(self):
            self._forward()

        def do_PUT(self):
            self._forward()

        def do_DELETE(self):
            self._forward()

        def _forward(self):
            parsed = urllib.parse.urlsplit(self.path)
            host_name = parsed.hostname or self.headers.get("Host", "")
            port_num = parsed.port or (443 if parsed.scheme == "https" else 80)
            scheme = parsed.scheme or "http"
            if not self._decision(self.command, host_name, port_num, scheme=scheme):
                return
            body = None
            if self.headers.get("Content-Length"):
                body = self.rfile.read(int(self.headers["Content-Length"]))
            conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(host_name, port_num, timeout=15)
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in {"proxy-connection", "connection", "host"}}
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status, resp.reason)
            for key, value in resp.getheaders():
                if key.lower() != "transfer-encoding":
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()

        def log_message(self, _fmt, *_args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def start_proxy(policy, host="127.0.0.1", port=0):
    server = make_proxy_server(host, port, policy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
