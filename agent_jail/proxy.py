import http.client
import http.server
import ipaddress
import select
import socket
import socketserver
import struct
import threading
import urllib.parse


class ProxyPolicy:
    def __init__(self, rules, default_allow=True):
        self.rules = [rule for rule in rules if rule.get("kind") == "network"]
        self.default_allow = default_allow

    def decide(self, method, host, port, scheme="tcp"):
        host = (host or "").lower()
        scheme = (scheme or "tcp").lower()
        for rule in self.rules:
            rule_host = (rule.get("host") or "").lower()
            rule_port = rule.get("port")
            rule_scheme = (rule.get("scheme") or "").lower()
            if rule_host != host:
                continue
            if rule_port not in (None, port):
                continue
            if rule_scheme and rule_scheme != scheme:
                continue
            return {"decision": "allow" if rule.get("allow", False) else "deny", "reason": "matched-rule"}
        return {"decision": "allow" if self.default_allow else "deny", "reason": "default-policy", "scheme": scheme}


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _relay(left, right):
    sockets = [left, right]
    while True:
        try:
            ready, _, _ = select.select(sockets, [], [], 0.5)
        except OSError:
            return
        if not ready:
            continue
        for src in ready:
            try:
                data = src.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                (right if src is left else left).sendall(data)
            except OSError:
                return


def _emit_proxy_event(event_sink, action, transport, method, host_name, port_num, scheme, reason):
    if not event_sink:
        return
    event_sink.emit(
        {
            "action": action,
            "category": "network",
            "raw": f"{transport} {method} {host_name}:{port_num} [{scheme}] ({reason})",
            "transport": transport,
            "method": method,
            "host": host_name,
            "port": port_num,
            "scheme": scheme,
            "reason": reason,
        }
    )


def _recv_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise ConnectionError("unexpected EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _pack_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)


def make_proxy_server(host, port, policy, event_sink=None):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _decision(self, method, host_name, port_num, scheme="tcp"):
            verdict = policy.decide(method, host_name, port_num, scheme=scheme)
            if verdict["decision"] == "deny":
                _emit_proxy_event(event_sink, "deny", "http", method, host_name, port_num, scheme, verdict["reason"])
                self.send_error(403, f"blocked by agent-jail policy: {host_name}:{port_num}")
                return None
            _emit_proxy_event(event_sink, "allow", "http", method, host_name, port_num, scheme, verdict["reason"])
            return verdict

        def do_CONNECT(self):
            host_name, _, port_text = self.path.partition(":")
            port_num = int(port_text or "443")
            if not self._decision("CONNECT", host_name, port_num):
                return
            try:
                upstream = socket.create_connection((host_name, port_num), timeout=10)
            except OSError:
                _emit_proxy_event(event_sink, "deny", "http", "CONNECT", host_name, port_num, "tcp", "connect-error")
                self.send_error(502, f"upstream connect failed: {host_name}:{port_num}")
                return
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
            try:
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
            except (OSError, http.client.HTTPException):
                _emit_proxy_event(event_sink, "deny", "http", self.command, host_name, port_num, scheme, "forward-error")
                self.send_error(502, f"upstream request failed: {host_name}:{port_num}")
            finally:
                conn.close()

        def log_message(self, _fmt, *_args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def make_socks_proxy_server(host, port, policy, event_sink=None):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            request = self.request
            try:
                version, methods_count = _recv_exact(request, 2)
                if version != 5:
                    return
                methods = _recv_exact(request, methods_count)
                if 0 not in methods:
                    request.sendall(b"\x05\xff")
                    return
                request.sendall(b"\x05\x00")
                header = _recv_exact(request, 4)
                version, command, _reserved, atyp = header
                if version != 5:
                    return
                if atyp == 1:
                    host_name = socket.inet_ntoa(_recv_exact(request, 4))
                elif atyp == 3:
                    size = _recv_exact(request, 1)[0]
                    host_name = _recv_exact(request, size).decode("idna")
                elif atyp == 4:
                    host_name = socket.inet_ntop(socket.AF_INET6, _recv_exact(request, 16))
                else:
                    request.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                port_num = struct.unpack("!H", _recv_exact(request, 2))[0]
                if command != 1:
                    request.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                verdict = policy.decide("CONNECT", host_name, port_num, scheme="tcp")
                if verdict["decision"] == "deny":
                    _emit_proxy_event(event_sink, "deny", "socks5", "CONNECT", host_name, port_num, "tcp", verdict["reason"])
                    request.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                _emit_proxy_event(event_sink, "allow", "socks5", "CONNECT", host_name, port_num, "tcp", verdict["reason"])
                upstream = socket.create_connection((host_name, port_num), timeout=10)
                try:
                    bound_host, bound_port = upstream.getsockname()[:2]
                    request.sendall(b"\x05\x00\x00" + _pack_address(bound_host, bound_port))
                    _relay(request, upstream)
                finally:
                    upstream.close()
            except (ConnectionError, OSError, ValueError):
                return

    return ThreadingTCPServer((host, port), Handler)


def _start_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def start_http_proxy(policy, host="127.0.0.1", port=0, event_sink=None):
    return _start_server(make_proxy_server(host, port, policy, event_sink=event_sink))


def start_socks_proxy(policy, host="127.0.0.1", port=0, event_sink=None):
    return _start_server(make_socks_proxy_server(host, port, policy, event_sink=event_sink))


def start_proxy(policy, host="127.0.0.1", port=0, event_sink=None):
    return start_http_proxy(policy, host=host, port=port, event_sink=event_sink)
