import json
import os
import socket
import tempfile
import threading
import unittest

from agent_jail.events import EventSink
from agent_jail.proxy import ProxyPolicy, start_http_proxy, start_socks_proxy


class ProxyTests(unittest.TestCase):
    def test_proxy_denies_unknown_host_when_default_is_deny(self):
        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "api.openai.com", "allow": True},
            ],
            default_allow=False,
        )
        verdict = policy.decide("CONNECT", "example.com", 443)
        self.assertEqual(verdict["decision"], "deny")

    def test_proxy_allows_matching_host(self):
        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "api.openai.com", "allow": True},
            ],
            default_allow=False,
        )
        verdict = policy.decide("CONNECT", "api.openai.com", 443)
        self.assertEqual(verdict["decision"], "allow")

    def test_proxy_matches_port_and_scheme(self):
        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "db.internal", "port": 5432, "scheme": "tcp", "allow": True},
            ],
            default_allow=False,
        )
        self.assertEqual(policy.decide("CONNECT", "db.internal", 5432, scheme="tcp")["decision"], "allow")
        self.assertEqual(policy.decide("CONNECT", "db.internal", 5432, scheme="udp")["decision"], "deny")
        self.assertEqual(policy.decide("CONNECT", "db.internal", 3306, scheme="tcp")["decision"], "deny")

    def test_socks5_connect_relays_matching_host(self):
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream_port = upstream.getsockname()[1]
        received = []

        def serve_once():
            conn, _ = upstream.accept()
            with conn:
                data = conn.recv(4096)
                received.append(data)
                conn.sendall(b"pong")

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()

        policy = ProxyPolicy(
            [
                {"kind": "network", "host": "127.0.0.1", "port": upstream_port, "scheme": "tcp", "allow": True},
            ],
            default_allow=False,
        )
        server, _ = start_socks_proxy(policy)
        proxy_port = server.server_address[1]
        try:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(client.recv(2), b"\x05\x00")
                request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + upstream_port.to_bytes(2, "big")
                client.sendall(request)
                response = client.recv(10)
                self.assertEqual(response[:2], b"\x05\x00")
                client.sendall(b"ping")
                self.assertEqual(client.recv(4), b"pong")
        finally:
            server.shutdown()
            server.server_close()
            upstream.close()
        thread.join(timeout=2)
        self.assertEqual(received, [b"ping"])

    def test_socks5_proxy_emits_allow_event(self):
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream_port = upstream.getsockname()[1]

        def serve_once():
            conn, _ = upstream.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(b"pong")

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()

        with tempfile.TemporaryDirectory() as tmp:
            sink = EventSink(os.path.join(tmp, "events.jsonl"))
            sink.start()
            policy = ProxyPolicy(
                [
                    {"kind": "network", "host": "127.0.0.1", "port": upstream_port, "scheme": "tcp", "allow": True},
                ],
                default_allow=False,
            )
            server, _ = start_socks_proxy(policy, event_sink=sink)
            proxy_port = server.server_address[1]
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
                    client.sendall(b"\x05\x01\x00")
                    self.assertEqual(client.recv(2), b"\x05\x00")
                    request = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + upstream_port.to_bytes(2, "big")
                    client.sendall(request)
                    self.assertEqual(client.recv(10)[:2], b"\x05\x00")
                    client.sendall(b"ping")
                    self.assertEqual(client.recv(4), b"pong")
            finally:
                server.shutdown()
                server.server_close()
                sink.close()
                upstream.close()
            with open(os.path.join(tmp, "events.jsonl"), encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle]
        thread.join(timeout=2)
        self.assertTrue(any(event["action"] == "allow" and event["category"] == "network" for event in events))
        self.assertTrue(any("127.0.0.1" in event["raw"] for event in events))

    def test_http_proxy_emits_deny_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            sink = EventSink(os.path.join(tmp, "events.jsonl"))
            sink.start()
            policy = ProxyPolicy([], default_allow=False)
            server, _ = start_http_proxy(policy, event_sink=sink)
            proxy_port = server.server_port
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
                    client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                    response = client.recv(4096)
                    self.assertIn(b"403", response)
            finally:
                server.shutdown()
                server.server_close()
                sink.close()
            with open(os.path.join(tmp, "events.jsonl"), encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle]
        self.assertTrue(any(event["action"] == "deny" and event["category"] == "network" for event in events))
        self.assertTrue(any("example.com:443" in event["raw"] for event in events))
