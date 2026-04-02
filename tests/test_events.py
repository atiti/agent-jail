import json
import os
import tempfile
import threading
import time
import unittest

from agent_jail.events import EventSink, render_event, stream_event_socket


class EventTests(unittest.TestCase):
    def test_event_sink_writes_log_and_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            socket_path = os.path.join(tmp, "events.sock")
            sink = EventSink(log_path, socket_path=socket_path)
            sink.start()
            try:
                sink.emit({"action": "allow", "category": "read-only", "raw": "git status"})
                with open(log_path, encoding="utf-8") as handle:
                    existing = [json.loads(line) for line in handle]
                self.assertEqual(existing[0]["action"], "allow")
                self.assertEqual(existing[0]["raw"], "git status")

                stream = stream_event_socket(socket_path)

                def delayed_emit():
                    time.sleep(0.05)
                    sink.emit({"action": "deny", "category": "policy", "raw": "opsctl status"})

                thread = threading.Thread(target=delayed_emit, daemon=True)
                thread.start()
                streamed = next(stream)
                self.assertEqual(streamed["action"], "deny")
                self.assertEqual(streamed["category"], "policy")
            finally:
                sink.close()

    def test_render_event_formats_human_output(self):
        self.assertEqual(
            render_event({"action": "allow", "category": "read-only", "raw": "git status"}),
            "[ALLOW][read-only] git status",
        )

    def test_render_event_includes_session_when_present(self):
        self.assertEqual(
            render_event({"action": "allow", "category": "read-only", "raw": "git status", "session": "session-123"}),
            "[ALLOW][read-only][session-123] git status",
        )

    def test_render_event_can_use_color(self):
        rendered = render_event({"action": "allow", "category": "read-only", "raw": "git status"}, color=True)
        self.assertIn("\033[32m[ALLOW]\033[0m", rendered)
        self.assertIn("\033[36m[read-only]\033[0m", rendered)

    def test_render_event_colors_network_category(self):
        rendered = render_event({"action": "deny", "category": "network", "raw": "http CONNECT example.com:443"}, color=True)
        self.assertIn("\033[31m[DENY]\033[0m", rendered)
        self.assertIn("[network]", rendered)

    def test_render_event_colors_jit_info(self):
        rendered = render_event({"action": "info", "category": "jit", "raw": "tree -L 2"}, color=True)
        self.assertIn("\033[34m[INFO]\033[0m", rendered)
        self.assertIn("\033[33m[jit]\033[0m", rendered)

    def test_render_event_includes_capability_phase_and_reason(self):
        rendered = render_event(
            {
                "action": "deny",
                "category": "capability",
                "raw": "bash ./scripts/service-health.sh summary --format text",
                "phase": "exit",
                "reason": "returncode=1",
            }
        )
        self.assertEqual(
            rendered,
            "[DENY][capability][exit] bash ./scripts/service-health.sh summary --format text (returncode=1)",
        )

    def test_render_event_truncates_long_raw_for_human_output(self):
        rendered = render_event({"action": "allow", "category": "general", "raw": "x" * 400})
        self.assertTrue(rendered.endswith("..."))
        self.assertLess(len(rendered), 320)
