import json
import os
import socket
import threading
from datetime import UTC, datetime
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer


class _StreamHandler(StreamRequestHandler):
    def handle(self):
        sink = self.server.event_sink
        sink._add_subscriber(self.connection)
        try:
            while self.connection.recv(1):
                pass
        except OSError:
            pass
        finally:
            sink._remove_subscriber(self.connection)


class EventSink:
    def __init__(self, log_path, socket_path=None):
        self.log_path = log_path
        self.socket_path = socket_path
        self._lock = threading.Lock()
        self._subscribers = set()
        self._server = None
        self._thread = None

    def start(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if self.socket_path:
            os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)

            class Server(ThreadingUnixStreamServer):
                daemon_threads = True
                allow_reuse_address = True

            self._server = Server(self.socket_path, _StreamHandler)
            self._server.event_sink = self
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()

    def close(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self.socket_path and os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        with self._lock:
            subscribers = list(self._subscribers)
            self._subscribers.clear()
        for subscriber in subscribers:
            try:
                subscriber.close()
            except OSError:
                pass

    def emit(self, event):
        payload = dict(event)
        payload.setdefault("timestamp", datetime.now(UTC).isoformat())
        line = json.dumps(payload, sort_keys=True)
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        data = (line + "\n").encode("utf-8")
        with self._lock:
            subscribers = list(self._subscribers)
        stale = []
        for subscriber in subscribers:
            try:
                subscriber.sendall(data)
            except OSError:
                stale.append(subscriber)
        for subscriber in stale:
            self._remove_subscriber(subscriber)

    def _add_subscriber(self, connection):
        with self._lock:
            self._subscribers.add(connection)

    def _remove_subscriber(self, connection):
        with self._lock:
            self._subscribers.discard(connection)
        try:
            connection.close()
        except OSError:
            pass


def render_event(event, color=False):
    action = event.get("action", "EVENT").upper()
    category = event.get("category")
    raw = event.get("raw") or event.get("message") or ""
    timestamp = event.get("timestamp", "")
    prefix = ""
    if timestamp:
        short = timestamp.replace("T", " ").replace("+00:00", "Z")
        prefix = f"{short} "
    if category:
        if color:
            action_text = f"{ACTION_COLORS.get(action, '')}[{action}]{ANSI_RESET}"
            category_text = f"{CATEGORY_COLORS.get(category, '')}[{category}]{ANSI_RESET}"
            prefix_text = f"{ANSI_DIM}{prefix}{ANSI_RESET}" if prefix else ""
            return f"{prefix_text}{action_text}{category_text} {raw}"
        return f"{prefix}[{action}][{category}] {raw}"
    if color:
        action_text = f"{ACTION_COLORS.get(action, '')}[{action}]{ANSI_RESET}"
        prefix_text = f"{ANSI_DIM}{prefix}{ANSI_RESET}" if prefix else ""
        return f"{prefix_text}{action_text} {raw}"
    return f"{prefix}[{action}] {raw}"


def load_runtime_state(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_runtime_state(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def stream_event_socket(socket_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(socket_path)
        buffer = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if not line:
                    continue
                yield json.loads(line.decode("utf-8"))
ANSI_RESET = "\033[0m"
ANSI_DIM = "\033[2m"
ACTION_COLORS = {
    "ALLOW": "\033[32m",
    "DENY": "\033[31m",
    "ASK": "\033[33m",
}
CATEGORY_COLORS = {
    "read-only": "\033[36m",
    "policy": "\033[35m",
    "capability": "\033[34m",
    "sensitive-delegate": "\033[31m",
    "read-scope": "\033[31m",
    "agent-launch": "\033[32m",
    "capability-bridge": "\033[34m",
}
