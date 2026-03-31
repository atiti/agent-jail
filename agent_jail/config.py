import json
import os
from pathlib import Path


def _normalize_path_list(values):
    if not isinstance(values, list):
        return []
    normalized = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            continue
        normalized.append(os.path.abspath(os.path.expanduser(item)))
    return normalized


def _normalize_pattern_list(values):
    if not isinstance(values, list):
        return []
    normalized = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            continue
        normalized.append(os.path.expanduser(item))
    return normalized


def default_config_path():
    home = os.environ.get("AGENT_JAIL_HOME") or str(Path.home() / ".agent-jail")
    return os.path.join(home, "config.json")


def load_config(path=None):
    config_path = path or default_config_path()
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    else:
        data = {}
    delegates = data.get("delegates")
    if not isinstance(delegates, list):
        delegates = []
    data["delegates"] = [item for item in delegates if isinstance(item, dict) and item.get("name")]
    filesystem = data.get("filesystem")
    if not isinstance(filesystem, dict):
        filesystem = {}
    data["filesystem"] = {
        "read_only_roots": _normalize_path_list(filesystem.get("read_only_roots")),
        "write_roots": _normalize_path_list(filesystem.get("write_roots")),
        "deny_read_patterns": _normalize_pattern_list(filesystem.get("deny_read_patterns")),
    }
    return data
