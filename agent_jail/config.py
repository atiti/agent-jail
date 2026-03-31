import json
import os
from pathlib import Path


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
    return data
