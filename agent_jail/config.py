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


def _normalize_run_defaults(values):
    if not isinstance(values, dict):
        values = {}
    project_mode = values.get("project_mode", "")
    if project_mode not in {"", "cwd"}:
        project_mode = ""
    return {
        "read_only_roots": _normalize_path_list(values.get("read_only_roots")),
        "write_roots": _normalize_path_list(values.get("write_roots")),
        "allow_ops": bool(values.get("allow_ops", False)),
        "project_mode": project_mode,
    }


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
    defaults = data.get("defaults")
    if not isinstance(defaults, dict):
        defaults = {}
    data["defaults"] = {
        "run": _normalize_run_defaults(defaults.get("run")),
    }
    llm_policy = data.get("llm_policy")
    if not isinstance(llm_policy, dict):
        llm_policy = {}
    data["llm_policy"] = {
        "provider": llm_policy.get("provider", ""),
        "model": llm_policy.get("model", ""),
        "endpoint_env": llm_policy.get("endpoint_env", "AZURE_OPENAI_ENDPOINT"),
        "api_key_env": llm_policy.get("api_key_env", "AZURE_OPENAI_API_KEY"),
        "deployment_env": llm_policy.get("deployment_env", "AZURE_OPENAI_DEPLOYMENT"),
        "api_version": llm_policy.get("api_version", "2024-10-21"),
        "auto_promote_min_count": int(llm_policy.get("auto_promote_min_count", 3)),
        "confidence_threshold": float(llm_policy.get("confidence_threshold", 0.8)),
        "jit_enabled": bool(llm_policy.get("jit_enabled", False)),
        "jit_timeout_ms": int(llm_policy.get("jit_timeout_ms", 800)),
        "jit_auto_apply_low_risk": bool(llm_policy.get("jit_auto_apply_low_risk", True)),
        "jit_force_low_risk": bool(llm_policy.get("jit_force_low_risk", False)),
        "stub_mode": llm_policy.get("stub_mode", ""),
        "stub_confidence": float(llm_policy.get("stub_confidence", 0.95)),
        "stub_reason": llm_policy.get("stub_reason", ""),
    }
    return data


def save_config(data, path=None):
    config_path = path or default_config_path()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
