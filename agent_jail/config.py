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


def _normalize_string_map(values):
    if not isinstance(values, dict):
        return {}
    normalized = {}
    for key, value in values.items():
        name = str(key).strip()
        if not name:
            continue
        normalized[name] = str(value)
    return normalized


def _normalize_home_mount_list(values):
    if not isinstance(values, list):
        return [".overwatchr"]
    normalized = []
    seen = set()
    for item in values:
        if not isinstance(item, str):
            continue
        value = item.strip()
        if not value:
            continue
        if value.startswith("~/"):
            value = value[2:]
        value = value.lstrip("/")
        value = value.rstrip("/")
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    if ".overwatchr" not in seen:
        normalized.append(".overwatchr")
    return normalized


def _normalize_host_list(values):
    if not isinstance(values, list):
        return []
    normalized = []
    seen = set()
    for item in values:
        if not isinstance(item, str):
            continue
        value = item.strip().lower()
        if not value:
            continue
        if "@" in value:
            value = value.rsplit("@", 1)[-1]
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        if value not in seen:
            seen.add(value)
            normalized.append(value)
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
    allow_delegates = values.get("allow_delegates")
    if not isinstance(allow_delegates, list):
        allow_delegates = []
    return {
        "read_only_roots": _normalize_path_list(values.get("read_only_roots")),
        "write_roots": _normalize_path_list(values.get("write_roots")),
        "home_mounts": _normalize_home_mount_list(values.get("home_mounts")),
        "git_ssh_hosts": _normalize_host_list(values.get("git_ssh_hosts")),
        "proxy": bool(values.get("proxy", True)),
        "allow_ops": bool(values.get("allow_ops", False)),
        "allow_delegates": [str(item) for item in allow_delegates if isinstance(item, str) and item.strip()],
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
    normalized_delegates = []
    for item in delegates:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        delegate = dict(item)
        set_env = delegate.get("set_env")
        if not isinstance(set_env, dict):
            set_env = {}
        delegate["set_env"] = _normalize_string_map(set_env)
        allowed_secrets = delegate.get("allowed_secrets")
        if not isinstance(allowed_secrets, list):
            allowed_secrets = []
        delegate["allowed_secrets"] = [str(item) for item in allowed_secrets if isinstance(item, str) and item.strip()]
        delegate["auto_inventory_from_cwd"] = bool(delegate.get("auto_inventory_from_cwd", False))
        normalized_delegates.append(delegate)
    data["delegates"] = normalized_delegates
    secrets = data.get("secrets")
    if not isinstance(secrets, dict):
        secrets = {}
    normalized_secrets = {}
    for name, item in secrets.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(item, dict):
            continue
        normalized_secrets[name] = {"env": _normalize_string_map(item.get("env"))}
    data["secrets"] = normalized_secrets
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
