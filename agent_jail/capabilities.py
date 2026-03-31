import os


def _normalize_path(path):
    return os.path.abspath(os.path.expanduser(path))


def resolve_session_capabilities(
    projects,
    allow_write,
    skills_proxy=True,
    ops_exec=False,
    delegates=None,
    browser_automation=False,
    direct_secret_env=False,
):
    writable = {_normalize_path(path) for path in allow_write}
    mounts = []
    for project in projects:
        path = _normalize_path(project)
        mounts.append({"path": path, "mode": "rw" if path in writable else "ro"})
    delegate_names = sorted(set(delegates or (["ops"] if ops_exec else [])))
    return {
        "mounts": mounts,
        "capabilities": {
            "skills_proxy": bool(skills_proxy),
            "ops_exec": bool(ops_exec or "ops" in delegate_names),
            "delegate": bool(delegate_names),
            "delegates": delegate_names,
            "browser_automation": bool(browser_automation),
            "direct_secret_env": bool(direct_secret_env),
        },
    }
