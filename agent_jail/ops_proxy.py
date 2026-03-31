def run_ops_proxy(capabilities, command):
    if not capabilities.get("ops_exec"):
        raise PermissionError("ops_exec capability denied")
    return {"status": "ok", "command": list(command)}
