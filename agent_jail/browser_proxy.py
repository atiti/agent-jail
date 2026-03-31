def run_browser_proxy(capabilities, request):
    if not capabilities.get("browser_automation"):
        raise PermissionError("browser_automation capability denied")
    return {"status": "ok", "tool": request.get("tool"), "action": request.get("action")}
