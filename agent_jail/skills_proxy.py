def run_skill_proxy(capabilities, request):
    if not capabilities.get("skills_proxy"):
        raise PermissionError("skills_proxy capability denied")
    return {"status": "ok", "name": request.get("name"), "operation": request.get("operation")}
