import ast
import os
import re
from pathlib import Path

from agent_jail.shell_analysis import ShellAnalysisError, analyze_shell_script


READ_ONLY_LEAF_TOOLS = {
    "cat",
    "find",
    "git",
    "grep",
    "head",
    "ls",
    "printenv",
    "pwd",
    "rg",
    "sed",
    "sort",
    "tree",
}
MUTATING_LEAF_TOOLS = {"cp", "mkdir", "mv", "tee", "touch"}
DESTRUCTIVE_LEAF_TOOLS = {"chmod", "chown", "rm"}
LAUNCHER_TOOLS = {"agent-jail", "agent-jail-cap", "sandbox-exec"}
PYTHON_NETWORK_MODULES = {"httpx", "requests", "socket", "urllib", "urllib3"}
SCRIPT_EXTENSIONS = {
    "python": {".py"},
    "shell": {".sh"},
    "ruby": {".rb"},
    "perl": {".pl", ".pm"},
}
SECRET_ENV_REF_PATTERNS = {
    "python": [
        re.compile(r'os\.environ\[\s*["\']([A-Z][A-Z0-9_]*)["\']\s*\]'),
        re.compile(r'os\.getenv\(\s*["\']([A-Z][A-Z0-9_]*)["\']'),
        re.compile(r'os\.environ\.get\(\s*["\']([A-Z][A-Z0-9_]*)["\']'),
    ],
    "shell": [
        re.compile(r"\$\{?([A-Z][A-Z0-9_]*)\}?"),
    ],
    "ruby": [
        re.compile(r'ENV\[\s*["\']([A-Z][A-Z0-9_]*)["\']\s*\]'),
        re.compile(r'ENV\.fetch\(\s*["\']([A-Z][A-Z0-9_]*)["\']'),
    ],
    "perl": [
        re.compile(r'\$ENV\{\s*["\']?([A-Z][A-Z0-9_]*)["\']?\s*\}'),
    ],
}


def _resolve_script_path(path, cwd):
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path(cwd or os.getcwd()) / candidate
    try:
        if candidate.exists() and candidate.is_file():
            return candidate
    except OSError:
        return None
    return None


def _literal_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_subprocess_args(node):
    if isinstance(node, ast.List):
        parts = []
        for element in node.elts:
            value = _literal_str(element)
            if value is None:
                return None
            parts.append(value)
        return parts
    value = _literal_str(node)
    if value is not None:
        return [value]
    return None


class _PythonAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.imports = set()
        self.literal_subprocesses = []
        self.dynamic_subprocess = False
        self.shell_subprocess = False
        self.file_write = False
        self.delete = False
        self.network = False
        self.dynamic_code = False
        self.read_paths = []
        self.string_bindings = {}
        self.path_bindings = {}

    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            literal = _resolve_python_string(node.value, self)
            if literal is not None:
                self.string_bindings[target] = literal
            path_literal = _resolve_python_path(node.value, self)
            if path_literal is not None:
                self.path_bindings[target] = path_literal
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in {"eval", "exec", "compile"}:
            self.dynamic_code = True
        if name in {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"}:
            self._handle_subprocess(node)
        if name in {"os.system", "os.popen"}:
            self.shell_subprocess = True
            if node.args:
                args = _literal_subprocess_args(node.args[0])
                if args:
                    self.literal_subprocesses.append(args)
                else:
                    self.dynamic_subprocess = True
        if name == "open" or method in {"write_text", "write_bytes"}:
            if _is_write_call(name, node) or method in {"write_text", "write_bytes"}:
                self.file_write = True
            elif name == "open" and node.args:
                path = _resolve_python_string(node.args[0], self)
                if path:
                    self.read_paths.append(path)
        if method in {"read_text", "read_bytes"}:
            path = _resolve_python_path(node.func.value, self)
            if path:
                self.read_paths.append(path)
        if name in {
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "pathlib.Path.unlink",
            "pathlib.Path.rmdir",
            "Path.unlink",
            "Path.rmdir",
            "shutil.rmtree",
        }:
            self.delete = True
        if name in {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.patch",
            "requests.delete",
            "urllib.request.urlopen",
            "httpx.get",
            "httpx.post",
            "socket.socket",
        }:
            self.network = True
        self.generic_visit(node)

    def _handle_subprocess(self, node):
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and bool(keyword.value.value):
                self.shell_subprocess = True
        if not node.args:
            self.dynamic_subprocess = True
            return
        args = _literal_subprocess_args(node.args[0])
        if args:
            self.literal_subprocesses.append(args)
        else:
            self.dynamic_subprocess = True


def _call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _is_write_call(name, node):
    if name != "open":
        return True
    if len(node.args) >= 2:
        mode = _literal_str(node.args[1]) or ""
        return any(flag in mode for flag in "wax+")
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = _literal_str(keyword.value) or ""
            return any(flag in mode for flag in "wax+")
    return False


def _resolve_python_string(node, analyzer):
    value = _literal_str(node)
    if value is not None:
        return value
    if isinstance(node, ast.Name):
        return analyzer.string_bindings.get(node.id)
    return None


def _resolve_python_path(node, analyzer):
    literal = _resolve_python_string(node, analyzer)
    if literal is not None:
        return literal
    if isinstance(node, ast.Name):
        return analyzer.path_bindings.get(node.id) or analyzer.string_bindings.get(node.id)
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        if name in {"Path", "pathlib.Path"} and node.args:
            return _resolve_python_string(node.args[0], analyzer)
    return None


def _leaf_tool_category(tool):
    if tool in READ_ONLY_LEAF_TOOLS:
        return "read-only"
    if tool in DESTRUCTIVE_LEAF_TOOLS:
        return "destructive"
    if tool in MUTATING_LEAF_TOOLS:
        return "mutating"
    if tool in {"curl", "wget", "ssh", "sudo", "doas"}:
        return "sensitive"
    return "unknown"


def _summarize_leaf_commands(commands):
    categories = []
    for command in commands:
        if not command:
            continue
        categories.append(_leaf_tool_category(os.path.basename(command[0])))
    if not categories:
        return {"risk": "low", "category": "general", "template": "shell local script", "reason": "shell script"}
    if any(item == "sensitive" for item in categories):
        return {"risk": "high", "category": "general", "template": "shell sensitive script", "reason": "shell script uses sensitive tools"}
    if any(item == "destructive" for item in categories):
        return {"risk": "high", "category": "general", "template": "shell destructive script", "reason": "shell script uses destructive tools"}
    if any(item == "mutating" for item in categories):
        return {"risk": "medium", "category": "general", "template": "shell mutating script", "reason": "shell mutating script"}
    if all(item == "read-only" for item in categories):
        return {"risk": "low", "category": "general", "template": "shell read-only script", "reason": "shell read-only script"}
    return {"risk": "low", "category": "general", "template": "shell local script", "reason": "shell script"}


def _analyze_python_source(source):
    tree = ast.parse(source)
    visitor = _PythonAnalyzer()
    visitor.visit(tree)
    if visitor.dynamic_code:
        return {"risk": "medium", "category": "general", "template": "python dynamic script", "reason": "python dynamic script"}
    if visitor.network or visitor.imports.intersection(PYTHON_NETWORK_MODULES):
        return {"risk": "high", "category": "general", "template": "python network script", "reason": "python network script"}
    if visitor.file_write or visitor.delete:
        return {"risk": "medium", "category": "general", "template": "python mutating script", "reason": "python mutating script"}
    if visitor.shell_subprocess or visitor.dynamic_subprocess:
        return {"risk": "medium", "category": "general", "template": "python subprocess script", "reason": "python subprocess script"}
    if visitor.literal_subprocesses:
        categories = [_leaf_tool_category(os.path.basename(args[0])) for args in visitor.literal_subprocesses if args]
        if categories and all(item == "read-only" for item in categories):
            return {
                "risk": "low",
                "category": "general",
                "template": "python read-only subprocess script",
                "reason": "python read-only subprocess script",
                "commands": visitor.literal_subprocesses,
                "read_paths": visitor.read_paths,
            }
        if any(item == "destructive" for item in categories):
            return {
                "risk": "high",
                "category": "general",
                "template": "python destructive subprocess script",
                "reason": "python destructive subprocess script",
                "commands": visitor.literal_subprocesses,
                "read_paths": visitor.read_paths,
            }
        return {
            "risk": "medium",
            "category": "general",
            "template": "python subprocess script",
            "reason": "python subprocess script",
            "commands": visitor.literal_subprocesses,
            "read_paths": visitor.read_paths,
        }
    return {
        "risk": "low",
        "category": "general",
        "template": "python local inspection script",
        "reason": "python local inspection script",
        "read_paths": visitor.read_paths,
    }


def _heuristic_script_summary(source, language):
    lower = source.lower()
    read_paths = []
    if language == "ruby":
        read_paths.extend(re.findall(r'File\.(?:read|open)\(\s*["\']([^"\']+)["\']', source))
    if language == "perl":
        read_paths.extend(re.findall(r'open\s*\([^,]+,\s*["\']<["\']\s*,\s*["\']([^"\']+)["\']', source))
        read_paths.extend(re.findall(r'open\s+[^,]+,\s*["\']<["\']\s*,\s*["\']([^"\']+)["\']', source))
    if any(token in lower for token in ("curl ", "wget ", " ssh ", "sudo ", " doas ")):
        return {"risk": "high", "category": "general", "template": f"{language} sensitive script", "reason": f"{language} sensitive script"}
    if any(token in lower for token in ("rm ", "unlink", "file.delete", "rmtree")):
        return {"risk": "high", "category": "general", "template": f"{language} destructive script", "reason": f"{language} destructive script"}
    if any(token in lower for token in ("system(", "exec(", "qx/", "`")):
        return {"risk": "medium", "category": "general", "template": f"{language} subprocess script", "reason": f"{language} subprocess script"}
    if any(token in lower for token in ("net::http", "open-uri", "lwp::", "socket", "http")):
        return {"risk": "high", "category": "general", "template": f"{language} network script", "reason": f"{language} network script"}
    if re.search(r"\b(open|print)\b", lower):
        return {"risk": "low", "category": "general", "template": f"{language} local script", "reason": f"{language} local script", "read_paths": read_paths}
    return {"risk": "low", "category": "general", "template": f"{language} local script", "reason": f"{language} local script", "read_paths": read_paths}


def _extract_secret_env_vars(source, language):
    matches = set()
    for pattern in SECRET_ENV_REF_PATTERNS.get(language, []):
        matches.update(pattern.findall(source))
    return sorted(matches)


def _secret_capabilities_for_env_vars(secret_env_vars, configured_secrets):
    if not secret_env_vars or not configured_secrets:
        return []
    capabilities = []
    for name, item in (configured_secrets or {}).items():
        env_map = item.get("env") if isinstance(item, dict) else {}
        if any(env_name in env_map for env_name in secret_env_vars):
            capabilities.append(name)
    return sorted(set(capabilities))


def _script_source_for_interpreter(tool, argv, cwd):
    tool_name = os.path.basename(tool)
    if tool_name.startswith("python"):
        if len(argv) > 2 and argv[1] == "-c":
            return ("python", argv[2], None)
        for item in argv[1:]:
            if item.startswith("-"):
                continue
            path = _resolve_script_path(item, cwd)
            if path and path.suffix in SCRIPT_EXTENSIONS["python"]:
                return ("python", path.read_text(encoding="utf-8"), str(path))
    if tool_name in {"sh", "bash", "zsh"}:
        if len(argv) > 2 and argv[1] in {"-c", "-lc"}:
            return ("shell", argv[2], None)
        for item in argv[1:]:
            if item.startswith("-"):
                continue
            path = _resolve_script_path(item, cwd)
            if path and path.suffix in SCRIPT_EXTENSIONS["shell"]:
                return ("shell", path.read_text(encoding="utf-8"), str(path))
    if tool_name.startswith("ruby") or tool_name == "perl":
        language = "ruby" if tool_name.startswith("ruby") else "perl"
        if len(argv) > 2 and argv[1] == "-e":
            return (language, argv[2], None)
        for item in argv[1:]:
            if item.startswith("-"):
                continue
            path = _resolve_script_path(item, cwd)
            if path and path.suffix in SCRIPT_EXTENSIONS[language]:
                return (language, path.read_text(encoding="utf-8"), str(path))
    return (None, None, None)


def unwrap_argv(argv):
    if not argv:
        return argv
    tool = os.path.basename(argv[0])
    if tool == "sandbox-exec" and len(argv) > 3 and argv[1] == "-f":
        return argv[3:]
    return argv


def analyze_invocation(argv, cwd=None):
    effective = unwrap_argv(argv)
    if not effective:
        return {"argv": argv}
    tool = os.path.basename(effective[0])
    language, source, path = _script_source_for_interpreter(tool, effective, cwd)
    if language == "python" and source:
        try:
            result = _analyze_python_source(source)
        except SyntaxError:
            result = {"risk": "medium", "category": "general", "template": "python script", "reason": "unparseable python script"}
        result["secret_env_vars"] = _extract_secret_env_vars(source, language)
        return {"argv": effective, "language": language, "source_path": path, **result}
    if language == "shell" and source:
        try:
            analysis = analyze_shell_script(source)
            result = _summarize_leaf_commands(analysis["commands"])
        except ShellAnalysisError:
            result = {"risk": "medium", "category": "general", "template": "shell script", "reason": "unparseable shell script"}
            analysis = {"commands": []}
        result["secret_env_vars"] = _extract_secret_env_vars(source, language)
        return {"argv": effective, "language": language, "source_path": path, "commands": analysis["commands"], **result}
    if language in {"ruby", "perl"} and source:
        result = _heuristic_script_summary(source, language)
        result["secret_env_vars"] = _extract_secret_env_vars(source, language)
        return {"argv": effective, "language": language, "source_path": path, **result}
    return {"argv": effective}


def detect_secret_capabilities(argv, cwd=None, configured_secrets=None):
    analysis = analyze_invocation(argv, cwd)
    env_vars = analysis.get("secret_env_vars", [])
    capabilities = _secret_capabilities_for_env_vars(env_vars, configured_secrets or {})
    return {
        "analysis": analysis,
        "secret_env_vars": env_vars,
        "secret_capabilities": capabilities,
    }
