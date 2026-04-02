import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from agent_jail.backend import build_command

SYSTEM_ROOT_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"
SYSTEM_ROOT_PEM_NAME = "macos-system-roots.pem"

BACKENDS = {
    "native-tls": ["blocking", "native-tls"],
    "rustls-native-roots": ["blocking", "rustls-tls-native-roots"],
    "rustls-webpki-roots": ["blocking", "rustls-tls-webpki-roots"],
}


def render_cargo_toml(backend):
    if backend not in BACKENDS:
        raise ValueError(f"unsupported backend: {backend}")
    features = ", ".join(f'"{feature}"' for feature in BACKENDS[backend])
    return f"""[package]
name = "reqwest-tls-probe"
version = "0.1.0"
edition = "2021"

[dependencies]
reqwest = {{ version = "0.12", default-features = false, features = [{features}] }}
serde_json = "1"
"""


def render_main_rs():
    return r"""use std::env;
use std::error::Error;

use reqwest::blocking::Client;
use serde_json::json;

fn error_chain(err: &dyn Error) -> Vec<String> {
    let mut out = vec![err.to_string()];
    let mut source = err.source();
    while let Some(next) = source {
        out.push(next.to_string());
        source = next.source();
    }
    out
}

fn main() {
    let url = env::var("REQWEST_TLS_PROBE_URL").expect("REQWEST_TLS_PROBE_URL is required");
    let cert_file = env::var("SSL_CERT_FILE").ok();

    let builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    let client = match builder.build() {
        Ok(client) => client,
        Err(err) => {
            println!(
                "{}",
                json!({
                    "stage": "build",
                    "ok": false,
                    "ssl_cert_file": cert_file,
                    "error_chain": error_chain(&err),
                    "debug": format!("{err:?}"),
                })
            );
            std::process::exit(2);
        }
    };

    match client.get(&url).send() {
        Ok(response) => {
            println!(
                "{}",
                json!({
                    "stage": "request",
                    "ok": true,
                    "ssl_cert_file": cert_file,
                    "status": response.status().as_u16(),
                    "url": response.url().as_str(),
                })
            );
        }
        Err(err) => {
            println!(
                "{}",
                json!({
                    "stage": "request",
                    "ok": false,
                    "ssl_cert_file": cert_file,
                    "error_chain": error_chain(&err),
                    "debug": format!("{err:?}"),
                })
            );
            std::process::exit(1);
        }
    }
}
"""


def export_system_roots_pem(session_dir):
    pem_path = Path(session_dir) / SYSTEM_ROOT_PEM_NAME
    result = subprocess.run(
        [
            "/usr/bin/security",
            "find-certificate",
            "-a",
            "-p",
            SYSTEM_ROOT_KEYCHAIN,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    pem_path.write_text(result.stdout, encoding="utf-8")
    return str(pem_path)


def prepare_cert_env(cert_source, cert_path, session_dir):
    if cert_source == "none":
        return {}
    if cert_source == "openssl-default":
        return {}
    if cert_source == "path":
        if not cert_path:
            raise ValueError("--cert-path is required when --cert-source=path")
        return {"SSL_CERT_FILE": cert_path}
    if cert_source == "system-roots-pem":
        pem_path = export_system_roots_pem(session_dir)
        if not pem_path:
            raise RuntimeError("failed to export macOS system roots to PEM")
        return {"SSL_CERT_FILE": pem_path}
    raise ValueError(f"unsupported cert source: {cert_source}")


def write_probe_crate(temp_dir, backend):
    crate_dir = Path(temp_dir) / "reqwest-tls-probe"
    src_dir = crate_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (crate_dir / "Cargo.toml").write_text(render_cargo_toml(backend), encoding="utf-8")
    (src_dir / "main.rs").write_text(render_main_rs(), encoding="utf-8")
    return crate_dir


def build_cargo_env(temp_dir, crate_dir):
    env = os.environ.copy()
    env["CARGO_HOME"] = os.path.join(temp_dir, "cargo-home")
    env["CARGO_TARGET_DIR"] = os.path.join(crate_dir, "target")
    return env


def build_probe_binary(crate_dir, temp_dir):
    subprocess.run(
        ["cargo", "build", "--quiet", "--release"],
        cwd=crate_dir,
        check=True,
        env=build_cargo_env(temp_dir, crate_dir),
    )
    return crate_dir / "target" / "release" / "reqwest-tls-probe"


def measure_system_root_export_bytes(sandbox, cwd, session_dir):
    command = [
        "/bin/zsh",
        "-lc",
        f"/usr/bin/security find-certificate -a -p {SYSTEM_ROOT_KEYCHAIN} | /usr/bin/wc -c | /usr/bin/tr -d ' '",
    ]
    env = os.environ.copy()
    if sandbox:
        env.update(
            {
                "AGENT_JAIL_HOME": os.path.expanduser("~/.agent-jail"),
                "AGENT_JAIL_SESSION_DIR": session_dir,
                "AGENT_JAIL_MOUNTS": "[]",
                "AGENT_JAIL_AUTH_MOUNTS": "[]",
                "AGENT_JAIL_DENY_READ_PATTERNS": "[]",
            }
        )
        command = build_command({"name": "sandbox-exec"}, command, cwd, env)
    result = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    return {"returncode": 0, "bytes": int(result.stdout.strip() or "0")}


def run_probe(url, backend, cert_source, cert_path, sandbox):
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="agent-jail-reqwest-probe-") as temp_dir:
        crate_dir = write_probe_crate(temp_dir, backend)
        binary = build_probe_binary(crate_dir, temp_dir)
        session_dir = temp_dir
        runtime_env = os.environ.copy()
        runtime_env["REQWEST_TLS_PROBE_URL"] = url
        runtime_env.pop("SSL_CERT_FILE", None)
        runtime_env.pop("SSL_CERT_DIR", None)
        if cert_source == "openssl-default":
            cafile = os.environ.get("SSL_CERT_FILE")
            if cafile:
                runtime_env["SSL_CERT_FILE"] = cafile
        else:
            runtime_env.update(prepare_cert_env(cert_source, cert_path, session_dir))
        cmd = [str(binary)]
        if sandbox:
            runtime_env.update(
                {
                    "AGENT_JAIL_HOME": os.path.expanduser("~/.agent-jail"),
                    "AGENT_JAIL_SESSION_DIR": session_dir,
                    "AGENT_JAIL_MOUNTS": "[]",
                    "AGENT_JAIL_AUTH_MOUNTS": "[]",
                    "AGENT_JAIL_DENY_READ_PATTERNS": "[]",
                }
            )
            cmd = build_command({"name": "sandbox-exec"}, cmd, cwd, runtime_env)
        result = subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True, env=runtime_env)
        parsed_stdout = None
        stdout = result.stdout.strip()
        if stdout:
            try:
                parsed_stdout = json.loads(stdout)
            except json.JSONDecodeError:
                parsed_stdout = None
        return {
            "backend": backend,
            "sandbox": sandbox,
            "cert_source": cert_source,
            "cert_file": runtime_env.get("SSL_CERT_FILE"),
            "system_root_export": measure_system_root_export_bytes(sandbox, cwd, session_dir),
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": result.stderr.strip(),
            "parsed": parsed_stdout,
        }


def build_parser():
    parser = argparse.ArgumentParser(description="Probe reqwest TLS behavior on macOS with and without sandbox-exec.")
    parser.add_argument("--url", default="https://developers.openai.com/mcp")
    parser.add_argument("--backend", choices=sorted(BACKENDS), default="native-tls")
    parser.add_argument(
        "--cert-source",
        choices=("none", "openssl-default", "system-roots-pem", "path"),
        default="none",
    )
    parser.add_argument("--cert-path")
    parser.add_argument("--sandbox", action="store_true")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    result = run_probe(
        url=args.url,
        backend=args.backend,
        cert_source=args.cert_source,
        cert_path=args.cert_path,
        sandbox=args.sandbox,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["returncode"] == 0 else result["returncode"]


if __name__ == "__main__":
    raise SystemExit(main())
