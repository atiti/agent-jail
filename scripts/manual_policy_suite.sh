#!/usr/bin/env bash
set -euo pipefail

: "${AZURE_OPENAI_JIT_TIMEOUT_MS:=10000}"
export AZURE_OPENAI_JIT_TIMEOUT_MS

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
AGENT_JAIL_BIN="${REPO_ROOT}/agent-jail"
MODE="all"
KEEP_STATE=0
SUITE_HOME=""
COLOR=0
MAX_OUTPUT_LINES="${MANUAL_SUITE_MAX_LINES:-12}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  COLOR=1
fi

if [ "${COLOR}" -eq 1 ]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_CYAN=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_RED=""
  C_GREEN=""
  C_YELLOW=""
  C_BLUE=""
  C_CYAN=""
fi

CASE_NAMES=()
CASE_EXPECTS=()
CASE_GROUPS=()
CASE_DESCS=()
CASE_CMDS=()
JIT_NAMES=()
JIT_MODES=()
JIT_DESCS=()
JIT_CMDS=()
JIT_TEMPLATES=()

usage() {
  cat <<'EOF'
Usage: scripts/manual_policy_suite.sh [--list] [--mode deterministic|jit|live-azure|live-azure-all|all] [--keep-state] [--home <path>]

Runs a manual non-destructive policy smoke suite against agent-jail.

Options:
  --list          Print the cases without executing them
  --mode <mode>   Run deterministic, jit, live-azure, live-azure-all, or all cases (default: all)
  --keep-state    Keep the temporary AGENT_JAIL_HOME directory after the run
  --home <path>   Use an explicit AGENT_JAIL_HOME instead of a temporary one
EOF
}

add_case() {
  local name="$1"
  local expectation="$2"
  local group="$3"
  local description="$4"
  shift 4
  CASE_NAMES+=("${name}")
  CASE_EXPECTS+=("${expectation}")
  CASE_GROUPS+=("${group}")
  CASE_DESCS+=("${description}")
  CASE_CMDS+=("$(printf '%q ' "$@")")
}

add_jit_case() {
  local name="$1"
  local mode="$2"
  local description="$3"
  local template="$4"
  shift 4
  JIT_NAMES+=("${name}")
  JIT_MODES+=("${mode}")
  JIT_DESCS+=("${description}")
  JIT_TEMPLATES+=("${template}")
  JIT_CMDS+=("$(printf '%q ' "$@")")
}

case_home() {
  local profile="$1"
  local case_name="$2"
  printf '%s\n' "${SUITE_HOME}/${profile}-${case_name}"
}

render_tag() {
  local kind="$1"
  case "${kind}" in
    PASS) printf '%sPASS%s' "${C_GREEN}${C_BOLD}" "${C_RESET}" ;;
    FAIL) printf '%sFAIL%s' "${C_RED}${C_BOLD}" "${C_RESET}" ;;
    OBSERVE) printf '%sOBSERVE%s' "${C_YELLOW}${C_BOLD}" "${C_RESET}" ;;
    ALLOW) printf '%sALLOW%s' "${C_GREEN}${C_BOLD}" "${C_RESET}" ;;
    DENY) printf '%sDENY%s' "${C_RED}${C_BOLD}" "${C_RESET}" ;;
    DENY-OR-MISSING) printf '%sDENY-OR-MISSING%s' "${C_YELLOW}${C_BOLD}" "${C_RESET}" ;;
    *) printf '%s' "${kind}" ;;
  esac
}

print_header() {
  echo "${C_CYAN}${C_BOLD}agent-jail manual policy suite${C_RESET}"
  echo "${C_DIM}repo: ${REPO_ROOT}${C_RESET}"
}

print_case_output() {
  local output="$1"
  local total_lines
  total_lines=$(printf '%s\n' "${output}" | wc -l | tr -d ' ')
  if [ "${total_lines}" -le "${MAX_OUTPUT_LINES}" ]; then
    printf '%s\n' "${output}"
    return 0
  fi
  printf '%s\n' "${output}" | sed -n "1,${MAX_OUTPUT_LINES}p"
  echo "${C_DIM}... truncated ${total_lines} lines to ${MAX_OUTPUT_LINES}${C_RESET}"
}

policy_query() {
  local home="$1"
  local snippet="$2"
  AGENT_JAIL_TARGET_HOME="${home}" AGENT_JAIL_POLICY_SNIPPET="${snippet}" python3 - <<'PY'
import json, os, pathlib
path = pathlib.Path(os.environ["AGENT_JAIL_TARGET_HOME"]) / "policy.json"
data = json.loads(path.read_text()) if path.exists() else {"rules": [], "pending_reviews": []}
namespace = {"data": data}
exec(os.environ["AGENT_JAIL_POLICY_SNIPPET"], namespace)
PY
}

while [ $# -gt 0 ]; do
  case "$1" in
    --list)
      MODE="list"
      shift
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --keep-state)
      KEEP_STATE=1
      shift
      ;;
    --home)
      SUITE_HOME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${MODE}" in
  list|deterministic|jit|live-azure|live-azure-all|all) ;;
  *)
    echo "invalid mode: ${MODE}" >&2
    exit 2
    ;;
esac

if [ -z "${SUITE_HOME}" ]; then
  SUITE_HOME=$(mktemp -d "${TMPDIR:-/tmp}/agent-jail-manual-suite.XXXXXX")
  CREATED_HOME=1
else
  mkdir -p "${SUITE_HOME}"
  CREATED_HOME=0
fi

cleanup() {
  if [ "${CREATED_HOME}" -eq 1 ] && [ "${KEEP_STATE}" -eq 0 ]; then
    rm -rf "${SUITE_HOME}"
  fi
}
trap cleanup EXIT

write_profile_config() {
  local profile="$1"
  local home="$2"
  mkdir -p "${home}"
  case "${profile}" in
    deterministic)
      cat > "${home}/config.json" <<EOF
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/*.pem",
      "~/build/**/*.key",
      "~/build/**/*.p12",
      "~/build/**/*.pfx",
      "~/build/**/secrets/**"
    ]
  },
  "llm_policy": {
    "jit_enabled": false
  }
}
EOF
      ;;
    jit-allow)
      cat > "${home}/config.json" <<EOF
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/secrets/**"
    ]
  },
  "llm_policy": {
    "provider": "stub",
    "jit_enabled": true,
    "jit_auto_apply_low_risk": true,
    "stub_mode": "allow",
    "stub_confidence": 0.95,
    "confidence_threshold": 0.8
  }
}
EOF
      ;;
    jit-ask)
      cat > "${home}/config.json" <<EOF
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/secrets/**"
    ]
  },
  "llm_policy": {
    "provider": "stub",
    "jit_enabled": true,
    "jit_auto_apply_low_risk": true,
    "stub_mode": "ask",
    "stub_confidence": 0.6,
    "confidence_threshold": 0.8
  }
}
EOF
      ;;
    jit-reject)
      cat > "${home}/config.json" <<EOF
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/secrets/**"
    ]
  },
  "llm_policy": {
    "provider": "stub",
    "jit_enabled": true,
    "jit_auto_apply_low_risk": true,
    "stub_mode": "reject",
    "stub_reason": "stub reject",
    "stub_confidence": 0.95,
    "confidence_threshold": 0.8
  }
}
EOF
      ;;
    live-azure)
      cat > "${home}/config.json" <<EOF
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/secrets/**"
    ]
  },
  "llm_policy": {
    "provider": "azure_openai",
    "model": "${AZURE_OPENAI_MODEL:-gpt-5.4}",
    "endpoint_env": "AZURE_OPENAI_ENDPOINT",
    "api_key_env": "AZURE_OPENAI_API_KEY",
    "deployment_env": "AZURE_OPENAI_DEPLOYMENT",
    "api_version": "${AZURE_OPENAI_API_VERSION:-2024-10-21}",
    "jit_enabled": true,
    "jit_auto_apply_low_risk": true,
    "jit_timeout_ms": ${AZURE_OPENAI_JIT_TIMEOUT_MS:-3000},
    "confidence_threshold": ${AZURE_OPENAI_JIT_CONFIDENCE:-0.8}
  }
}
EOF
      ;;
    *)
      echo "unknown profile: ${profile}" >&2
      exit 2
      ;;
  esac
}

profile_home() {
  local profile="$1"
  local home="${SUITE_HOME}/${profile}"
  write_profile_config "${profile}" "${home}"
  printf '%s\n' "${home}"
}

pass_count=0
fail_count=0
observe_count=0

run_case() {
  local index="$1"
  local name="${CASE_NAMES[${index}]}"
  local expectation="${CASE_EXPECTS[${index}]}"
  local description="${CASE_DESCS[${index}]}"
  local group="${CASE_GROUPS[${index}]}"
  local serialized="${CASE_CMDS[${index}]}"
  local -a cmd=()
  local home
  eval "cmd=( ${serialized} )"
  home=$(case_home "deterministic" "${name}")
  write_profile_config "deterministic" "${home}"

  if [ "${MODE}" = "list" ]; then
    printf '%-24s %-18s %-18s %s\n' "${name}" "${group}" "${expectation}" "${description}"
    return 0
  fi

  echo
  echo "${C_BLUE}${C_BOLD}== ${name} ==${C_RESET}"
  echo "${C_DIM}group:${C_RESET}  ${group}"
  echo "${C_DIM}expect:${C_RESET} $(render_tag "$(echo "${expectation}" | tr '[:lower:]' '[:upper:]')")"
  echo "${C_DIM}desc:${C_RESET}   ${description}"
  echo "${C_DIM}cmd:${C_RESET}    ${cmd[*]}"

  local output status
  set +e
  output=$(AGENT_JAIL_HOME="${home}" "${AGENT_JAIL_BIN}" run --project "${REPO_ROOT}" --allow-write "${REPO_ROOT}" "${cmd[@]}" 2>&1)
  status=$?
  set -e
  print_case_output "${output}"

  local result="FAIL"
  case "${expectation}" in
    allow)
      if [ "${status}" -eq 0 ]; then
        result="PASS"
      fi
      ;;
    deny)
      if [ "${status}" -ne 0 ] && [[ "${output}" == *"denied:"* ]]; then
        result="PASS"
      fi
      ;;
    deny-or-missing)
      if [ "${status}" -ne 0 ] && ([[ "${output}" == *"denied:"* ]] || [[ "${output}" == *"No such file"* ]] || [[ "${output}" == *"cannot open"* ]]); then
        result="PASS"
      fi
      ;;
    observe)
      result="OBSERVE"
      ;;
    *)
      echo "unknown expectation: ${expectation}" >&2
      exit 2
      ;;
  esac

  case "${result}" in
    PASS)
      pass_count=$((pass_count + 1))
      ;;
    FAIL)
      fail_count=$((fail_count + 1))
      ;;
    OBSERVE)
      observe_count=$((observe_count + 1))
      ;;
  esac

  echo "result: $(render_tag "${result}")"
}

run_jit_case() {
  local index="$1"
  local name="${JIT_NAMES[${index}]}"
  local jit_mode="${JIT_MODES[${index}]}"
  local description="${JIT_DESCS[${index}]}"
  local template="${JIT_TEMPLATES[${index}]}"
  local serialized="${JIT_CMDS[${index}]}"
  local -a cmd=()
  local profile="jit-${jit_mode}"
  local home
  eval "cmd=( ${serialized} )"
  if [[ "${jit_mode}" == live-azure* ]]; then
    profile="live-azure"
  fi
  home=$(case_home "${profile}" "${name}")
  write_profile_config "${profile}" "${home}"

  if [ "${MODE}" = "list" ]; then
    printf '%-24s %-18s %-18s %s\n' "${name}" "jit/${jit_mode}" "${jit_mode}" "${description}"
    return 0
  fi

  echo
  echo "${C_BLUE}${C_BOLD}== ${name} ==${C_RESET}"
  echo "${C_DIM}group:${C_RESET}  jit/${jit_mode}"
  echo "${C_DIM}expect:${C_RESET} $(render_tag "$(echo "${jit_mode}" | tr '[:lower:]' '[:upper:]')")"
  echo "${C_DIM}desc:${C_RESET}   ${description}"
  echo "${C_DIM}cmd:${C_RESET}    ${cmd[*]}"

  local output status result review_id has_rule template_ok rerun_output rerun_status
  set +e
  output=$(AGENT_JAIL_HOME="${home}" "${AGENT_JAIL_BIN}" run --project "${REPO_ROOT}" --allow-write "${REPO_ROOT}" "${cmd[@]}" 2>&1)
  status=$?
  set -e
  print_case_output "${output}"
  result="FAIL"

  case "${jit_mode}" in
    allow)
      if [ "${status}" -eq 0 ]; then
        has_rule=$(AGENT_JAIL_EXPECTED_TEMPLATE="${template}" policy_query "${home}" $'import os\nprint(any(rule.get("constraints", {}).get("template") == os.environ["AGENT_JAIL_EXPECTED_TEMPLATE"] for rule in data.get("rules", [])))')
        if [ "${has_rule}" = "True" ]; then
          set +e
          rerun_output=$(AGENT_JAIL_HOME="${home}" "${AGENT_JAIL_BIN}" run --project "${REPO_ROOT}" --allow-write "${REPO_ROOT}" "${cmd[@]}" 2>&1)
          rerun_status=$?
          set -e
          if [ "${rerun_status}" -eq 0 ]; then
            result="PASS"
          fi
        fi
      fi
      ;;
    ask)
      if [ "${status}" -ne 0 ] && [[ "${output}" == *"jit-review-required["* ]]; then
        review_id=$(printf '%s' "${output}" | sed -n 's/.*jit-review-required\[\([^]]*\)\].*/\1/p' | head -n 1)
        template_ok=$(AGENT_JAIL_EXPECTED_TEMPLATE="${template}" AGENT_JAIL_REVIEW_ID="${review_id}" policy_query "${home}" $'import os\nitems = [item for item in data.get("pending_reviews", []) if item.get("id") == os.environ["AGENT_JAIL_REVIEW_ID"]]\nprint(bool(items and items[0].get("template") == os.environ["AGENT_JAIL_EXPECTED_TEMPLATE"]))')
        set +e
        rerun_output=$(AGENT_JAIL_HOME="${home}" "${AGENT_JAIL_BIN}" run --project "${REPO_ROOT}" --allow-write "${REPO_ROOT}" "${cmd[@]}" 2>&1)
        rerun_status=$?
        set -e
        if [ "${template_ok}" = "True" ] && [ "${rerun_status}" -ne 0 ] && [[ "${rerun_output}" == *"jit-review-required[${review_id}]"* ]]; then
          result="PASS"
        fi
      fi
      ;;
    reject)
      if [ "${status}" -ne 0 ] && [[ "${output}" == *"jit-rejected:"* ]]; then
        result="PASS"
      fi
      ;;
    live-azure|live-azure-all)
      if [[ "${output}" == *"jit request failed:"* ]] || [[ "${output}" == *"jit http error:"* ]] || [[ "${output}" == *"jit provider unavailable:"* ]] || [[ "${output}" == *"jit response"* ]]; then
        result="FAIL"
      elif [ "${status}" -eq 0 ]; then
        has_rule=$(AGENT_JAIL_EXPECTED_TEMPLATE="${template}" policy_query "${home}" $'import os\nprint(any(rule.get("constraints", {}).get("template") == os.environ["AGENT_JAIL_EXPECTED_TEMPLATE"] for rule in data.get("rules", [])))')
        if [ "${has_rule}" = "True" ]; then
          result="PASS"
        fi
      elif [[ "${output}" == *"jit-review-required["* ]]; then
        review_id=$(printf '%s' "${output}" | sed -n 's/.*jit-review-required\[\([^]]*\)\].*/\1/p' | head -n 1)
        template_ok=$(AGENT_JAIL_EXPECTED_TEMPLATE="${template}" AGENT_JAIL_REVIEW_ID="${review_id}" policy_query "${home}" $'import os\nitems = [item for item in data.get("pending_reviews", []) if item.get("id") == os.environ["AGENT_JAIL_REVIEW_ID"]]\nprint(bool(items and items[0].get("template") == os.environ["AGENT_JAIL_EXPECTED_TEMPLATE"]))')
        if [ "${template_ok}" = "True" ]; then
          result="PASS"
        fi
      fi
      ;;
    *)
      echo "unknown jit mode: ${jit_mode}" >&2
      exit 2
      ;;
  esac

  case "${result}" in
    PASS) pass_count=$((pass_count + 1)) ;;
    FAIL) fail_count=$((fail_count + 1)) ;;
  esac
  echo "result: $(render_tag "${result}")"
}

python_read_repo=$'import pathlib\nprint(pathlib.Path("README.md").read_text().splitlines()[0])'
python_read_system=$'print(open("/etc/passwd").read())'
python_read_system_var=$'p = "/etc/passwd"\nprint(open(p).read())'
python_read_system_pathlib=$'from pathlib import Path\nprint(Path("/etc/passwd").read_text())'
python_read_system_pathlib_var=$'from pathlib import Path\np = Path("/etc/passwd")\nprint(p.read_text())'

add_case "allow_repo_cat" "allow" "read-scope" "repo-local read should pass" cat README.md
add_case "allow_repo_pipeline" "allow" "read-scope" "read-only shell pipeline inside repo should pass" bash -c 'cat README.md | head'
add_case "allow_python_repo_read" "allow" "interpreters" "python read of repo file should pass" python3 -c "${python_read_repo}"
add_case "deny_system_cat" "deny" "read-scope" "direct system file read should be blocked" bash -c 'cat /etc/passwd'
add_case "deny_system_cat_obfuscated" "deny" "path-obfuscation" "normalized system path should still be blocked" bash -c 'cat /etc/../etc/passwd'
add_case "deny_escape_relative" "deny" "read-scope" "relative escape outside repo should be blocked" bash -c 'cat ../../../../../../../passwd'
add_case "deny_system_pipeline" "deny" "read-scope" "pipelined read of system file should be blocked" bash -c 'cat /etc/passwd | head'
add_case "deny_python_system_read" "deny" "interpreters" "python literal read of system file should be blocked" python3 -c "${python_read_system}"
add_case "deny_python_system_var_read" "deny" "interpreters" "python variable-based read of system file should be blocked" python3 -c "${python_read_system_var}"
add_case "deny_python_pathlib_system_read" "deny" "interpreters" "python pathlib direct read of system file should be blocked" python3 -c "${python_read_system_pathlib}"
add_case "deny_python_pathlib_var_read" "deny" "interpreters" "python pathlib variable read of system file should be blocked" python3 -c "${python_read_system_pathlib_var}"
add_case "deny_ruby_system_read" "deny" "interpreters" "ruby direct system file read should be blocked" ruby -e 'puts File.read("/etc/passwd")'
add_case "deny_perl_system_read" "deny" "interpreters" "perl direct system file read should be blocked" perl -e 'open my $f, "<", "/etc/passwd" or die $!; print <$f>'
add_case "deny_fd_path" "deny" "devices" "reading via /dev/fd path should be blocked by read scope" bash -c 'exec 3<README.md; cat /dev/fd/3'
add_case "deny_grep_system" "deny" "read-scope" "grep on system file should be blocked" bash -c 'grep root /etc/passwd'
add_case "deny_find_system" "deny" "read-scope" "find on system tree should be blocked" bash -c 'find /etc -maxdepth 1 -type f'
add_case "deny_shell_var_indirection" "deny" "shell-indirection" "shell variable-expanded path read should be blocked" bash -c 'p=/etc/passwd; cat "$p"'
add_case "deny_shell_substitution_indirection" "deny" "shell-indirection" "command-substituted path read should be blocked" bash -c 'cat "$(printf /etc/passwd)"'
add_case "deny_shell_xargs_indirection" "deny" "pipeline-hiding" "xargs-mediated path read should be blocked" bash -c 'printf "/etc/passwd\n" | xargs cat'

if [ -e /proc/1/cmdline ]; then
  add_case "deny_proc_other_pid" "deny-or-missing" "procfs" "reading another process proc entry should not pass" bash -c 'cat /proc/1/cmdline'
fi

add_case "observe_dmesg" "observe" "observability" "current model behavior for kernel log reads" bash -c 'dmesg'

add_jit_case "jit_python_auto_allow" "allow" "stub JIT auto-allows a semantic python inspection rule and persists it" "python read-only subprocess script" python3 -c "import subprocess; subprocess.run(['tree', '-L', '2'])"
add_jit_case "jit_python_review" "ask" "stub JIT creates one deduped pending review with the semantic python template" "python read-only subprocess script" python3 -c "import subprocess; subprocess.run(['tree', '-L', '2'])"
add_jit_case "jit_tree_reject" "reject" "stub JIT explicit reject denies the command without creating an allow rule" "tree *" tree -L 2
add_jit_case "live_python_semantic" "live-azure" "live Azure JIT should either auto-allow or create a semantic review for a low-risk python inspection script" "python read-only subprocess script" python3 -c "import subprocess; subprocess.run(['tree', '-L', '2'])"
add_jit_case "live_tree_semantic" "live-azure-all" "live Azure JIT should return a sane semantic outcome for direct tree inspection" "tree *" tree -L 2
add_jit_case "live_shell_semantic" "live-azure-all" "live Azure JIT should return a sane semantic outcome for a read-only shell pipeline" "shell read-only script" bash -c 'ls | head'
add_jit_case "live_python_semantic_matrix" "live-azure-all" "live Azure JIT should return a sane semantic outcome for a low-risk python inspection script" "python read-only subprocess script" python3 -c "import subprocess; subprocess.run(['tree', '-L', '2'])"

print_header

if [ "${MODE}" = "list" ]; then
  printf '%-24s %-18s %-18s %s\n' "case" "group" "expect" "description"
  printf '%-24s %-18s %-18s %s\n' "----" "-----" "------" "-----------"
  for ((i=0; i<${#CASE_NAMES[@]}; i++)); do
    run_case "${i}"
  done
  for ((i=0; i<${#JIT_NAMES[@]}; i++)); do
    run_jit_case "${i}"
  done
  exit 0
fi

if [ "${MODE}" = "all" ] || [ "${MODE}" = "deterministic" ]; then
  for ((i=0; i<${#CASE_NAMES[@]}; i++)); do
    run_case "${i}"
  done
fi

if [ "${MODE}" = "all" ] || [ "${MODE}" = "jit" ]; then
  for ((i=0; i<${#JIT_NAMES[@]}; i++)); do
    if [[ "${JIT_MODES[${i}]}" != live-azure* ]]; then
      run_jit_case "${i}"
    fi
  done
fi

if [ "${MODE}" = "live-azure" ] || [ "${MODE}" = "live-azure-all" ]; then
  if [ -z "${AZURE_OPENAI_ENDPOINT:-}" ] || [ -z "${AZURE_OPENAI_API_KEY:-}" ] || [ -z "${AZURE_OPENAI_DEPLOYMENT:-}" ]; then
    echo "live-azure mode requires AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT" >&2
    exit 2
  fi
  for ((i=0; i<${#JIT_NAMES[@]}; i++)); do
    if [ "${MODE}" = "live-azure" ] && [ "${JIT_MODES[${i}]}" = "live-azure" ]; then
      run_jit_case "${i}"
    fi
    if [ "${MODE}" = "live-azure-all" ] && [[ "${JIT_MODES[${i}]}" == live-azure* ]]; then
      run_jit_case "${i}"
    fi
  done
fi

echo
echo "${C_CYAN}${C_BOLD}summary${C_RESET}"
echo "suite_home: ${SUITE_HOME}"
echo "passed: $(render_tag PASS) ${pass_count}"
echo "failed: $(render_tag FAIL) ${fail_count}"
echo "observed: $(render_tag OBSERVE) ${observe_count}"

if [ "${fail_count}" -ne 0 ]; then
  exit 1
fi
