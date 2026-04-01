#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
AGENT_JAIL_BIN="${REPO_ROOT}/agent-jail"
MODE="run"
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

usage() {
  cat <<'EOF'
Usage: scripts/manual_policy_suite.sh [--list] [--keep-state] [--home <path>]

Runs a manual non-destructive policy smoke suite against agent-jail.

Options:
  --list          Print the cases without executing them
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

while [ $# -gt 0 ]; do
  case "$1" in
    --list)
      MODE="list"
      shift
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

cat > "${SUITE_HOME}/config.json" <<EOF
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
  eval "cmd=( ${serialized} )"

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
  output=$(AGENT_JAIL_HOME="${SUITE_HOME}" "${AGENT_JAIL_BIN}" run --project "${REPO_ROOT}" --allow-write "${REPO_ROOT}" "${cmd[@]}" 2>&1)
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

python_read_repo=$'import pathlib\nprint(pathlib.Path("README.md").read_text().splitlines()[0])'
python_read_system=$'print(open("/etc/passwd").read())'

add_case "allow_repo_cat" "allow" "read-scope" "repo-local read should pass" cat README.md
add_case "allow_repo_pipeline" "allow" "read-scope" "read-only shell pipeline inside repo should pass" bash -c 'cat README.md | head'
add_case "allow_python_repo_read" "allow" "interpreters" "python read of repo file should pass" python3 -c "${python_read_repo}"
add_case "deny_system_cat" "deny" "read-scope" "direct system file read should be blocked" bash -c 'cat /etc/passwd'
add_case "deny_escape_relative" "deny" "read-scope" "relative escape outside repo should be blocked" bash -c 'cat ../../../../../../../passwd'
add_case "deny_system_pipeline" "deny" "read-scope" "pipelined read of system file should be blocked" bash -c 'cat /etc/passwd | head'
add_case "deny_python_system_read" "deny" "interpreters" "python literal read of system file should be blocked" python3 -c "${python_read_system}"
add_case "deny_fd_path" "deny" "devices" "reading via /dev/fd path should be blocked by read scope" bash -c 'exec 3<README.md; cat /dev/fd/3'
add_case "deny_grep_system" "deny" "read-scope" "grep on system file should be blocked" bash -c 'grep root /etc/passwd'
add_case "deny_find_system" "deny" "read-scope" "find on system tree should be blocked" bash -c 'find /etc -maxdepth 1 -type f'

if [ -e /proc/1/cmdline ]; then
  add_case "deny_proc_other_pid" "deny-or-missing" "procfs" "reading another process proc entry should not pass" bash -c 'cat /proc/1/cmdline'
fi

add_case "observe_dmesg" "observe" "observability" "current model behavior for kernel log reads" bash -c 'dmesg'

print_header

if [ "${MODE}" = "list" ]; then
  printf '%-24s %-18s %-18s %s\n' "case" "group" "expect" "description"
  printf '%-24s %-18s %-18s %s\n' "----" "-----" "------" "-----------"
  for ((i=0; i<${#CASE_NAMES[@]}; i++)); do
    run_case "${i}"
  done
  exit 0
fi

for ((i=0; i<${#CASE_NAMES[@]}; i++)); do
  run_case "${i}"
done

echo
echo "${C_CYAN}${C_BOLD}summary${C_RESET}"
echo "suite_home: ${SUITE_HOME}"
echo "passed: $(render_tag PASS) ${pass_count}"
echo "failed: $(render_tag FAIL) ${fail_count}"
echo "observed: $(render_tag OBSERVE) ${observe_count}"

if [ "${fail_count}" -ne 0 ]; then
  exit 1
fi
