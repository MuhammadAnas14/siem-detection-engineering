#!/usr/bin/env bash
# Shared helpers sourced by every install script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${SCRIPT_DIR}/splunk.env" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/splunk.env"
else
    echo "FATAL: ${SCRIPT_DIR}/splunk.env not found."
    echo "       cp splunk.env.example splunk.env && chmod 600 splunk.env"
    exit 1
fi

log()  { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

require_root() {
    [[ ${EUID} -eq 0 ]] || die "run as root (sudo $0)"
}

# splunk_cmd <binary-home> <args...>  -- run a splunk CLI command non-interactively
splunk_cmd() {
    local home="$1"; shift
    "${home}/bin/splunk" "$@" \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" \
        --accept-license --answer-yes --no-prompt
}

# Back up a conf file once before we overwrite it.
backup_once() {
    local f="$1"
    [[ -f "$f" && ! -f "${f}.orig" ]] && cp -a "$f" "${f}.orig"
    return 0
}
