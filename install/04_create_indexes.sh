#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Creates the indexes declared in indexer/etc/system/local/indexes.conf.
#
# indexes.conf is the single source of truth: this script reads the stanza
# list out of it and creates whatever splunkd does not already know about, so
# adding an index is a one-line edit there rather than a change in two places.
#
# Idempotent - safe to re-run.
#
#   sudo ./04_create_indexes.sh            # create + verify
#   sudo ./04_create_indexes.sh --verify   # verify only
# ---------------------------------------------------------------------------
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_common.sh"

INDEXES_CONF="${REPO_DIR}/indexer/etc/system/local/indexes.conf"
VERIFY_ONLY=0
[[ "${1:-}" == "--verify" ]] && VERIFY_ONLY=1

[[ -f "${INDEXES_CONF}" ]] || die "missing ${INDEXES_CONF}"

# Stanza names, skipping comments and Splunk's volume:/default stanzas.
mapfile -t WANTED < <(
    grep -E '^\[[a-zA-Z0-9_]+\]$' "${INDEXES_CONF}" \
        | tr -d '[]' \
        | grep -vE '^(default|volume|provider)' \
        | sort -u
)
log "indexes.conf declares ${#WANTED[@]} indexes: ${WANTED[*]}"

existing() {
    splunk_cmd "${SPLUNK_HOME}" list index 2>/dev/null \
        | awk '/^\t/ {print $1}' | tr -d '\t'
}

create_missing() {
    local have
    have="$(existing || true)"
    local created=0
    for idx in "${WANTED[@]}"; do
        if grep -qx "${idx}" <<<"${have}"; then
            log "  = ${idx} (exists)"
            continue
        fi
        log "  + ${idx} (creating)"
        splunk_cmd "${SPLUNK_HOME}" add index "${idx}" \
            -homePath   "\$SPLUNK_DB/${idx}/db" \
            -coldPath   "\$SPLUNK_DB/${idx}/colddb" \
            -thawedPath "\$SPLUNK_DB/${idx}/thaweddb" \
            -maxDataSize auto \
            -frozenTimePeriodInSecs "${RETENTION_SECS}"
        created=$((created + 1))
    done
    (( created > 0 )) && {
        log "restarting Splunk to apply ${created} new index(es)"
        splunk_cmd "${SPLUNK_HOME}" restart
    }
    return 0
}

verify() {
    log "verifying against splunkd"
    local have missing=0
    have="$(existing || true)"
    for idx in "${WANTED[@]}"; do
        if grep -qx "${idx}" <<<"${have}"; then
            printf '      \033[0;32mOK  \033[0m %s\n' "${idx}"
        else
            printf '      \033[0;31mMISS\033[0m %s\n' "${idx}"
            missing=$((missing + 1))
        fi
    done
    log "retention / bucket settings per index:"
    for idx in "${WANTED[@]}"; do
        local days
        days=$(splunk_cmd "${SPLUNK_HOME}" btool indexes list "${idx}" 2>/dev/null \
            | awk -F= '/frozenTimePeriodInSecs/ {printf "%d", $2/86400}')
        printf '      %-14s frozen after %s days\n' "${idx}" "${days:-?}"
    done
    (( missing == 0 )) || die "${missing} index(es) missing"
}

(( VERIFY_ONLY == 0 )) && create_missing
verify
log "index configuration complete."
