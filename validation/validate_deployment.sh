#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Post-deployment health check.
#
# Answers the questions that matter after a deploy or a change, in the order
# a failure would cascade:
#
#   1. Is the platform up and accepting data?
#   2. Is data actually arriving in every index that should have it?
#   3. Is the detection content deployed, enabled and executing?
#   4. Are the dashboards and lookups in place?
#   5. Is every rule mapped to a technique?
#   6. Are the external data sources reachable?
#
# Exits non-zero if anything fails, so it can gate a deployment pipeline.
#
#   sudo ./validate_deployment.sh
# ---------------------------------------------------------------------------
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../install/00_common.sh"

PASS=0; FAIL=0; NOTE=0

check() {  # check <description> <command...>
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '  \033[0;32mPASS\033[0m  %s\n' "${desc}"; PASS=$((PASS+1))
    else
        printf '  \033[0;31mFAIL\033[0m  %s\n' "${desc}"; FAIL=$((FAIL+1))
    fi
}
pass() { printf '  \033[0;32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[0;31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
note() { printf '  \033[0;33mNOTE\033[0m  %s\n' "$*"; NOTE=$((NOTE+1)); }
info() { printf '  \033[0;36mINFO\033[0m  %s\n' "$*"; }
section() { printf '\n\033[1m%s\033[0m\n' "$*"; }

spl() {  # spl <query> [earliest] -> oneshot search
    sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" search "$1" \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" \
        -earliest_time "${2:--24h}" -latest_time now 2>/dev/null
}

num() { tr -dc '0-9' | tail -c 12; }   # extract a count from CLI output

# ===========================================================================
section "1. Platform"
# ===========================================================================
check "splunkd is running" \
    pgrep -f "${SPLUNK_HOME}/bin/splunkd"
check "management port ${SPLUNK_MGMT_PORT} responds" \
    curl -ks "https://127.0.0.1:${SPLUNK_MGMT_PORT}/services/server/info"
check "web interface on port ${SPLUNK_WEB_PORT} responds" \
    curl -ks -o /dev/null "https://127.0.0.1:${SPLUNK_WEB_PORT}/en-US/account/login"
check "receiving port ${INDEXER_S2S_PORT} is listening" \
    bash -c "ss -ltn 2>/dev/null | grep -q ':${INDEXER_S2S_PORT}'"
check "boot-start is enabled" \
    systemctl is-enabled Splunkd

info "$(sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" version 2>/dev/null | head -1)"

# A full disk takes splunkd down hard; check headroom before it matters.
avail=$(df -BG --output=avail "${SPLUNK_HOME}" 2>/dev/null | tail -1 | tr -dc '0-9')
if [[ -n "${avail}" ]] && (( avail > 20 )); then
    pass "disk headroom on ${SPLUNK_HOME}: ${avail} GB free"
else
    fail "low disk on ${SPLUNK_HOME}: ${avail:-?} GB free (minFreeSpace is 10 GB)"
fi

# ===========================================================================
section "2. Data ingestion"
# ===========================================================================
for idx in linux linux_audit windows windows_audit; do
    count=$(spl "| tstats count WHERE index=${idx} | fields count" | num)
    if [[ -n "${count}" && "${count}" -gt 0 ]]; then
        pass "$(printf 'index=%-14s %s events in 24h' "${idx}" "${count}")"
    else
        fail "$(printf 'index=%-14s no events in 24h' "${idx}")"
    fi
done

printf '\n  Forwarder connections:\n'
spl 'index=_internal sourcetype=splunkd group=tcpin_connections | stats latest(version) AS version, sum(kb) AS kb by sourceIp | eval mb=round(kb/1024,1) | fields sourceIp, version, mb' \
    | sed 's/^/      /'

printf '\n  Sourcetype coverage:\n'
spl '| tstats count WHERE index=linux OR index=windows OR index=linux_audit OR index=windows_audit BY index, sourcetype | sort - count' \
    | sed 's/^/      /'

# A forwarder that connects but sends nothing is a permissions problem, not a
# network one - worth separating because the fix is completely different.
silent=$(spl 'index=_internal sourcetype=splunkd group=tcpin_connections | stats sum(kb) AS kb BY sourceIp | where kb=0 | stats count' | num)
[[ "${silent:-0}" -eq 0 ]] \
    && pass "no forwarder is connected but idle" \
    || note "${silent} forwarder(s) connected but sent 0 KB - check file permissions on the endpoint"

# ===========================================================================
section "3. Detection content"
# ===========================================================================
rules=$(spl '| rest /servicesNS/-/siem_core/saved/searches | search eai:acl.app=siem_core title!=default | stats count' -1m | num)
if [[ "${rules:-0}" -gt 0 ]]; then
    pass "${rules} rules deployed"
else
    fail "no rules found in the siem_core app"
fi

disabled=$(spl '| rest /servicesNS/-/siem_core/saved/searches | search eai:acl.app=siem_core disabled=1 | stats count' -1m | num)
[[ "${disabled:-0}" -eq 0 ]] \
    && pass "all rules enabled" \
    || note "${disabled} rule(s) disabled"

# The important one: a rule can be enabled and still never execute.
skipped=$(spl 'index=_internal sourcetype=scheduler app=siem_core status=skipped | stats count' -24h | num)
[[ "${skipped:-0}" -eq 0 ]] \
    && pass "no scheduler skips in the last 24h" \
    || fail "${skipped} scheduler skip(s) in 24h - rules are enabled but not running (see limits.conf)"

printf '\n  Rules that have fired in the last 7 days:\n'
spl 'index=siem_summary | stats count AS alerts, latest(_time) AS last BY rule_id | eval last=strftime(last,"%F %T") | sort rule_id' -7d \
    | sed 's/^/      /'

printf '\n  Deployed but never triggered (unproven, not necessarily broken):\n'
spl '| rest /servicesNS/-/siem_core/saved/searches | search eai:acl.app=siem_core title!=default | rex field=title "^(?<rule_id>(UC|OPS)-\d+)" | join type=left rule_id [ search index=siem_summary earliest=-7d | stats count BY rule_id ] | where isnull(count) | table title' -7d \
    | sed 's/^/      /'

# ===========================================================================
section "4. Dashboards and lookups"
# ===========================================================================
for view in soc_overview use_case_catalog mitre_attack_coverage forwarder_health system_health; do
    check "dashboard '${view}' installed" \
        test -f "${SPLUNK_HOME}/etc/apps/siem_core/default/data/ui/views/${view}.xml"
done
check "navigation menu installed" \
    test -f "${SPLUNK_HOME}/etc/apps/siem_core/default/data/ui/nav/default.xml"
check "ATT&CK lookup readable" \
    test -r "${SPLUNK_HOME}/etc/apps/siem_core/lookups/mitre_attack_lookup.csv"
check "severity lookup readable" \
    test -r "${SPLUNK_HOME}/etc/apps/siem_core/lookups/severity_lookup.csv"

# ===========================================================================
section "5. ATT&CK coverage"
# ===========================================================================
printf '  Tactic coverage:\n'
spl '| inputlookup mitre_attack_lookup | where mitre_tactic_id!="NA" | stats count AS rules, values(rule_id) AS rule_ids BY mitre_tactic_id, mitre_tactic | sort mitre_tactic_id' -1m \
    | sed 's/^/      /'

unmapped=$(spl '| inputlookup mitre_attack_lookup | where mitre_tactic_id="NA" AND NOT match(rule_id,"^OPS") | stats count' -1m | num)
[[ "${unmapped:-0}" -eq 0 ]] \
    && pass "every detection rule carries a tactic and technique" \
    || fail "${unmapped} detection rule(s) unmapped"

# Catches the drift that breaks enrichment: a rule renamed without updating
# the lookup silently loses its classification.
orphans=$(spl '| rest /servicesNS/-/siem_core/saved/searches | search eai:acl.app=siem_core title!=default | rex field=title "^(?<rule_id>(UC|OPS)-\d+)" | join type=left rule_id [| inputlookup mitre_attack_lookup | fields rule_id, mitre_tactic] | where isnull(mitre_tactic) | stats count' -1m | num)
[[ "${orphans:-0}" -eq 0 ]] \
    && pass "every deployed rule resolves in the lookup" \
    || fail "${orphans} deployed rule(s) have no lookup row - enrichment will be empty"

# ===========================================================================
section "6. External data sources"
# ===========================================================================
if timeout 5 bash -c "</dev/tcp/${MYSQL_HOST}/${MYSQL_PORT}" 2>/dev/null; then
    pass "MySQL ${MYSQL_HOST}:${MYSQL_PORT} reachable"
else
    note "MySQL ${MYSQL_HOST}:${MYSQL_PORT} unreachable - the DB Connect input will produce no rows"
fi
if timeout 5 bash -c "</dev/tcp/${MSSQL_HOST}/${MSSQL_PORT}" 2>/dev/null; then
    note "SQL Server ${MSSQL_HOST}:${MSSQL_PORT} reachable - the mssql_* stanzas can be enabled"
else
    note "SQL Server ${MSSQL_HOST}:${MSSQL_PORT} unreachable - mssql_* stanzas are correctly left disabled"
fi

# ===========================================================================
printf '\n\033[1mSummary\033[0m\n'
printf '  passed: %d   failed: %d   notes: %d\n\n' "${PASS}" "${FAIL}" "${NOTE}"
(( FAIL == 0 )) || exit 1
