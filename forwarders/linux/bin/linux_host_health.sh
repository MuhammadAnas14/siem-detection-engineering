#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Scripted input referenced by etc/system/local/inputs.conf.
#
# Emits one key=value event per interval so endpoint CPU, memory and disk can
# be plotted next to the security data, without deploying a separate metrics
# agent. Keep it cheap - it runs on every endpoint, every interval.
#
# Install to: /opt/splunkforwarder/bin/linux_host_health.sh  (mode 0755)
# ---------------------------------------------------------------------------
set -euo pipefail

ts=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
host=$(hostname -f 2>/dev/null || hostname)

# CPU: 100 - idle, averaged over one second
cpu_idle=$(top -bn2 -d1 | awk '/^%Cpu/ {v=$8} END {print v+0}')
cpu_used=$(awk -v i="${cpu_idle}" 'BEGIN {printf "%.2f", 100-i}')

mem_total=$(awk '/MemTotal/     {print $2}' /proc/meminfo)
mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
mem_used_pct=$(awk -v t="${mem_total}" -v a="${mem_avail}" \
    'BEGIN {printf "%.2f", (t-a)/t*100}')

disk_used_pct=$(df -P / | awk 'NR==2 {gsub("%","",$5); print $5}')
load1=$(awk '{print $1}' /proc/loadavg)
uptime_s=$(awk '{printf "%d", $1}' /proc/uptime)

# Self-reported forwarder version, so the version inventory covers hosts that
# are not phoning home to the deployment server.
uf_version=$("${SPLUNK_HOME:-/opt/splunkforwarder}/bin/splunk" version 2>/dev/null \
    | awk '/Splunk Universal Forwarder/ {print $4}')

# Logged-in users and failed-login tally for the auth panels.
sessions=$(who | wc -l)
failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)

printf '%s host=%s os=linux cpu_used_pct=%s mem_used_pct=%s disk_used_pct=%s load1=%s uptime_secs=%s uf_version=%s sessions=%s failed_logins_total=%s\n' \
    "${ts}" "${host}" "${cpu_used}" "${mem_used_pct}" "${disk_used_pct}" \
    "${load1}" "${uptime_s}" "${uf_version:-unknown}" "${sessions}" "${failed_logins}"
