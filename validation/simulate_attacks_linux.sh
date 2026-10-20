#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Generates the log patterns the Linux detections match, so a rule can be
# proven to fire end to end before anyone relies on it in an incident.
#
# This is a test harness, not an attack tool. Every event is written directly
# into the log stream with `logger`; the only real filesystem operations are
# on a throwaway file under /tmp. No account is touched, no service is
# stopped, nothing is escalated.
#
# Run on an endpoint that has the forwarder installed:
#   sudo ./simulate_attacks_linux.sh            # all scenarios
#   sudo ./simulate_attacks_linux.sh uc02       # one scenario
# ---------------------------------------------------------------------------
set -euo pipefail

SCENARIO="${1:-all}"
FAKE_SRC="198.51.100.77"          # TEST-NET-2, reserved for documentation
FAKE_USER="testuser_sim"
TAG_PREFIX="siem-lab2-sim"

log() { printf '\033[0;32m[+]\033[0m %s\n' "$*"; }

[[ ${EUID} -eq 0 ]] || { echo "run as root so logger can write to authpriv"; exit 1; }

banner() {
    printf '\n\033[1m%s\033[0m\n' "$*"
}

# --- UC-02: SSH brute force ------------------------------------------------
# Eight failures then a success, so both severity branches of the rule are
# exercised - the escalation to "high" is the part most worth testing.
uc02_ssh_bruteforce() {
    banner "UC-02  SSH brute force (8 failed passwords, then one success)"
    for i in $(seq 1 8); do
        logger -p authpriv.info -t "sshd[$((20000 + i))]" \
            "Failed password for ${FAKE_USER} from ${FAKE_SRC} port $((40000 + i)) ssh2"
        sleep 0.2
    done
    # The success that turns this from "attempt" into "compromised".
    logger -p authpriv.info -t "sshd[20099]" \
        "Accepted password for ${FAKE_USER} from ${FAKE_SRC} port 40099 ssh2"
    log "8 failures + 1 success written to auth.log"
}

# --- UC-08: PAM authentication failures ------------------------------------
uc08_auth_failures() {
    banner "UC-08  PAM authentication failures"
    for i in $(seq 1 6); do
        logger -p authpriv.warning -t "sshd[$((21000 + i))]" \
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=${FAKE_SRC} user=${FAKE_USER}"
        sleep 0.2
    done
    log "6 PAM authentication failures written"
}

# --- UC-04: file integrity -------------------------------------------------
# Real chmod/chown run against /tmp only; the log lines naming /etc paths are
# written with logger, so the detection sees a protected-path change without
# one ever occurring.
uc04_file_integrity() {
    banner "UC-04  File integrity - chmod/chown on a throwaway file"
    local tmpfile="/tmp/${TAG_PREFIX}-fim-target"
    touch "${tmpfile}"
    chmod 777 "${tmpfile}"
    chown root:root "${tmpfile}"
    # The detection reads the sudo/auth record, so emit matching log lines.
    logger -p authpriv.notice -t "sudo" \
        " ${FAKE_USER} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod 777 /etc/passwd"
    logger -p authpriv.notice -t "sudo" \
        " ${FAKE_USER} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chown root:root /etc/shadow"
    rm -f "${tmpfile}"
    log "chmod/chown events written (real file operations confined to /tmp)"
}

# --- UC-17: root session ---------------------------------------------------
uc17_root_session() {
    banner "UC-17  Root session opened and closed"
    logger -p authpriv.info -t "sudo" \
        "pam_unix(sudo:session): session opened for user root by ${FAKE_USER}(uid=1000)"
    sleep 1
    logger -p authpriv.info -t "sudo" \
        "pam_unix(sudo:session): session closed for user root"
    log "root session open/close written - expect a High, real-time alert"
}

# --- UC-19: shutdown -------------------------------------------------------
uc19_shutdown() {
    banner "UC-19  Shutdown signal (log line only - nothing is actually stopped)"
    logger -p daemon.notice -t "systemd-logind" \
        "System is powering down."
    log "shutdown log line written; no service was touched"
}

# --- Summary ---------------------------------------------------------------
summary() {
    banner "Verify on the indexer"
    cat <<'EOF'
  UC-02  index=linux sourcetype=linux_secure "Failed password" testuser_sim
         | bin _time span=5m | stats count by _time, host

  UC-04  index=linux sourcetype=linux_secure ("chmod" OR "chown")
         | table _time, host, _raw

  UC-08  index=linux sourcetype=linux_secure "authentication failure"
         | stats count by user

  UC-17  index=linux sourcetype=linux_secure "session * for user root"
         | table _time, host, _raw

  Fired alerts:
         index=siem_summary rule_id IN ("UC-02","UC-04","UC-08","UC-17","UC-19")
         | table _time, rule_id, host, user, severity

  Clean-up: these are ordinary auth.log lines and age out with normal log
  rotation on the endpoint and with index retention in Splunk. To remove them
  immediately (needs the can_delete role):
         index=linux testuser_sim | delete
EOF
}

case "${SCENARIO}" in
    all)  uc02_ssh_bruteforce; uc08_auth_failures; uc04_file_integrity
          uc17_root_session;   uc19_shutdown ;;
    uc02) uc02_ssh_bruteforce ;;
    uc04) uc04_file_integrity ;;
    uc08) uc08_auth_failures ;;
    uc17) uc17_root_session ;;
    uc19) uc19_shutdown ;;
    *)    echo "usage: $0 [all|uc02|uc04|uc08|uc17|uc19]"; exit 1 ;;
esac

summary
