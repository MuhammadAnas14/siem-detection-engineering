#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Installs and initialises Splunk Enterprise on a Debian/Ubuntu host.
#
# Idempotent: re-running skips anything already in place, so it is safe to use
# to re-apply configuration after a change.
#
#   sudo ./01_install_splunk_enterprise.sh
# ---------------------------------------------------------------------------
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_common.sh"
require_root

TARBALL="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${TARBALL}"

# --- Sizing check ----------------------------------------------------------
# Warns rather than aborts: undersized is workable for a small estate, but it
# is worth knowing before the scheduler starts dropping searches.
check_sizing() {
    local cpus mem_gb disk_gb
    cpus=$(nproc)
    mem_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
    disk_gb=$(df -BG --output=avail /opt 2>/dev/null | tail -1 | tr -dc '0-9')
    log "detected: ${cpus} vCPU, ${mem_gb} GB RAM, ${disk_gb:-?} GB free on /opt"
    (( cpus    >= 4   )) || warn "4 vCPU recommended (have ${cpus}) - expect scheduler contention"
    (( mem_gb  >= 7   )) || warn "8 GB RAM recommended (have ${mem_gb} GB)"
    (( ${disk_gb:-0} >= 180 )) || warn "200 GB on /opt recommended (have ${disk_gb:-?} GB) - review retention in indexes.conf"
}

# --- Download and extract --------------------------------------------------
install_splunk() {
    if [[ -x "${SPLUNK_HOME}/bin/splunk" ]]; then
        log "Splunk already present at ${SPLUNK_HOME}, skipping extract"
        return
    fi
    getent group  "${SPLUNK_GROUP}" >/dev/null || groupadd -r "${SPLUNK_GROUP}"
    getent passwd "${SPLUNK_USER}"  >/dev/null || \
        useradd -r -m -g "${SPLUNK_GROUP}" -d /home/"${SPLUNK_USER}" -s /bin/bash "${SPLUNK_USER}"

    log "downloading ${TARBALL}"
    [[ -f "/tmp/${TARBALL}" ]] || curl -fL -o "/tmp/${TARBALL}" "${URL}"

    log "extracting into $(dirname "${SPLUNK_HOME}")"
    tar -xzf "/tmp/${TARBALL}" -C "$(dirname "${SPLUNK_HOME}")"
    chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${SPLUNK_HOME}"
}

# Seed the admin account so the first start is non-interactive.
seed_admin() {
    local seed="${SPLUNK_HOME}/etc/system/local/user-seed.conf"
    [[ -f "${SPLUNK_HOME}/etc/passwd" ]] && { log "admin already seeded"; return; }
    cat > "${seed}" <<EOF
[user_info]
USERNAME = ${SPLUNK_ADMIN_USER}
PASSWORD = ${SPLUNK_ADMIN_PASSWORD}
EOF
    chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${seed}"
    chmod 600 "${seed}"
}

# --- First start and boot-start -------------------------------------------
first_start() {
    log "starting Splunk (accepting licence)"
    sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" start \
        --accept-license --answer-yes --no-prompt

    log "enabling boot-start (systemd unit Splunkd)"
    "${SPLUNK_HOME}/bin/splunk" enable boot-start \
        -user "${SPLUNK_USER}" -systemd-managed 1 -create-polkit-rules 1 \
        --accept-license --answer-yes --no-prompt
    systemctl daemon-reload
}

# --- Licence ---------------------------------------------------------------
apply_license() {
    if [[ -z "${SPLUNK_LICENSE_FILE}" ]]; then
        warn "SPLUNK_LICENSE_FILE unset - staying on the 60-day Enterprise Trial"
        warn "  the trial reverts to the free licence, which disables alerting"
        return
    fi
    [[ -f "${SPLUNK_LICENSE_FILE}" ]] || die "licence file not found: ${SPLUNK_LICENSE_FILE}"
    log "applying licence ${SPLUNK_LICENSE_FILE}"
    splunk_cmd "${SPLUNK_HOME}" add licenses "${SPLUNK_LICENSE_FILE}"
}

# --- indexer-side system configuration -------------------------------------
deploy_system_conf() {
    log "deploying indexer etc/system/local configuration"
    local src="${REPO_DIR}/indexer/etc/system/local"
    local dst="${SPLUNK_HOME}/etc/system/local"
    for f in indexes.conf inputs.conf outputs.conf server.conf web.conf limits.conf props.conf; do
        [[ -f "${src}/${f}" ]] || continue
        backup_once "${dst}/${f}"
        # Only etc/system/local is touched; the shipped defaults under
        # etc/system/default stay pristine so an upgrade can replace them.
        install -o "${SPLUNK_USER}" -g "${SPLUNK_GROUP}" -m 644 "${src}/${f}" "${dst}/${f}"
        log "  -> ${f}"
    done
    # Substitute the indexer address placeholders.
    sed -i "s/__INDEXER_HOST__/${INDEXER_HOST}/g; s/__S2S_PORT__/${INDEXER_S2S_PORT}/g" \
        "${dst}"/*.conf
}

# --- Verification ----------------------------------------------------------
verify() {
    log "waiting for splunkd on :${SPLUNK_MGMT_PORT}"
    for _ in $(seq 1 30); do
        curl -ks "https://127.0.0.1:${SPLUNK_MGMT_PORT}/services/server/info" >/dev/null && break
        sleep 2
    done
    log "indexes now configured:"
    splunk_cmd "${SPLUNK_HOME}" list index 2>/dev/null | sed 's/^/      /' || true
    log "web interface: https://${INDEXER_HOST}:${SPLUNK_WEB_PORT}/login"
}

check_sizing
install_splunk
seed_admin
first_start
apply_license
deploy_system_conf
log "restarting to pick up indexes.conf / inputs.conf"
splunk_cmd "${SPLUNK_HOME}" restart
verify
log "Splunk Enterprise ${SPLUNK_VERSION} deployment complete."
