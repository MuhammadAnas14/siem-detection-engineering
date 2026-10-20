#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Installs and configures the Universal Forwarder on a Linux endpoint.
#
# Run on the endpoint itself:  sudo ./02_install_uf_linux.sh
#
# Beyond installing the agent this also fixes the permissions problem that
# silently breaks most first deployments - see grant_log_access below.
# ---------------------------------------------------------------------------
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_common.sh"
require_root

TARBALL="splunkforwarder-${UF_VERSION}-${SPLUNK_BUILD}-linux-amd64.tgz"
URL="https://download.splunk.com/products/universalforwarder/releases/${UF_VERSION}/linux/${TARBALL}"

# --- Install ---------------------------------------------------------------
install_uf() {
    if [[ -x "${UF_HOME}/bin/splunk" ]]; then
        log "UF already present at ${UF_HOME}"
        return
    fi
    getent group  "${SPLUNK_GROUP}" >/dev/null || groupadd -r "${SPLUNK_GROUP}"
    getent passwd "${SPLUNK_USER}"  >/dev/null || \
        useradd -r -m -g "${SPLUNK_GROUP}" -d /home/"${SPLUNK_USER}" -s /bin/bash "${SPLUNK_USER}"

    log "downloading ${TARBALL}"
    [[ -f "/tmp/${TARBALL}" ]] || curl -fL -o "/tmp/${TARBALL}" "${URL}"
    tar -xzf "/tmp/${TARBALL}" -C "$(dirname "${UF_HOME}")"
    chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${UF_HOME}"

    cat > "${UF_HOME}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = ${SPLUNK_ADMIN_USER}
PASSWORD = ${SPLUNK_ADMIN_PASSWORD}
EOF
    chmod 600 "${UF_HOME}/etc/system/local/user-seed.conf"
    chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${UF_HOME}/etc/system/local/user-seed.conf"

    sudo -u "${SPLUNK_USER}" "${UF_HOME}/bin/splunk" start \
        --accept-license --answer-yes --no-prompt
    "${UF_HOME}/bin/splunk" enable boot-start -user "${SPLUNK_USER}" \
        -systemd-managed 1 --accept-license --answer-yes --no-prompt
}

# The forwarder runs as an unprivileged user that cannot read auth.log or
# audit.log by default. The input is configured, splunkd reports no error, and
# the index simply stays empty - which is the single most common reason a
# Linux onboarding appears to succeed but produces no authentication data.
# Fixing it here makes the failure impossible rather than documented.
grant_log_access() {
    log "granting the splunk user read access to the monitored logs"
    usermod -aG adm "${SPLUNK_USER}" || true
    if getent group audit >/dev/null; then
        usermod -aG audit "${SPLUNK_USER}" || true
    fi
    # auditd's log is 0600 root:root on most distros - relax to group-read.
    if [[ -f /var/log/audit/audit.log ]]; then
        chgrp adm /var/log/audit/audit.log 2>/dev/null || true
        chmod 640 /var/log/audit/audit.log 2>/dev/null || true
        # Make it stick across log rotation.
        if [[ -f /etc/audit/auditd.conf ]]; then
            sed -i 's/^log_group.*/log_group = adm/' /etc/audit/auditd.conf || true
        fi
    fi
}

# --- Deploy configuration --------------------------------------------------
deploy_confs() {
    local src="${REPO_DIR}/forwarders/linux/etc/system/local"
    local dst="${UF_HOME}/etc/system/local"
    for f in inputs.conf outputs.conf deploymentclient.conf; do
        backup_once "${dst}/${f}"
        install -o "${SPLUNK_USER}" -g "${SPLUNK_GROUP}" -m 644 "${src}/${f}" "${dst}/${f}"
        sed -i "s/__INDEXER_HOST__/${INDEXER_HOST}/g; s/__S2S_PORT__/${INDEXER_S2S_PORT}/g" \
            "${dst}/${f}"
        log "  -> ${f}"
    done

    install -o "${SPLUNK_USER}" -g "${SPLUNK_GROUP}" -m 755 \
        "${REPO_DIR}/forwarders/linux/bin/linux_host_health.sh" \
        "${UF_HOME}/bin/linux_host_health.sh"

    # Declare the forwarding destination through the CLI as well, so it is
    # visible in `splunk list forward-server`.
    sudo -u "${SPLUNK_USER}" "${UF_HOME}/bin/splunk" add forward-server \
        "${INDEXER_HOST}:${INDEXER_S2S_PORT}" \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" 2>/dev/null || true
}

# --- Restart and confirm transmission --------------------------------------
restart_and_verify() {
    log "restarting the forwarder"
    sudo -u "${SPLUNK_USER}" "${UF_HOME}/bin/splunk" restart

    log "forward-server status:"
    sudo -u "${SPLUNK_USER}" "${UF_HOME}/bin/splunk" list forward-server \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" | sed 's/^/      /'

    log "monitored inputs:"
    sudo -u "${SPLUNK_USER}" "${UF_HOME}/bin/splunk" list monitor \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" | sed 's/^/      /'

    log "confirm on the indexer with:"
    echo "      index=linux host=$(hostname) | stats count by sourcetype"
}

install_uf
grant_log_access
deploy_confs
restart_and_verify
log "Linux Universal Forwarder configured against ${INDEXER_HOST}:${INDEXER_S2S_PORT}"
