#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Configures Splunk DB Connect to pull application and database audit tables
# into the SIEM.
#
# Why bother, when the OS logs are already here: an account failing
# authentication at both the OS and the application layer is a materially
# stronger signal than either alone, and database privilege changes have no
# OS-level equivalent at all.
#
# DB Connect itself must be installed from Splunkbase first - it requires a
# login, so it cannot be fetched unattended.
#
#   sudo ./06_setup_dbconnect.sh
# ---------------------------------------------------------------------------
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00_common.sh"
require_root

DBX_HOME="${SPLUNK_HOME}/etc/apps/splunk_app_db_connect"
DRIVERS="${DBX_HOME}/drivers"
MYSQL_DRIVER_VERSION="8.4.0"

# --- 1a. DB Connect app -----------------------------------------------------
check_dbx() {
    if [[ -d "${DBX_HOME}" ]]; then
        log "DB Connect present at ${DBX_HOME}"
        return
    fi
    warn "Splunk DB Connect is not installed."
    warn "  It is a Splunkbase app and requires a login, so it cannot be fetched"
    warn "  unattended. Install it, then re-run this script:"
    warn "    1. https://splunkbase.splunk.com/app/2686  (Splunk DB Connect)"
    warn "    2. Splunk Web > Apps > Manage Apps > Install app from file"
    warn "    3. or: ${SPLUNK_HOME}/bin/splunk install app /path/to/splunk-db-connect.tgz"
    die "DB Connect missing"
}

# --- 1b. Java + JDBC drivers ------------------------------------------------
check_java() {
    if command -v java >/dev/null 2>&1; then
        log "java found: $(java -version 2>&1 | head -1)"
    else
        log "installing OpenJDK 11 (DB Connect requires a JRE)"
        apt-get update -qq && apt-get install -y openjdk-11-jre-headless
    fi
    local java_home
    java_home=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")
    mkdir -p "${DBX_HOME}/local"
    cat > "${DBX_HOME}/local/dbx_settings.conf" <<EOF
[java]
javaHome = ${java_home}

[task_server]
# Cap the JVM so the DB Connect task server does not compete with splunkd
# for memory on a modest indexer.
jvmOptions = -Xmx512m -Xms256m
EOF
    chown -R "${SPLUNK_USER}:${SPLUNK_GROUP}" "${DBX_HOME}/local"
    log "JAVA_HOME set to ${java_home}"
}

install_mysql_driver() {
    mkdir -p "${DRIVERS}"
    if ls "${DRIVERS}"/mysql-connector-*.jar >/dev/null 2>&1; then
        log "MySQL JDBC driver already present"
        return
    fi
    local jar="mysql-connector-j-${MYSQL_DRIVER_VERSION}.jar"
    local url="https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/${MYSQL_DRIVER_VERSION}/${jar}"
    log "downloading MySQL Connector/J ${MYSQL_DRIVER_VERSION}"
    curl -fL -o "${DRIVERS}/${jar}" "${url}"
    chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${DRIVERS}/${jar}"
    chmod 644 "${DRIVERS}/${jar}"
}

install_mssql_driver() {
    if ls "${DRIVERS}"/mssql-jdbc-*.jar >/dev/null 2>&1; then
        log "MS SQL JDBC driver already present"
        return
    fi
    local ver="12.6.1.jre11"
    local jar="mssql-jdbc-${ver}.jar"
    local url="https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/${ver}/${jar}"
    log "downloading MS SQL JDBC driver ${ver}"
    curl -fL -o "${DRIVERS}/${jar}" "${url}" || \
        warn "MS SQL driver download failed - the SQL Server input stays disabled anyway"
    [[ -f "${DRIVERS}/${jar}" ]] && chown "${SPLUNK_USER}:${SPLUNK_GROUP}" "${DRIVERS}/${jar}"
}

# --- 2. connections + scheduled inputs -------------------------------------
deploy_dbx_conf() {
    log "deploying DB Connect configuration"
    mkdir -p "${DBX_HOME}/local"
    for f in db_connection_types.conf db_connections.conf db_inputs.conf; do
        backup_once "${DBX_HOME}/local/${f}"
        install -o "${SPLUNK_USER}" -g "${SPLUNK_GROUP}" -m 644 \
            "${REPO_DIR}/dbconnect/${f}" "${DBX_HOME}/local/${f}"
        sed -i "s/192\.168\.150\.140/${MYSQL_HOST}/g; s/192\.168\.150\.141/${MSSQL_HOST}/g" \
            "${DBX_HOME}/local/${f}"
        log "  -> ${f}"
    done
}

# Provision the identity through REST so the password is encrypted by splunkd
# and never written to disk in plaintext by this script.
provision_identity() {
    log "provisioning the mysql_splunk_ro identity via REST"
    curl -ks -u "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASSWORD}" \
        "https://127.0.0.1:${SPLUNK_MGMT_PORT}/servicesNS/nobody/splunk_app_db_connect/db_connect/identities" \
        -d "name=mysql_splunk_ro" \
        -d "username=${MYSQL_USER}" \
        --data-urlencode "password=${MYSQL_PASSWORD}" \
        >/dev/null && log "  identity created" || \
        warn "  identity may already exist - check Configuration > Databases > Identities"
}

# --- 3. validation ---------------------------------------------------------
validate() {
    log "testing TCP reachability before blaming DB Connect"
    if timeout 5 bash -c "</dev/tcp/${MYSQL_HOST}/${MYSQL_PORT}" 2>/dev/null; then
        log "  MySQL ${MYSQL_HOST}:${MYSQL_PORT} reachable"
    else
        warn "  MySQL ${MYSQL_HOST}:${MYSQL_PORT} NOT reachable"
    fi
    if timeout 5 bash -c "</dev/tcp/${MSSQL_HOST}/${MSSQL_PORT}" 2>/dev/null; then
        log "  SQL Server ${MSSQL_HOST}:${MSSQL_PORT} reachable"
        log "  set 'disabled = 0' on [mssql_secdb] and [mssql_security_events] to enable it."
    else
        warn "  SQL Server ${MSSQL_HOST}:${MSSQL_PORT} NOT reachable"
        warn "  The [mssql_*] stanzas ship disabled; leave them that way until"
        warn "  this test passes. Check, in order: the host firewall, whether"
        warn "  the TCP/IP protocol is enabled in SQL Server Configuration"
        warn "  Manager (off by default), and whether this is a named instance"
        warn "  on a dynamic port rather than 1433."
    fi

    log "restarting Splunk to load DB Connect configuration"
    splunk_cmd "${SPLUNK_HOME}" restart

    log "verify ingestion after one input interval with:"
    echo "      index=db_input | stats count by sourcetype, host"
    log "and the cross-layer correlation the database input exists for:"
    echo "      (index=db_input sourcetype=mysql:auth_events result=FAILED)"
    echo "        OR (index=linux sourcetype=linux_secure \"Failed password\")"
    echo "      | eval src=coalesce(source_ip, src)"
    echo "      | stats dc(sourcetype) AS surfaces, count AS attempts BY src"
    echo "      | where surfaces > 1"
}

check_dbx
check_java
install_mysql_driver
install_mssql_driver
deploy_dbx_conf
provision_identity
validate
log "DB Connect configuration complete (MySQL enabled, SQL Server disabled)."
