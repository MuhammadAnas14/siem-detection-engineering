# Splunk SIEM Deployment

A complete, deployable Splunk SIEM: log collection from Windows and Linux
endpoints, 19 correlation rules mapped to MITRE ATT&CK, SOC dashboards, and
the platform-health monitoring that keeps the whole thing honest.

Everything is scripted and idempotent. Re-running a deploy re-applies
configuration rather than duplicating it, so this is usable both for a first
build and for pushing a content change to a running system.

## Quick start

```bash
cd install
cp splunk.env.example splunk.env && chmod 600 splunk.env
$EDITOR splunk.env                      # indexer address, admin password, SOC email

# on the Splunk host
sudo ./01_install_splunk_enterprise.sh
sudo ./04_create_indexes.sh
sudo ./05_deploy_app.sh
sudo ./06_setup_dbconnect.sh            # optional: database inputs

# on each endpoint
sudo ./02_install_uf_linux.sh
.\03_install_uf_windows.ps1             # elevated PowerShell

# confirm it works
sudo ../validation/validate_deployment.sh
```

Then open `https://<indexer>:8000/en-US/app/siem_core/soc_overview`.

`make lint` runs anywhere without Splunk installed and is the fast feedback
loop while editing detection content.

## Layout

```
install/            Deployment automation, run in numbered order
  splunk.env        All environment-specific values (gitignored)
indexer/            Indexer-side configuration: indexes, inputs, TLS, limits
forwarders/         Per-OS agent configuration and host-health scripted inputs
apps/siem_core/     Detection content, dashboards, parsing, ATT&CK mapping
dbconnect/          JDBC connections and scheduled table inputs
validation/         Post-deploy health check and inert rule-test harnesses
scripts/            Offline config linter used by `make lint`
```

## Detection content

19 detection rules plus 4 platform-health rules, in
`apps/siem_core/default/savedsearches.conf`.

| Rule | Detects | Tactic | Severity |
|---|---|---|---|
| UC-01 | Windows brute force, escalating on a successful logon | Credential Access | medium→high |
| UC-02 | SSH brute force, escalating on a successful logon | Credential Access | medium→high |
| UC-03 | Administrative privileges assigned to a user account | Privilege Escalation | medium |
| UC-04 | Permission changes on protected system paths | Defense Evasion | medium |
| UC-05 | PowerShell combining two or more abuse indicators | Execution | high |
| UC-06 | Service installed from outside system directories | Persistence | high |
| UC-07 | Endpoint malware detection without remediation | Execution | high |
| UC-08 | Repeated authentication failures / password spraying | Credential Access | medium |
| UC-09 | DNS tunnelling by label entropy and query volume | Exfiltration | high |
| UC-10 | certutil used to download or decode payloads | Defense Evasion | high |
| UC-11 | Admin-share access across multiple hosts | Lateral Movement | medium→high |
| UC-12 | Account added to a privileged group | Privilege Escalation | high |
| UC-13 | Ransomware: known extensions or mass file rewrite | Impact | critical |
| UC-14 | Audit log cleared or audit policy changed | Defense Evasion | critical |
| UC-15 | SQL injection patterns in web request payloads | Initial Access | high |
| UC-16 | Offensive PowerShell framework indicators | Command and Control | critical |
| UC-17 | Root session opened or closed | Privilege Escalation | high |
| UC-18 | Registry persistence key modified | Persistence | medium |
| UC-19 | Host shutdown or unexpected restart | Impact | low→high |
| OPS-01…04 | Forwarder silence, ingestion volume, licence pressure, skipped rules | — | — |

Coverage is 9 of the 14 ATT&CK Enterprise tactics across 18 techniques. The
gaps — Reconnaissance, Resource Development, Discovery, Collection — are
telemetry problems rather than detection problems, and the MITRE dashboard
computes them live from the mapping lookup rather than from a stale list.

### Design decisions worth knowing

**Severity reflects confirmed impact, not pattern matches.** UC-01 and UC-02
correlate failed logons with a subsequent success in the same window. Counting
failures alone finds every mistyped password; correlating them is what
separates "someone is guessing" from "someone got in".

**Indicators are scored, not matched individually.** The PowerShell rules
score six independent indicators and fire on two or more. Any one flag has
legitimate uses — installers run with `-noprofile`, management scripts
download files — so matching them singly produces noise the SOC learns to
ignore.

**Behaviour over signatures where it generalises.** UC-13 catches known
ransomware extensions *and* the structural behaviour — one process rewriting
100+ distinct files into few extensions in five minutes — because the families
whose extensions nobody has published yet are the ones that matter.

**Rules go through macros, not literal index names.** Re-pointing the estate,
splitting an index or onboarding a new one is a single edit in `macros.conf`
rather than a sweep through 23 saved searches.

**Suppression is keyed on identity.** Each rule declares the fields that make
two alerts "the same thing", so a sustained attack produces one actionable
alert rather than a thousand.

## Platform health

A SIEM fails silently: dashboards keep rendering and rules keep showing as
enabled while no data arrives and nothing executes. Three things guard that:

- **OPS-01** alerts when a host that was reporting goes quiet.
- **OPS-04** alerts when the scheduler skips a rule — the failure where a rule
  is enabled in the UI but never actually runs. `limits.conf` is tuned to
  prevent it; OPS-04 catches it when the tuning is wrong.
- **validate_deployment.sh** checks ports, per-index ingestion, rule
  execution, scheduler skips, dashboards and ATT&CK mapping completeness,
  exiting non-zero so it can gate a pipeline.

## Dashboards

| View | Answers |
|---|---|
| SOC Overview | What is happening now, and what to triage first |
| Use Case Catalog | Which rules exist, are enabled, and have actually fired |
| MITRE ATT&CK Coverage | What is detected, what is not, where the gaps are |
| Forwarder Health | Is data still arriving, from what, on which agent version |
| System Health | Capacity, licence, index growth, scheduler health |

## Prerequisites

| Component | Requirement |
|---|---|
| Splunk host | 4 vCPU, 8 GB RAM, 200 GB disk; Debian/Ubuntu |
| Endpoints | Universal Forwarder; Windows Server 2019+ or Win 10+, any supported Linux |
| Network | Endpoints reach the indexer on 9997/tcp; analysts reach 8000/tcp |
| Optional | Sysmon for richer process telemetry; DB Connect for database inputs |

The Windows installer enables the audit subcategories and PowerShell Script
Block Logging that several detections depend on. Without them those rules
deploy and enable cleanly but can never fire, because the events they match
are never written. The Linux installer grants the forwarder's service account
read access to `auth.log` and `audit.log` for the same reason.

## Verifying detections

Deploying a rule is not evidence it works. Two harnesses generate the patterns
the rules match:

```bash
sudo ./validation/simulate_attacks_linux.sh
.\validation\simulate_attacks_windows.ps1
.\validation\simulate_attacks_windows.ps1 -UseRealSecurityEvents
```

Both are test harnesses, not attack tools. The Linux one writes log lines with
`logger` and confines real file operations to `/tmp`. The Windows one writes
to a dedicated Application-log source and never installs a service, clears a
log, or executes a payload; `-UseRealSecurityEvents` produces genuine 4625
events via failed logons against a disabled throwaway account, which is what
actually exercises the deployed rule rather than just its SPL. Each script
documents its cleanup.

## Operations

**Tuning a rule.** Never edit `default/savedsearches.conf` on a live instance
— it is overwritten on redeploy. Either change it here and redeploy, or add an
override in `$SPLUNK_HOME/etc/apps/siem_core/local/savedsearches.conf`, which
survives. The usual knobs are `alert.suppress.period`,
`alert.suppress.fields`, and the thresholds in the SPL.

**Licence pressure.** `transforms.conf` already drops the highest-volume,
lowest-value Windows events (4634, 4658, 5156, 5158) at index time, which is
the single largest saving available on a Windows estate. Note that nullQueue
data is discarded, not hidden. To see what is actually consuming licence:

```spl
index=_internal source=*license_usage.log type=Usage
| stats sum(b) AS bytes BY idx, st
| eval GB=round(bytes/1024/1024/1024,3) | sort - GB
```

## Security

- `install/splunk.env` is gitignored and holds every credential; nothing
  tracked here contains a working password.
- Forwarder-to-indexer traffic and Splunk Web are TLS. Replace the
  self-signed certificates and set `sslVerifyServerCert = true` before
  treating the transport as trustworthy against an active attacker.
- DB Connect identities are provisioned over REST so splunkd encrypts them;
  `identities.conf.example` is a template and is never filled in.
- Database connections are read-only — a compromised SIEM should not become a
  path to altering the audit trail it reads.
- `authorize.conf` defines `soc_analyst` and `soc_engineer` so analysts triage
  without admin rights. The split matters: an analyst who can edit detections
  can also silence them.
