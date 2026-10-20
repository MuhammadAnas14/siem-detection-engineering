#!/usr/bin/env python3
"""
Structural checks over every .conf in this deployment.

Splunk's own `btool` only runs on an installed instance against
$SPLUNK_HOME; this catches the mistakes that matter before deployment:

  * malformed stanza headers and key = value lines
  * duplicate stanzas within one file (the second silently wins)
  * line continuations that dangle at EOF
  * saved searches missing a `search` or `description`
  * macros referenced by a saved search but never defined
  * rule_ids used in savedsearches.conf but absent from the ATT&CK lookup
  * index names referenced by a forwarder inputs.conf but never created

Exit status is non-zero if any ERROR is found; warnings do not fail the build.
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "apps" / "siem_core"

errors: list[str] = []
warnings: list[str] = []


def err(path: Path, line: int | None, msg: str) -> None:
    loc = f"{path.relative_to(ROOT)}" + (f":{line}" if line else "")
    errors.append(f"ERROR {loc}: {msg}")


def warn(path: Path, line: int | None, msg: str) -> None:
    loc = f"{path.relative_to(ROOT)}" + (f":{line}" if line else "")
    warnings.append(f"WARN  {loc}: {msg}")


STANZA_RE = re.compile(r"^\[(?P<name>.*)\]\s*$")
KV_RE = re.compile(r"^(?P<key>[^=\[\s][^=]*?)\s*=\s*(?P<value>.*)$")


def parse_conf(path: Path) -> dict[str, dict[str, str]]:
    """Parse a Splunk .conf file, honouring backslash line continuations."""
    stanzas: dict[str, dict[str, str]] = {}
    current: str | None = None
    seen_stanzas: set[str] = set()

    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()

    # Join continuation lines first, remembering the starting line number.
    joined: list[tuple[int, str]] = []
    buf, start = "", 0
    for idx, line in enumerate(raw, 1):
        stripped = line.rstrip("\n")
        if buf:
            buf = buf[:-1] + stripped.strip()
        else:
            start, buf = idx, stripped
        if buf.endswith("\\"):
            continue
        joined.append((start, buf))
        buf = ""
    if buf:
        err(path, start, "file ends with a dangling line continuation (trailing backslash)")
        joined.append((start, buf.rstrip("\\")))

    for lineno, line in joined:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = STANZA_RE.match(s)
        if m:
            current = m.group("name")
            if current in seen_stanzas:
                err(path, lineno, f"duplicate stanza [{current}] - the later one silently wins")
            seen_stanzas.add(current)
            stanzas.setdefault(current, {})
            continue
        if current is None:
            err(path, lineno, f"key outside any stanza: {s[:60]}")
            continue
        kv = KV_RE.match(s)
        if not kv:
            err(path, lineno, f"not a stanza or key = value: {s[:60]}")
            continue
        stanzas[current][kv.group("key").strip()] = kv.group("value").strip()

    return stanzas


def check_savedsearches(path: Path) -> tuple[set[str], set[str]]:
    """Return (rule_ids, macros_used)."""
    stanzas = parse_conf(path)
    rule_ids: set[str] = set()
    macros: set[str] = set()

    for name, kv in stanzas.items():
        if name == "default":
            continue
        if "search" not in kv:
            err(path, None, f"[{name}] has no `search` attribute")
        if "description" not in kv:
            warn(path, None, f"[{name}] has no `description`")

        m = re.match(r"^((?:UC|OPS)-\d+)", name)
        if m:
            rule_ids.add(m.group(1))
        else:
            warn(path, None, f"[{name}] title does not start with a UC-/OPS- rule id")

        spl = kv.get("search", "")
        macros.update(re.findall(r"`([a-z_]+)(?:\(\d*\))?`", spl))

        # An alert with a threshold must say what to compare.
        if kv.get("alert_type") == "number of events" and "alert_comparator" not in kv:
            warn(path, None, f"[{name}] sets alert_type without alert_comparator")

        # Real-time stanzas need a cron_schedule too, or the scheduler ignores them.
        if "rt-" in kv.get("dispatch.earliest_time", "") and "cron_schedule" not in kv:
            err(path, None, f"[{name}] is real-time but has no cron_schedule")

    return rule_ids, macros


def main() -> int:
    conf_files = sorted(
        p for p in ROOT.rglob("*.conf")
        if ".git" not in p.parts and p.name != "splunk.env"
    )
    if not conf_files:
        print("no .conf files found", file=sys.stderr)
        return 1

    for p in conf_files:
        parse_conf(p)

    # --- saved searches, macros, MITRE coverage -----------------------------
    ss_path = APP / "default" / "savedsearches.conf"
    rule_ids, macros_used = check_savedsearches(ss_path)

    macro_path = APP / "default" / "macros.conf"
    defined = {re.sub(r"\(\d+\)$", "", n) for n in parse_conf(macro_path)}
    for m in sorted(macros_used - defined):
        err(ss_path, None, f"macro `{m}` is used but not defined in macros.conf")

    lookup = APP / "lookups" / "mitre_attack_lookup.csv"
    with lookup.open(newline="", encoding="utf-8") as fh:
        mapped = {row["rule_id"] for row in csv.DictReader(fh)}
    for rid in sorted(rule_ids - mapped):
        err(lookup, None, f"rule {rid} has no row in the ATT&CK lookup")
    for rid in sorted(mapped - rule_ids):
        warn(lookup, None, f"lookup row {rid} has no matching saved search")

    # --- indexes referenced vs created --------------------------------------
    idx_conf = ROOT / "indexer" / "etc" / "system" / "local" / "indexes.conf"
    created = {n for n in parse_conf(idx_conf) if not n.startswith(("default", "volume"))}
    for fwd in ROOT.glob("forwarders/*/etc/system/local/inputs.conf"):
        for stanza, kv in parse_conf(fwd).items():
            idx = kv.get("index")
            if idx and idx not in created:
                err(fwd, None, f"[{stanza}] targets index '{idx}' which indexes.conf never creates")

    # --- report ------------------------------------------------------------
    for w in warnings:
        print(w)
    for e in errors:
        print(e, file=sys.stderr)

    print(
        f"\nchecked {len(conf_files)} conf files, {len(rule_ids)} rules, "
        f"{len(defined)} macros, {len(created)} indexes "
        f"-> {len(errors)} error(s), {len(warnings)} warning(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
