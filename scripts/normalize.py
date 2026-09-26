#!/usr/bin/env python3
"""Normalize scanner output (SARIF, Nuclei JSONL, Brakeman JSON, ZAP JSON) into one common finding schema."""
import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Scanner descriptions are unbounded (Trivy embeds full CVE prose). They end up
# verbatim in the Gemini prompt, so clamp them here rather than at prompt time.
MAX_DESCRIPTION = 1000
MAX_FIELD = 500

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def _clean(value, limit=MAX_FIELD):
    """Coerce a scanner-supplied value to a bounded single-line string."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    # Scanner output is attacker-influenceable (it echoes source code and URLs).
    # Strip control characters so a finding cannot forge log lines or workflow
    # commands when the normalized JSON is cat'd into the Actions log.
    value = "".join(ch for ch in value if ch == "\t" or ch >= " ")
    value = value.strip()
    if len(value) > limit:
        value = value[: limit - 1] + "…"
    return value


def _coerce_line(value):
    try:
        line = int(value)
    except (TypeError, ValueError):
        return 0
    return line if line >= 0 else 0


def _normalize_cwe(value):
    """Return a bare 'CWE-<number>' from any scanner spelling, else CWE-UNKNOWN.

    Semgrep tags look like "CWE-89: Improper Neutralization of ...", so a raw
    startswith() check leaks the whole prose into the id and defeats grouping.
    """
    if value is None:
        return "CWE-UNKNOWN"
    text = str(value).strip()
    # ZAP's `cweid` and Brakeman's `cwe_id` are bare numbers ("79", 89) with no
    # "CWE" prefix at all, so check for that form before the prefixed one.
    if text.isdigit():
        return "CWE-UNKNOWN" if int(text) <= 0 else f"CWE-{int(text)}"
    match = CWE_RE.search(text)
    return f"CWE-{match.group(1)}" if match else "CWE-UNKNOWN"


def _extract_cwe(tags):
    for tag in tags or []:
        cwe = _normalize_cwe(tag)
        if cwe != "CWE-UNKNOWN":
            return cwe
    return "CWE-UNKNOWN"


def _sarif_level_to_severity(level, rule_props):
    val = (rule_props or {}).get("security-severity")
    if val is not None:
        try:
            score = float(val)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9:
                return "CRITICAL"
            if score >= 7:
                return "HIGH"
            if score >= 4:
                return "MEDIUM"
            return "LOW"
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")


def _finding(tool, cwe, severity, file_path, line, rule_id, description):
    """Build a schema-conformant finding, clamping every scanner-supplied field."""
    severity = severity if severity in SEVERITY_RANK else "MEDIUM"
    return {
        "tool": tool,
        "cwe": cwe,
        "severity": severity,
        "file": _clean(file_path) or "unknown",
        "line": _coerce_line(line),
        "rule_id": _clean(rule_id),
        "description": _clean(description, MAX_DESCRIPTION),
    }


def _load_json(path):
    data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object at top level, got {type(data).__name__}")
    return data


def _as_list(value):
    return value if isinstance(value, list) else []


def parse_sarif(path, tool_name):
    data = _load_json(path)
    findings = []
    for run in _as_list(data.get("runs")):
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {
            rule.get("id"): rule
            for rule in _as_list(driver.get("rules"))
            if isinstance(rule, dict)
        }
        for result in _as_list(run.get("results")):
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId") or ""
            rule = rules.get(rule_id) or {}
            props = rule.get("properties") or {}
            tags = props.get("tags")
            level = result.get("level", "warning")
            locations = _as_list(result.get("locations"))
            loc = (locations[0] if locations and isinstance(locations[0], dict) else {})
            physical = loc.get("physicalLocation") or {}
            file_path = (physical.get("artifactLocation") or {}).get("uri", "unknown")
            line = (physical.get("region") or {}).get("startLine", 0)
            message = (result.get("message") or {}).get("text", "")
            # Trivy carries the CWE on the rule's properties, Semgrep on its tags.
            cwe = _extract_cwe(tags)
            if cwe == "CWE-UNKNOWN":
                cwe = _extract_cwe(_as_list(props.get("cwe_id")))
            findings.append(
                _finding(tool_name, cwe, _sarif_level_to_severity(level, props),
                         file_path, line, rule_id, message)
            )
    return findings


def parse_nuclei_jsonl(path):
    findings = []
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return findings
    text = p.read_text(encoding="utf-8", errors="replace")
    # Nuclei writes JSONL, but -json (not -jsonl) emits a single JSON array.
    # Accept both rather than dropping every finding on a flag mismatch.
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            records = _as_list(json.loads(stripped))
        except json.JSONDecodeError as e:
            print(f"::warning::nuclei: not valid JSON array: {e}", file=sys.stderr)
            records = []
    else:
        records = []
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                # One truncated line (a killed scan) must not discard the rest.
                print(f"::warning::nuclei: skipping malformed line {lineno}: {e}", file=sys.stderr)

    for rec in records:
        if not isinstance(rec, dict):
            continue
        info = rec.get("info") or {}
        sev = str(info.get("severity", "info")).upper()
        findings.append(
            _finding("nuclei", _normalize_cwe((info.get("classification") or {}).get("cwe-id")),
                     sev if sev in SEVERITY_RANK else "INFO",
                     rec.get("matched-at") or rec.get("host") or "unknown", 0,
                     info.get("name") or rec.get("template-id") or "",
                     info.get("description") or info.get("name") or "")
        )
    return findings


def parse_brakeman(path):
    data = _load_json(path)
    findings = []
    conf_map = {"High": "HIGH", "Medium": "MEDIUM", "Weak": "LOW"}
    for w in _as_list(data.get("warnings")):
        if not isinstance(w, dict):
            continue
        cwe_id = w.get("cwe_id")
        # Brakeman emits a list, but older/other versions emit a bare int.
        cwe = _extract_cwe(cwe_id) if isinstance(cwe_id, list) else _normalize_cwe(cwe_id)
        findings.append(
            _finding("brakeman", cwe, conf_map.get(w.get("confidence"), "MEDIUM"),
                     w.get("file"), w.get("line"), w.get("warning_type"), w.get("message"))
        )
    return findings


def parse_zap(path):
    data = _load_json(path)
    findings = []
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in _as_list(data.get("site")):
        if not isinstance(site, dict):
            continue
        for alert in _as_list(site.get("alerts")):
            if not isinstance(alert, dict):
                continue
            instances = _as_list(alert.get("instances"))
            first = instances[0] if instances and isinstance(instances[0], dict) else {}
            # An alert with an explicit empty instances[] is common on
            # passive-scan-only runs; fall back to the site rather than crash.
            uri = first.get("uri") or site.get("@name") or "unknown"
            cweid = alert.get("cweid")
            cwe = "CWE-UNKNOWN" if str(cweid) in ("None", "-1", "0", "") else _normalize_cwe(cweid)
            findings.append(
                _finding("zap", cwe, risk_map.get(str(alert.get("riskcode", "1")), "LOW"),
                         uri, 0, alert.get("name"), alert.get("desc"))
            )
    return findings


PARSERS = {
    "semgrep-sarif": lambda p: parse_sarif(p, "semgrep"),
    "trivy-sarif": lambda p: parse_sarif(p, "trivy"),
    "sarif": lambda p: parse_sarif(p, "sarif"),
    "nuclei-jsonl": parse_nuclei_jsonl,
    "brakeman-json": parse_brakeman,
    "zap-json": parse_zap,
}


def dedupe(findings):
    """Collapse identical findings, keeping the highest severity seen.

    Two tools reporting the same CWE at the same file:line is the common case
    (Semgrep and Trivy overlap heavily); merging here means the prompt carries
    one row with both tool names instead of paying tokens for near-duplicates.
    """
    merged = {}
    for f in findings:
        key = (f["cwe"], f["file"], f["line"], f["rule_id"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(f, tools=[f["tool"]])
            continue
        if SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[existing["severity"]]:
            existing["severity"] = f["severity"]
        if f["tool"] not in existing["tools"]:
            existing["tools"].append(f["tool"])
    out = []
    for f in merged.values():
        tools = sorted(f.pop("tools"))
        f["tool"] = ",".join(tools)
        out.append(f)
    out.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["cwe"], f["file"], f["line"]))
    return out


def read_args_file(path):
    """Read NUL-delimited <parser-key>=<file-path> entries.

    The workflow passes arguments this way rather than interpolating them into
    a shell command line: entries derive from artifact contents, so paths can
    contain spaces, newlines, quotes, or shell metacharacters.
    """
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    return [entry for entry in raw.split("\0") if entry.strip()]


# States the workflow's fetch step can record for a manifest entry, plus
# "failed", which only a scan-status.json with a non-zero exit can produce.
FETCH_STATES = {"ok", "empty", "missing"}
STATUS_RE = re.compile(r"[a-z0-9-]{1,64}")
ARTIFACT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def read_status_file(path):
    """Read a scan-status.json written by one of this repo's scan workflows.

    Returns {"tool", "exit_code"} or None. The file travels inside an
    artifact, so everything in it is validated rather than trusted.
    """
    try:
        data = _load_json(path)
    except (OSError, ValueError) as e:
        print(f"::warning::ignoring unreadable scan status {path}: {e}", file=sys.stderr)
        return None
    code = data.get("exit_code")
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    tool = _clean(data.get("tool"), 64)
    return {"tool": tool if STATUS_RE.fullmatch(tool or "") else "", "exit_code": code}


def summarize_scan_status(entries):
    """Turn fetch-step records into one status row per manifest entry.

    Each entry is "<parser-key>=<artifact>=<state>=<status-file-or-empty>".
    A scanner that exited non-zero is "failed" even if it left partial
    output, so the report never presents a crashed scan as a clean one.
    """
    rows = []
    for entry in entries:
        parts = entry.split("=", 3)
        if len(parts) != 4:
            print(f"::warning::ignoring malformed status record {entry[:80]!r}", file=sys.stderr)
            continue
        key, artifact, state, status_path = parts
        if not (STATUS_RE.fullmatch(key) and ARTIFACT_RE.fullmatch(artifact)
                and state in FETCH_STATES):
            print(f"::warning::ignoring invalid status record {entry[:80]!r}", file=sys.stderr)
            continue
        row = {"parser": key, "artifact": artifact, "state": state, "tool": "", "exit_code": None}
        if status_path and Path(status_path).is_file():
            status = read_status_file(status_path)
            if status:
                row["tool"] = status["tool"]
                row["exit_code"] = status["exit_code"]
                if status["exit_code"] != 0:
                    row["state"] = "failed"
        rows.append(row)
    return rows


def main():
    """Args: pairs of <parser-key>=<file-path>, or --args-file <nul-delimited-file>.

    Optionally --status-args-file <nul-delimited-file> --status-out <path>
    writes a per-artifact scanner status summary alongside the findings.
    Writes the normalized findings JSON array to stdout.
    """
    argv = sys.argv[1:]
    options = {}
    while argv and argv[0] in ("--args-file", "--status-args-file", "--status-out"):
        if len(argv) < 2:
            print("usage: normalize.py [--args-file <path>] "
                  "[--status-args-file <path> --status-out <path>] [key=path ...]", file=sys.stderr)
            sys.exit(2)
        options[argv[0]] = argv[1]
        argv = argv[2:]
    if ("--status-args-file" in options) != ("--status-out" in options):
        print("usage: --status-args-file and --status-out must be given together", file=sys.stderr)
        sys.exit(2)

    if "--args-file" in options:
        if argv:
            print("usage: normalize.py --args-file <path> takes no key=path arguments", file=sys.stderr)
            sys.exit(2)
        try:
            argv = read_args_file(options["--args-file"])
        except OSError as e:
            print(f"::warning::cannot read args file {options['--args-file']}: {e}", file=sys.stderr)
            argv = []

    if "--status-args-file" in options:
        try:
            status_entries = read_args_file(options["--status-args-file"])
        except OSError as e:
            print(f"::warning::cannot read status args file: {e}", file=sys.stderr)
            status_entries = []
        rows = summarize_scan_status(status_entries)
        Path(options["--status-out"]).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        for row in rows:
            print(f"scanner status: {row['artifact']} ({row['parser']}) {row['state']}", file=sys.stderr)

    all_findings = []
    for arg in argv:
        key, sep, path = arg.partition("=")
        if not sep or not path:
            print(f"::warning::ignoring malformed argument '{arg}' (expected key=path)", file=sys.stderr)
            continue
        parser = PARSERS.get(key)
        if not parser:
            print(f"::warning::unknown parser key '{key}', skipping", file=sys.stderr)
            continue
        if not Path(path).is_file():
            continue
        try:
            parsed = parser(path)
        except Exception as e:
            print(f"::warning::failed to parse {path} as {key}: {e}", file=sys.stderr)
            continue
        print(f"parsed {len(parsed)} finding(s) from {path} as {key}", file=sys.stderr)
        all_findings.extend(parsed)

    findings = dedupe(all_findings)
    print(f"normalized {len(all_findings)} raw -> {len(findings)} deduped finding(s)", file=sys.stderr)
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
