#!/usr/bin/env python3
"""Normalize scanner output (SARIF, Nuclei JSONL, Brakeman JSON, ZAP JSON) into one common finding schema."""
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _sarif_level_to_severity(level, rule_props):
    for key in ("security-severity",):
        val = rule_props.get(key) if rule_props else None
        if val:
            try:
                score = float(val)
                if score >= 9:
                    return "CRITICAL"
                if score >= 7:
                    return "HIGH"
                if score >= 4:
                    return "MEDIUM"
                return "LOW"
            except ValueError:
                pass
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")


def _extract_cwe(tags):
    for tag in tags or []:
        if tag.upper().startswith("CWE-"):
            return tag.upper()
    return "CWE-UNKNOWN"


def parse_sarif(path, tool_name):
    data = json.loads(Path(path).read_text())
    findings = []
    for run in data.get("runs", []):
        rules = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rules[rule.get("id")] = rule
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            tags = props.get("tags", [])
            level = result.get("level", "warning")
            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            file_path = loc.get("artifactLocation", {}).get("uri", "unknown")
            line = loc.get("region", {}).get("startLine", 0)
            message = result.get("message", {}).get("text", "")
            findings.append({
                "tool": tool_name,
                "cwe": _extract_cwe(tags),
                "severity": _sarif_level_to_severity(level, props),
                "file": file_path,
                "line": line,
                "rule_id": rule_id,
                "description": message,
            })
    return findings


def parse_nuclei_jsonl(path):
    findings = []
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return findings
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        info = rec.get("info", {})
        sev = info.get("severity", "info").upper()
        findings.append({
            "tool": "nuclei",
            "cwe": "CWE-UNKNOWN",
            "severity": sev if sev in SEVERITY_ORDER else "INFO",
            "file": rec.get("matched-at", rec.get("host", "unknown")),
            "line": 0,
            "rule_id": info.get("name", rec.get("template-id", "")),
            "description": info.get("description", info.get("name", "")),
        })
    return findings


def parse_brakeman(path):
    data = json.loads(Path(path).read_text())
    findings = []
    conf_map = {"High": "HIGH", "Medium": "MEDIUM", "Weak": "LOW"}
    for w in data.get("warnings", []):
        findings.append({
            "tool": "brakeman",
            "cwe": f"CWE-{w['cwe_id'][0]}" if w.get("cwe_id") else "CWE-UNKNOWN",
            "severity": conf_map.get(w.get("confidence", "Medium"), "MEDIUM"),
            "file": w.get("file", "unknown"),
            "line": w.get("line", 0),
            "rule_id": w.get("warning_type", ""),
            "description": w.get("message", ""),
        })
    return findings


def parse_zap(path):
    data = json.loads(Path(path).read_text())
    findings = []
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances", [{}])
            findings.append({
                "tool": "zap",
                "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") not in (None, "-1") else "CWE-UNKNOWN",
                "severity": risk_map.get(str(alert.get("riskcode", "1")), "LOW"),
                "file": instances[0].get("uri", "unknown"),
                "line": 0,
                "rule_id": alert.get("name", ""),
                "description": alert.get("desc", ""),
            })
    return findings


PARSERS = {
    "semgrep-sarif": lambda p: parse_sarif(p, "semgrep"),
    "trivy-sarif": lambda p: parse_sarif(p, "trivy"),
    "nuclei-jsonl": parse_nuclei_jsonl,
    "brakeman-json": parse_brakeman,
    "zap-json": parse_zap,
}


def main():
    """Args: pairs of <parser-key>=<file-path>. Writes normalized findings JSON array to stdout."""
    all_findings = []
    for arg in sys.argv[1:]:
        key, _, path = arg.partition("=")
        parser = PARSERS.get(key)
        if not parser:
            print(f"::warning::unknown parser key '{key}', skipping", file=sys.stderr)
            continue
        if not Path(path).exists():
            continue
        try:
            all_findings.extend(parser(path))
        except Exception as e:
            print(f"::warning::failed to parse {path} as {key}: {e}", file=sys.stderr)
    json.dump(all_findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
