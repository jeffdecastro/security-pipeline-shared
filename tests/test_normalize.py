#!/usr/bin/env python3
"""Unit tests for normalize.py. Run: python3 -m unittest discover -s tests -v"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import normalize  # noqa: E402


def write(tmpdir, name, content):
    p = Path(tmpdir) / name
    p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return str(p)


class TestCweNormalization(unittest.TestCase):
    def test_bare_and_prose_tags_reduce_to_id(self):
        # Semgrep tags carry prose after the id; the raw startswith() check
        # used to leak the whole string into the cwe field.
        self.assertEqual(normalize._normalize_cwe("CWE-89"), "CWE-89")
        self.assertEqual(
            normalize._normalize_cwe("CWE-89: Improper Neutralization of Special Elements"),
            "CWE-89",
        )
        self.assertEqual(normalize._normalize_cwe("cwe_79"), "CWE-79")
        self.assertEqual(normalize._normalize_cwe(89), "CWE-89")

    def test_non_cwe_values(self):
        self.assertEqual(normalize._normalize_cwe(None), "CWE-UNKNOWN")
        self.assertEqual(normalize._normalize_cwe("OWASP-A03"), "CWE-UNKNOWN")

    def test_extract_picks_first_real_cwe(self):
        self.assertEqual(normalize._extract_cwe(["security", "OWASP-A1", "CWE-22: Path Traversal"]), "CWE-22")
        self.assertEqual(normalize._extract_cwe([]), "CWE-UNKNOWN")
        self.assertEqual(normalize._extract_cwe(None), "CWE-UNKNOWN")


class TestSeverityMapping(unittest.TestCase):
    def test_security_severity_score_bands(self):
        band = lambda s: normalize._sarif_level_to_severity("warning", {"security-severity": s})
        self.assertEqual(band("9.8"), "CRITICAL")
        self.assertEqual(band("7.5"), "HIGH")
        self.assertEqual(band("5.0"), "MEDIUM")
        self.assertEqual(band("2.1"), "LOW")

    def test_non_numeric_score_falls_back_to_level(self):
        # A non-str/non-numeric value raised TypeError before (only ValueError
        # was caught), killing the whole SARIF file's findings.
        self.assertEqual(normalize._sarif_level_to_severity("error", {"security-severity": None}), "HIGH")
        self.assertEqual(normalize._sarif_level_to_severity("error", {"security-severity": []}), "HIGH")
        self.assertEqual(normalize._sarif_level_to_severity("note", {"security-severity": "n/a"}), "LOW")

    def test_level_fallback_and_default(self):
        self.assertEqual(normalize._sarif_level_to_severity("error", {}), "HIGH")
        self.assertEqual(normalize._sarif_level_to_severity("bogus", {}), "MEDIUM")


class TestSarifParser(unittest.TestCase):
    def test_parses_result_with_rule_metadata(self):
        sarif = {"runs": [{
            "tool": {"driver": {"rules": [
                {"id": "java.sqli", "properties": {"tags": ["CWE-89: SQL Injection"],
                                                   "security-severity": "9.1"}}]}},
            "results": [{"ruleId": "java.sqli", "level": "error",
                         "message": {"text": "SQLi"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "src/A.java"},
                             "region": {"startLine": 42}}}]}]}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_sarif(write(d, "a.sarif", sarif), "semgrep")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0], {"tool": "semgrep", "cwe": "CWE-89", "severity": "CRITICAL",
                                "file": "src/A.java", "line": 42, "rule_id": "java.sqli",
                                "description": "SQLi"})

    def test_result_without_locations_or_rule(self):
        sarif = {"runs": [{"tool": {"driver": {}}, "results": [{"ruleId": "orphan"}]}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_sarif(write(d, "a.sarif", sarif), "trivy")
        self.assertEqual(f[0]["file"], "unknown")
        self.assertEqual(f[0]["line"], 0)
        self.assertEqual(f[0]["severity"], "MEDIUM")

    def test_malformed_structures_do_not_crash(self):
        for bad in ({"runs": "not-a-list"},
                    {"runs": [{"results": "nope"}]},
                    {"runs": [{"results": ["a string", None]}]},
                    {"runs": [None]},
                    {}):
            with tempfile.TemporaryDirectory() as d:
                self.assertEqual(normalize.parse_sarif(write(d, "a.sarif", bad), "t"), [])

    def test_non_object_toplevel_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                normalize.parse_sarif(write(d, "a.sarif", [1, 2, 3]), "t")


class TestNucleiParser(unittest.TestCase):
    def test_jsonl_and_cwe_classification(self):
        lines = "\n".join(json.dumps(r) for r in [
            {"info": {"severity": "high", "name": "Exposed .env",
                      "classification": {"cwe-id": ["CWE-200"]}},
             "matched-at": "http://app/.env"},
            {"info": {"severity": "info", "name": "Tech detect"}, "host": "app"},
        ])
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_nuclei_jsonl(write(d, "n.jsonl", lines))
        self.assertEqual([x["severity"] for x in f], ["HIGH", "INFO"])
        self.assertEqual(f[0]["cwe"], "CWE-200")
        self.assertEqual(f[0]["file"], "http://app/.env")
        self.assertEqual(f[1]["file"], "app")

    def test_malformed_line_skipped_not_fatal(self):
        # A killed scan leaves a truncated last line; previously that raised
        # and discarded every finding in the file.
        content = json.dumps({"info": {"severity": "critical", "name": "RCE"}}) + "\n{ truncated"
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_nuclei_jsonl(write(d, "n.jsonl", content))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "CRITICAL")

    def test_json_array_form_accepted(self):
        recs = [{"info": {"severity": "medium", "name": "CORS"}, "host": "h"}]
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_nuclei_jsonl(write(d, "n.json", recs))
        self.assertEqual(len(f), 1)

    def test_empty_and_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(normalize.parse_nuclei_jsonl(write(d, "e.jsonl", "")), [])
            self.assertEqual(normalize.parse_nuclei_jsonl(str(Path(d) / "nope.jsonl")), [])

    def test_unknown_severity_becomes_info(self):
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_nuclei_jsonl(
                write(d, "n.jsonl", json.dumps({"info": {"severity": "unknown", "name": "x"}})))
        self.assertEqual(f[0]["severity"], "INFO")


class TestZapParser(unittest.TestCase):
    def test_alert_with_instances(self):
        data = {"site": [{"@name": "http://app", "alerts": [
            {"riskcode": "3", "cweid": "79", "name": "XSS", "desc": "Reflected XSS",
             "instances": [{"uri": "http://app/search"}]}]}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_zap(write(d, "z.json", data))
        self.assertEqual(f[0]["severity"], "HIGH")
        self.assertEqual(f[0]["cwe"], "CWE-79")
        self.assertEqual(f[0]["file"], "http://app/search")

    def test_empty_instances_list_does_not_crash(self):
        # `alert.get("instances", [{}])` returns [] when the key exists but is
        # empty, so instances[0] raised IndexError.
        data = {"site": [{"@name": "http://app", "alerts": [
            {"riskcode": "2", "cweid": "-1", "name": "Header", "desc": "d", "instances": []}]}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_zap(write(d, "z.json", data))
        self.assertEqual(f[0]["file"], "http://app")
        self.assertEqual(f[0]["cwe"], "CWE-UNKNOWN")
        self.assertEqual(f[0]["severity"], "MEDIUM")

    def test_riskcode_bands(self):
        alerts = [{"riskcode": str(rc), "name": f"a{rc}", "desc": "", "instances": [{"uri": "u"}]}
                  for rc in (3, 2, 1, 0)]
        data = {"site": [{"@name": "s", "alerts": alerts}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_zap(write(d, "z.json", data))
        self.assertEqual([x["severity"] for x in f], ["HIGH", "MEDIUM", "LOW", "INFO"])


class TestBrakemanParser(unittest.TestCase):
    def test_cwe_list_and_scalar_forms(self):
        data = {"warnings": [
            {"cwe_id": [89], "confidence": "High", "file": "app/a.rb", "line": 3,
             "warning_type": "SQL Injection", "message": "m"},
            {"cwe_id": 79, "confidence": "Weak", "file": "app/b.rb", "line": 9,
             "warning_type": "XSS", "message": "m"},
            {"confidence": "Medium", "file": "app/c.rb"},
        ]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_brakeman(write(d, "b.json", data))
        self.assertEqual([x["cwe"] for x in f], ["CWE-89", "CWE-79", "CWE-UNKNOWN"])
        self.assertEqual([x["severity"] for x in f], ["HIGH", "LOW", "MEDIUM"])
        self.assertEqual(f[2]["line"], 0)


class TestFieldClamping(unittest.TestCase):
    def test_long_description_truncated(self):
        long = "A" * 5000
        data = {"warnings": [{"cwe_id": [89], "confidence": "High", "file": "a.rb",
                              "line": 1, "warning_type": "T", "message": long}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_brakeman(write(d, "b.json", data))
        self.assertLessEqual(len(f[0]["description"]), normalize.MAX_DESCRIPTION)

    def test_control_characters_stripped(self):
        # A finding echoing source text must not be able to forge an Actions
        # workflow command when normalized JSON is printed to the log.
        data = {"warnings": [{"cwe_id": [89], "confidence": "High", "file": "a.rb", "line": 1,
                              "warning_type": "T", "message": "bad\n::error::forged\x00\x07"}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_brakeman(write(d, "b.json", data))
        self.assertNotIn("\n", f[0]["description"])
        self.assertNotIn("\x00", f[0]["description"])

    def test_negative_and_bogus_line_numbers(self):
        data = {"warnings": [{"confidence": "High", "file": "a.rb", "line": -5},
                             {"confidence": "High", "file": "b.rb", "line": "abc"}]}
        with tempfile.TemporaryDirectory() as d:
            f = normalize.parse_brakeman(write(d, "b.json", data))
        self.assertEqual([x["line"] for x in f], [0, 0])


class TestDedupeAndOrdering(unittest.TestCase):
    def test_same_finding_from_two_tools_merges(self):
        findings = [
            {"tool": "semgrep", "cwe": "CWE-89", "severity": "HIGH", "file": "a.java",
             "line": 10, "rule_id": "r1", "description": "d"},
            {"tool": "trivy", "cwe": "CWE-89", "severity": "CRITICAL", "file": "a.java",
             "line": 10, "rule_id": "r1", "description": "d"},
        ]
        out = normalize.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["tool"], "semgrep,trivy")
        self.assertEqual(out[0]["severity"], "CRITICAL")  # highest wins

    def test_distinct_findings_preserved_and_sorted_by_severity(self):
        findings = [
            {"tool": "t", "cwe": "CWE-1", "severity": "LOW", "file": "a", "line": 1,
             "rule_id": "r1", "description": ""},
            {"tool": "t", "cwe": "CWE-2", "severity": "CRITICAL", "file": "b", "line": 2,
             "rule_id": "r2", "description": ""},
            {"tool": "t", "cwe": "CWE-3", "severity": "MEDIUM", "file": "c", "line": 3,
             "rule_id": "r3", "description": ""},
        ]
        out = normalize.dedupe(findings)
        self.assertEqual([x["severity"] for x in out], ["CRITICAL", "MEDIUM", "LOW"])

    def test_schema_keys_are_stable(self):
        out = normalize.dedupe([{"tool": "t", "cwe": "CWE-1", "severity": "LOW", "file": "a",
                                 "line": 1, "rule_id": "r", "description": "d"}])
        self.assertEqual(set(out[0]), {"tool", "cwe", "severity", "file", "line",
                                       "rule_id", "description"})


class TestArgsFile(unittest.TestCase):
    def test_nul_delimited_paths_with_metacharacters(self):
        # The whole point of the args file: paths that would be mangled or
        # dangerous if interpolated into a shell command line.
        with tempfile.TemporaryDirectory() as d:
            entries = ["trivy-sarif=/tmp/a b.sarif", "semgrep-sarif=/tmp/$(id).sarif",
                       "nuclei-jsonl=/tmp/we;ird.jsonl"]
            args_file = write(d, "args.txt", "\0".join(entries) + "\0")
            self.assertEqual(normalize.read_args_file(args_file), entries)

    def test_empty_args_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(normalize.read_args_file(write(d, "args.txt", "")), [])



class TestScanStatus(unittest.TestCase):
    """The workflow records one status per manifest entry so a scanner that
    crashed or never uploaded is reported, not silently read as "no findings"."""

    def test_fetch_states_pass_through(self):
        rows = normalize.summarize_scan_status([
            "semgrep-sarif=semgrep-output=ok=", "trivy-sarif=trivy-output=missing=",
            "zap-json=zap-output=empty=",
        ])
        self.assertEqual([(r["artifact"], r["state"]) for r in rows],
                         [("semgrep-output", "ok"), ("trivy-output", "missing"), ("zap-output", "empty")])

    def test_nonzero_exit_marks_failed_even_with_output(self):
        with tempfile.TemporaryDirectory() as d:
            status = write(d, "scan-status.json", {"tool": "semgrep", "exit_code": 2, "sarif": True})
            row = normalize.summarize_scan_status([f"semgrep-sarif=semgrep-output=ok={status}"])[0]
        self.assertEqual(row["state"], "failed")
        self.assertEqual(row["exit_code"], 2)
        self.assertEqual(row["tool"], "semgrep")

    def test_zero_exit_keeps_fetch_state(self):
        with tempfile.TemporaryDirectory() as d:
            status = write(d, "scan-status.json", {"tool": "semgrep", "exit_code": 0, "sarif": True})
            row = normalize.summarize_scan_status([f"semgrep-sarif=semgrep-output=ok={status}"])[0]
        self.assertEqual((row["state"], row["exit_code"]), ("ok", 0))

    def test_status_path_containing_equals_sign(self):
        # Only the first three '=' separate fields; the path is the remainder.
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "a=b"
            sub.mkdir()
            status = write(str(sub), "scan-status.json", {"tool": "semgrep", "exit_code": 1})
            row = normalize.summarize_scan_status([f"semgrep-sarif=semgrep-output=ok={status}"])[0]
        self.assertEqual(row["state"], "failed")

    def test_untrusted_status_file_contents_validated(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ({"exit_code": True}, {"exit_code": "2"}, [1, 2], "not json"):
                status = write(d, "scan-status.json", bad)
                row = normalize.summarize_scan_status([f"semgrep-sarif=s=ok={status}"])[0]
                self.assertEqual((row["state"], row["exit_code"]), ("ok", None), bad)
            status = write(d, "scan-status.json", {"tool": "::error::x\ny", "exit_code": 0})
            self.assertEqual(normalize.read_status_file(status)["tool"], "")

    def test_malformed_and_invalid_records_dropped(self):
        rows = normalize.summarize_scan_status([
            "no-separators", "semgrep-sarif=ok=", "BAD KEY=a=ok=", "k=../../etc=ok=",
            "k=a=exploded=", "k=a=failed=",  # failed only comes from a status file
            "k=good=ok=",
        ])
        self.assertEqual([r["artifact"] for r in rows], ["good"])

    def test_missing_status_file_path_ignored(self):
        row = normalize.summarize_scan_status(["k=a=ok=/nonexistent/scan-status.json"])[0]
        self.assertEqual((row["state"], row["exit_code"]), ("ok", None))


class TestCli(unittest.TestCase):
    SCRIPT = str(Path(__file__).resolve().parent.parent / "scripts" / "normalize.py")

    def run_cli(self, *args):
        import subprocess
        return subprocess.run([sys.executable, self.SCRIPT, *args],
                              capture_output=True, text=True)

    def test_status_summary_written_alongside_findings(self):
        with tempfile.TemporaryDirectory() as d:
            sarif = write(d, "s.sarif", {"runs": []})
            args = write(d, "args.txt", f"semgrep-sarif={sarif}\0")
            status = write(d, "scan-status.json", {"tool": "semgrep", "exit_code": 2})
            status_args = write(d, "status.txt", f"semgrep-sarif=semgrep-output=ok={status}\0"
                                                 f"trivy-sarif=trivy-output=missing=\0")
            out = str(Path(d) / "summary.json")
            r = self.run_cli("--args-file", args, "--status-args-file", status_args, "--status-out", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout), [])
            summary = json.loads(Path(out).read_text())
        self.assertEqual([(x["artifact"], x["state"]) for x in summary],
                         [("semgrep-output", "failed"), ("trivy-output", "missing")])

    def test_old_invocation_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            args = write(d, "args.txt", "")
            r = self.run_cli("--args-file", args)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "[]"))

    def test_status_flags_must_be_paired(self):
        r = self.run_cli("--status-out", "x.json")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
