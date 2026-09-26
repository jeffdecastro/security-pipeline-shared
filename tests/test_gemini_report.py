#!/usr/bin/env python3
"""Unit tests for gemini_report.py. Run: python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import gemini_report as gr  # noqa: E402


def finding(sev="HIGH", cwe="CWE-89", i=0):
    return {"tool": "semgrep", "cwe": cwe, "severity": sev, "file": f"a{i}.java",
            "line": i, "rule_id": "r", "description": "d"}


class FakeResponse:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, body=b"{}"):
    return urllib.error.HTTPError("https://x", code, "err", {}, BytesIO(body))


class TestExtractText(unittest.TestCase):
    def test_happy_path_joins_parts(self):
        payload = {"candidates": [{"content": {"parts": [{"text": "a"}, {"text": "b"}]}}]}
        self.assertEqual(gr._extract_text(payload), "ab")

    def test_safety_block_raises_clearly(self):
        # Previously indexed blindly into candidates[0] -> KeyError/IndexError.
        with self.assertRaisesRegex(RuntimeError, "blocked the prompt: SAFETY"):
            gr._extract_text({"promptFeedback": {"blockReason": "SAFETY"}})

    def test_no_candidates(self):
        with self.assertRaisesRegex(RuntimeError, "no candidates"):
            gr._extract_text({"candidates": []})

    def test_candidate_without_parts_reports_finish_reason(self):
        payload = {"candidates": [{"finishReason": "MAX_TOKENS", "content": {}}]}
        with self.assertRaisesRegex(RuntimeError, "MAX_TOKENS"):
            gr._extract_text(payload)


class TestRetry(unittest.TestCase):
    def test_retries_then_succeeds_on_transient_error(self):
        ok = FakeResponse({"candidates": [{"content": {"parts": [{"text": "report"}]}}]})
        with mock.patch.object(gr.urllib.request, "urlopen",
                               side_effect=[http_error(503), ok]) as m, \
             mock.patch.object(gr.time, "sleep"):
            self.assertEqual(gr.call_gemini("k", "p"), "report")
        self.assertEqual(m.call_count, 2)

    def test_does_not_retry_on_client_error(self):
        with mock.patch.object(gr.urllib.request, "urlopen",
                               side_effect=http_error(400)) as m, \
             mock.patch.object(gr.time, "sleep"):
            with self.assertRaises(RuntimeError):
                gr.call_gemini("k", "p")
        self.assertEqual(m.call_count, 1)

    def test_gives_up_after_max_attempts(self):
        with mock.patch.object(gr.urllib.request, "urlopen",
                               side_effect=http_error(429)) as m, \
             mock.patch.object(gr.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "failed after"):
                gr.call_gemini("k", "p")
        self.assertEqual(m.call_count, gr.MAX_ATTEMPTS)

    def test_api_key_sent_as_header_not_query_string(self):
        captured = {}

        def fake_urlopen(req, **kw):
            captured["url"] = req.full_url
            captured["headers"] = req.headers
            return FakeResponse({"candidates": [{"content": {"parts": [{"text": "r"}]}}]})

        with mock.patch.object(gr.urllib.request, "urlopen", fake_urlopen):
            gr.call_gemini("SUPER_SECRET_KEY", "p")
        self.assertNotIn("SUPER_SECRET_KEY", captured["url"])
        self.assertNotIn("key=", captured["url"])
        self.assertEqual(captured["headers"].get("X-goog-api-key"), "SUPER_SECRET_KEY")


class TestSanitize(unittest.TestCase):
    def test_strips_html_comments_so_marker_cannot_be_forged(self):
        # If the model echoes the marker, a later run would find the forged
        # comment and PATCH the wrong body / orphan the real one.
        out = gr.sanitize_report(f"before {gr.MARKER} after")
        self.assertNotIn(gr.MARKER, out)
        self.assertNotIn("<!--", out)

    def test_strips_active_markup(self):
        out = gr.sanitize_report("ok <script>alert(1)</script> <iframe src=x></iframe> end")
        self.assertNotIn("<script", out.lower())
        self.assertNotIn("<iframe", out.lower())

    def test_preserves_legitimate_markdown_and_details(self):
        md = "## Risk\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n<details><summary>Low</summary>x</details>"
        self.assertEqual(gr.sanitize_report(md), md)


class TestGithubLimits(unittest.TestCase):
    def test_oversized_body_truncated_below_limit(self):
        body = gr.truncate_for_github("x" * (gr.GITHUB_COMMENT_LIMIT + 5000))
        self.assertLessEqual(len(body), gr.GITHUB_COMMENT_LIMIT)
        self.assertIn("truncated", body)

    def test_normal_body_untouched(self):
        self.assertEqual(gr.truncate_for_github("hello"), "hello")


class TestPromptBudget(unittest.TestCase):
    def test_large_finding_set_truncated_and_flagged(self):
        findings = [finding(i=i) for i in range(gr.MAX_FINDINGS_IN_PROMPT + 250)]
        prompt, included, total = gr.build_prompt(findings)
        self.assertEqual(total, len(findings))
        self.assertLessEqual(included, gr.MAX_FINDINGS_IN_PROMPT)
        self.assertIn("only the", prompt)
        self.assertLess(len(prompt), gr.MAX_FINDINGS_CHARS + 10000)

    def test_small_set_has_no_truncation_note(self):
        prompt, included, total = gr.build_prompt([finding()])
        self.assertEqual((included, total), (1, 1))
        self.assertNotIn("NOTE:", prompt)

    def test_findings_are_delimited_in_prompt(self):
        prompt, _, _ = gr.build_prompt([finding()])
        self.assertIn("<<<FINDINGS_JSON_START>>>", prompt)
        self.assertIn("<<<FINDINGS_JSON_END>>>", prompt)


class TestLoadFindings(unittest.TestCase):
    def _write(self, content):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_missing_file_is_zero_findings_not_a_crash(self):
        # The normalize step is continue-on-error, so this file may not exist.
        self.assertEqual(gr.load_findings("/nonexistent/findings.json"), [])

    def test_malformed_json_is_zero_findings(self):
        self.assertEqual(gr.load_findings(self._write("{not json")), [])

    def test_non_array_json_rejected(self):
        self.assertEqual(gr.load_findings(self._write('{"a":1}')), [])

    def test_non_dict_entries_filtered(self):
        self.assertEqual(gr.load_findings(self._write('[{"a":1}, "junk", null]')), [{"a": 1}])


class TestAppendix(unittest.TestCase):
    """Regression cover for a live run where the model summarized 90 SAST
    findings and silently omitted all 23 DAST ones, while still describing
    itself as a detailed breakdown."""

    def _mixed(self):
        return (
            [{"tool": "semgrep", "cwe": "CWE-89", "severity": "MEDIUM",
              "file": f"a{i}.php", "line": i, "rule_id": "sqli", "description": "d"}
             for i in range(90)]
            + [{"tool": "zap", "cwe": "CWE-693", "severity": "LOW",
                "file": "http://127.0.0.1:4280", "line": 0,
                "rule_id": "CSP Header Not Set", "description": "d"}
               for _ in range(23)]
        )

    def test_every_finding_appears_regardless_of_model_output(self):
        findings = self._mixed()
        appendix = gr.build_appendix(findings)
        self.assertIn("113 finding(s)", appendix)
        # the DAST tool and its CWE must be present even though a model
        # narrative would typically drop them
        self.assertIn("zap", appendix)
        self.assertIn("CWE-693", appendix)
        self.assertIn("<code>http://127.0.0.1:4280</code>", appendix)

    def test_counts_are_complete_even_when_table_is_truncated(self):
        findings = [{"tool": "semgrep", "cwe": "CWE-89", "severity": "HIGH",
                     "file": "x" * 300 + str(i), "line": i,
                     "rule_id": "r" * 100, "description": "d"} for i in range(500)]
        appendix = gr.build_appendix(findings)
        self.assertIn("500 finding(s)", appendix)
        self.assertIn("omitted from this table", appendix)
        self.assertIn("the counts above are complete", appendix)
        self.assertLess(len(appendix), gr.APPENDIX_BUDGET + 2000)

    def test_severity_and_tool_breakdown(self):
        appendix = gr.build_appendix(self._mixed())
        self.assertIn("**MEDIUM** 90", appendix)
        self.assertIn("**LOW** 23", appendix)
        self.assertIn("`semgrep` 90", appendix)
        self.assertIn("`zap` 23", appendix)

    def test_merged_tool_names_counted_separately(self):
        f = [{"tool": "semgrep,trivy", "cwe": "CWE-1", "severity": "HIGH",
              "file": "a", "line": 1, "rule_id": "r", "description": "d"}]
        appendix = gr.build_appendix(f)
        self.assertIn("`semgrep` 1", appendix)
        self.assertIn("`trivy` 1", appendix)

    def test_pipe_in_field_does_not_break_table(self):
        f = [{"tool": "zap", "cwe": "CWE-1", "severity": "LOW",
              "file": "http://h/?a=1|b=2", "line": 0,
              "rule_id": "weird | rule", "description": "d"}]
        row = [l for l in gr.build_appendix(f).splitlines() if l.startswith("| LOW")][0]
        self.assertEqual(row.count("|") - row.count("\\|"), 6)

    def test_empty_findings_list(self):
        appendix = gr.build_appendix([])
        self.assertIn("0 finding(s)", appendix)

    def _row(self, **overrides):
        f = dict({"tool": "semgrep", "cwe": "CWE-1", "severity": "LOW", "file": "a.php",
                  "line": 3, "rule_id": "r", "description": "d"}, **overrides)
        return [l for l in gr.build_appendix([f]).splitlines() if l.startswith("| LOW")][0]

    def test_backtick_in_path_cannot_break_out_of_code(self):
        # The location used to sit in a `code span`: one backtick in a
        # scanner-reported path closed it and let the rest render as markdown.
        row = self._row(file="x`**bold** [click](https://evil.example)`.php")
        self.assertNotIn("`", row)
        self.assertNotIn("**", row)
        self.assertNotIn("](", row)

    def test_html_in_rule_id_is_inert(self):
        row = self._row(rule_id='<img src=x onerror=alert(1)><!-- gemini-security-report -->')
        self.assertNotIn("<img", row)
        self.assertNotIn("<!--", row)
        self.assertIn("&lt;img", row)

    def test_mentions_and_refs_are_neutralized(self):
        # An @name or #123 in a rule id would otherwise ping a user or
        # cross-link an issue from the bot's comment.
        row = self._row(rule_id="@octocat fixes #1")
        self.assertNotIn("@octocat", row)
        self.assertNotIn("#1", row)
        self.assertIn("<code>", row)

    def test_newline_in_field_stays_on_one_row(self):
        row = self._row(file="a\n| INJECTED | row |")
        self.assertIn("a &#124; INJECTED", row)


class TestScanStatus(unittest.TestCase):
    """Once this repo runs scanners, a failed scan must never read as an
    all-clear: a crashed Semgrep yields an empty finding set, which used to
    post "No security findings to report"."""

    OK = {"parser": "semgrep-sarif", "artifact": "semgrep-output", "state": "ok", "exit_code": 0}
    FAILED = {"parser": "trivy-json", "artifact": "trivy-results", "state": "failed", "exit_code": 2}
    MISSING = {"parser": "nuclei-jsonl", "artifact": "nuclei-results", "state": "missing", "exit_code": None}

    def _write(self, data):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        f.write(data if isinstance(data, str) else json.dumps(data))
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_no_findings_with_failed_scanner_is_not_an_all_clear(self):
        body = gr.no_findings_body([self.OK, self.FAILED])
        self.assertNotIn("No security findings to report", body)
        self.assertIn("not every scanner produced results", body)
        self.assertIn("`trivy-results` **failed (exit 2)**", body)
        self.assertTrue(body.startswith(gr.MARKER))

    def test_no_findings_all_scanners_ran(self):
        body = gr.no_findings_body([self.OK])
        self.assertIn("No security findings to report", body)
        self.assertIn("`semgrep-output` ran", body)

    def test_no_findings_without_status_is_unchanged(self):
        # Callers on an older workflow produce no status summary.
        self.assertEqual(gr.no_findings_body([]),
                         f"{gr.MARKER}\n### No security findings to report for this PR.")

    def test_appendix_names_failed_and_missing_scanners(self):
        appendix = gr.build_appendix([finding()], [self.OK, self.FAILED, self.MISSING])
        self.assertIn("`nuclei-results` **artifact missing**", appendix)
        self.assertIn("`trivy-results` **failed (exit 2)**", appendix)
        self.assertIn("may be incomplete", appendix)

    def test_appendix_all_ok_has_no_warning(self):
        appendix = gr.build_appendix([finding()], [self.OK])
        self.assertIn("Scanners: `semgrep-output` ran", appendix)
        self.assertNotIn("may be incomplete", appendix)

    def test_did_not_run_label(self):
        line = gr.render_scan_status([dict(self.FAILED, exit_code=-1)])
        self.assertIn("**failed (did not run)**", line)

    def test_load_validates_rows(self):
        path = self._write([self.OK, {"parser": "x", "artifact": "<img>", "state": "ok"},
                            {"parser": "x", "artifact": "a", "state": "bogus"},
                            dict(self.OK, exit_code="2"), dict(self.OK, exit_code=True), "junk"])
        self.assertEqual(gr.load_scan_status(path), [self.OK])

    def test_load_tolerates_absent_or_broken_file(self):
        self.assertEqual(gr.load_scan_status(None), [])
        self.assertEqual(gr.load_scan_status("/nonexistent.json"), [])
        self.assertEqual(gr.load_scan_status(self._write("{not json")), [])
        self.assertEqual(gr.load_scan_status(self._write({"a": 1})), [])


class TestComposeBody(unittest.TestCase):
    def test_appendix_survives_when_narrative_is_oversized(self):
        findings = [{"tool": "zap", "cwe": "CWE-693", "severity": "LOW",
                     "file": "http://h", "line": 0, "rule_id": "CSP", "description": "d"}]
        appendix = gr.build_appendix(findings)
        body = gr.compose_body("N" * 200_000, appendix)
        self.assertLessEqual(len(body), gr.GITHUB_COMMENT_LIMIT)
        self.assertTrue(body.startswith(gr.MARKER))
        # the whole point: the generated inventory is not what gets cut
        self.assertIn("CWE-693", body)
        self.assertIn("</details>", body)
        self.assertIn("narrative truncated", body)

    def test_normal_case_keeps_both_intact(self):
        appendix = gr.build_appendix([{"tool": "t", "cwe": "CWE-1", "severity": "LOW",
                                       "file": "a", "line": 1, "rule_id": "r",
                                       "description": "d"}])
        body = gr.compose_body("## Narrative", appendix)
        self.assertIn("## Narrative", body)
        self.assertIn("CWE-1", body)
        self.assertEqual(body.count(gr.MARKER), 1)


class TestUpsert(unittest.TestCase):
    def test_posts_when_no_existing_comment(self):
        with mock.patch.object(gr, "_gh", return_value="") as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        self.assertIn("-X", m.call_args_list[-1].args[0])
        self.assertIn("POST", m.call_args_list[-1].args[0])

    def test_patches_when_marker_comment_exists(self):
        listing = "123\tgithub-actions[bot]\n456\tgithub-actions[bot]\n"
        with mock.patch.object(gr, "_gh", side_effect=[listing, ""]) as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        args = m.call_args_list[-1].args[0]
        self.assertIn("PATCH", args)
        self.assertIn("repos/o/r/issues/comments/456", args)

    def test_marker_comment_by_another_author_is_never_patched(self):
        # Anyone can post a comment that starts with the marker. The bot used
        # to PATCH the latest such comment - an attacker's, if they posted last.
        listing = "123\tgithub-actions[bot]\n456\tmallory\n"
        with mock.patch.object(gr, "_gh", side_effect=[listing, ""]) as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        args = m.call_args_list[-1].args[0]
        self.assertIn("repos/o/r/issues/comments/123", args)
        self.assertNotIn("repos/o/r/issues/comments/456", args)

    def test_only_foreign_marker_comments_means_post_new(self):
        with mock.patch.object(gr, "_gh", side_effect=["456\tmallory\n", ""]) as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        self.assertIn("POST", m.call_args_list[-1].args[0])

    def test_listing_query_filters_on_marker_and_returns_author(self):
        with mock.patch.object(gr, "_gh", return_value="") as m:
            gr.list_marker_comments("o/r", "5")
        jq = m.call_args.args[0][m.call_args.args[0].index("--jq") + 1]
        self.assertIn(json.dumps(gr.MARKER), jq)
        self.assertIn(".user.login", jq)

    def test_malformed_listing_lines_ignored(self):
        with mock.patch.object(gr, "_gh", return_value="garbage\nabc\tx\n7\tgithub-actions[bot]\n"):
            self.assertEqual(gr.list_marker_comments("o/r", "5"), [("7", "github-actions[bot]")])

    def test_temp_file_cleaned_up_even_on_failure(self):
        created = []
        real = gr.tempfile.NamedTemporaryFile

        def spy(*a, **kw):
            f = real(*a, **kw)
            created.append(f.name)
            return f

        with mock.patch.object(gr.tempfile, "NamedTemporaryFile", spy), \
             mock.patch.object(gr, "_gh", side_effect=["", RuntimeError("boom")]):
            with self.assertRaises(RuntimeError):
                gr.upsert_pr_comment("o/r", "5", "body")
        self.assertTrue(created)
        self.assertFalse(any(Path(p).exists() for p in created))


class TestMain(unittest.TestCase):
    """Regression cover for a missing GEMINI_API_KEY posting no comment at all.

    Discovered wiring the shared pipeline into a repo that had never had the
    secret configured: with findings present but no key, main() used to
    sys.exit(1) before ever calling upsert_pr_comment, so the run showed green
    (continue-on-error) with zero visible signal that nothing was posted."""

    def _findings_file(self, findings):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(findings, f)
        f.close()
        return f.name

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "o/r", "PR_NUMBER": "5",
        }, clear=False)
        self.env.start()
        os.environ.pop("GEMINI_API_KEY", None)
        self.addCleanup(self.env.stop)

    def test_missing_key_with_findings_still_posts_a_comment(self):
        path = self._findings_file([finding()])
        with mock.patch.object(gr, "upsert_pr_comment") as up, \
             self.assertRaises(SystemExit) as ctx, \
             mock.patch.object(sys, "argv", ["gemini_report.py", path]):
            gr.main()
        up.assert_called_once()
        body = up.call_args.args[2]
        self.assertIn("GEMINI_API_KEY", body)
        self.assertIn("CWE-89", body)  # the inventory, not just the excuse text
        self.assertEqual(ctx.exception.code, 1)  # step shows failed, but posted

    def test_missing_key_with_no_findings_posts_the_normal_no_findings_comment(self):
        path = self._findings_file([])
        with mock.patch.object(gr, "upsert_pr_comment") as up:
            with mock.patch.object(sys, "argv", ["gemini_report.py", path]):
                gr.main()  # returns normally, no key needed when nothing to report
        self.assertIn("No security findings", up.call_args.args[2])

    def test_gemini_failure_also_still_posts_and_exits_nonzero(self):
        path = self._findings_file([finding()])
        os.environ["GEMINI_API_KEY"] = "k"
        with mock.patch.object(gr, "call_gemini", side_effect=RuntimeError("503")), \
             mock.patch.object(gr, "upsert_pr_comment") as up, \
             self.assertRaises(SystemExit) as ctx:
            with mock.patch.object(sys, "argv", ["gemini_report.py", path]):
                gr.main()
        up.assert_called_once()
        self.assertIn("CWE-89", up.call_args.args[2])
        self.assertEqual(ctx.exception.code, 1)

    def test_status_file_argument_reaches_the_comment(self):
        path = self._findings_file([])
        status = self._findings_file([{"parser": "semgrep-sarif", "artifact": "semgrep-output",
                                       "state": "failed", "exit_code": 2}])
        with mock.patch.object(gr, "upsert_pr_comment") as up, \
             mock.patch.object(sys, "argv", ["gemini_report.py", path, status]):
            gr.main()
        self.assertIn("not every scanner produced results", up.call_args.args[2])

    def test_invalid_report_author_rejected(self):
        path = self._findings_file([finding()])
        with mock.patch.object(gr, "REPORT_AUTHOR", "x; rm -rf /"), \
             mock.patch.object(gr, "upsert_pr_comment") as up, \
             self.assertRaises(SystemExit) as ctx, \
             mock.patch.object(sys, "argv", ["gemini_report.py", path]):
            gr.main()
        up.assert_not_called()
        self.assertEqual(ctx.exception.code, 1)

    def test_successful_call_exits_zero(self):
        path = self._findings_file([finding()])
        os.environ["GEMINI_API_KEY"] = "k"
        with mock.patch.object(gr, "call_gemini", return_value="## narrative"), \
             mock.patch.object(gr, "upsert_pr_comment"):
            with mock.patch.object(sys, "argv", ["gemini_report.py", path]):
                try:
                    gr.main()
                    code = 0
                except SystemExit as e:
                    code = e.code
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
