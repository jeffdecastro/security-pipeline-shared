#!/usr/bin/env python3
"""Unit tests for gemini_report.py. Run: python3 -m unittest discover -s tests -v"""
import json
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


class TestUpsert(unittest.TestCase):
    def test_posts_when_no_existing_comment(self):
        with mock.patch.object(gr, "_gh", return_value="") as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        self.assertIn("-X", m.call_args_list[-1].args[0])
        self.assertIn("POST", m.call_args_list[-1].args[0])

    def test_patches_when_marker_comment_exists(self):
        with mock.patch.object(gr, "_gh", side_effect=["123\n456\n", ""]) as m:
            gr.upsert_pr_comment("o/r", "5", "body")
        args = m.call_args_list[-1].args[0]
        self.assertIn("PATCH", args)
        self.assertIn("repos/o/r/issues/comments/456", args)

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


if __name__ == "__main__":
    unittest.main()
