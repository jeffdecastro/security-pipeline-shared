#!/usr/bin/env python3
"""Structural tests for the workflow files. Run: python3 -m unittest discover -s tests -v

The workflows carry this repo's security rules (pinned actions, no ${{ }} in
run blocks, an isolated scan job, strict input validation), and until now
nothing enforced them. These tests read the YAML as text - stdlib has no YAML
parser - and exercise the real validation regexes with bash's own =~.
"""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
DOCKER_PIN = re.compile(r"^docker://[\w./-]+@sha256:[0-9a-f]{64}$")


def workflow(name):
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def code_only(text):
    """Drop full-line comments, so prose in comments cannot trip a check."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def run_blocks(text):
    """Yield (line number, script text) for every run: step, inline or block."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2)
        start = i + 1
        if rest.strip() not in ("|", ">", "|-", ">-"):
            yield start, rest
            i += 1
            continue
        body = []
        i += 1
        while i < len(lines) and (not lines[i].strip()
                                  or len(lines[i]) - len(lines[i].lstrip()) > indent):
            body.append(lines[i])
            i += 1
        yield start, "\n".join(body)


def validation_regex(text, name):
    """The bash regex on the line after a `# validate:<name>` marker."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"# validate:{name}":
            m = re.search(r"=~ (\S+) \]\]", lines[i + 1])
            if m:
                return m.group(1)
    raise AssertionError(f"no validation regex marked {name!r}")


def bash_matches(regex, value):
    # The regex is passed as a variable, so bash applies it unquoted as a
    # regex, exactly as in the workflow; the value is never interpolated.
    r = subprocess.run(["bash", "-c", '[[ "$1" =~ $2 ]]', "_", value, regex])
    return r.returncode == 0


class TestAllWorkflows(unittest.TestCase):
    FILES = sorted(WORKFLOWS.glob("*.yml"))

    def test_there_are_workflows(self):
        self.assertIn("sast-semgrep.yml", [f.name for f in self.FILES])

    def test_every_action_pinned_to_full_sha(self):
        for f in self.FILES:
            for n, line in enumerate(f.read_text().splitlines(), 1):
                m = re.match(r"^\s*(?:- )?uses:\s*(\S+)", line)
                if not m:
                    continue
                ref = m.group(1)
                if ref.startswith("./"):
                    continue  # this repo's own reusable workflows
                self.assertTrue(SHA_PIN.match(ref) or DOCKER_PIN.match(ref),
                                f"{f.name}:{n} not pinned to a full SHA: {ref}")

    def test_scanner_images_pinned_by_digest(self):
        # A mutable tag on a scanner image is how the March 2026 Trivy
        # compromise reached CI pipelines.
        for f in self.FILES:
            for n, script in run_blocks(f.read_text()):
                for image, ref in re.findall(r"\b(semgrep/semgrep|aquasec/trivy)(\S*)",
                                             code_only(script)):
                    self.assertRegex(ref, r"^@sha256:[0-9a-f]{64}$",
                                     f"{f.name}: run block at line {n} uses unpinned {image}{ref}")

    def test_no_expressions_inside_run_blocks(self):
        # ${{ }} is substituted as literal text before bash parses the
        # script - an injection sink for any caller- or scanner-derived value.
        for f in self.FILES:
            for n, script in run_blocks(f.read_text()):
                self.assertNotIn("${{", script, f"{f.name}: run block at line {n} uses ${{{{ }}}}")

    def test_top_level_permissions_empty(self):
        for name in ("gemini-report.yml", "sast-semgrep.yml"):
            self.assertRegex(workflow(name), r"(?m)^permissions: \{\}$", name)


class TestSastSemgrepWorkflow(unittest.TestCase):
    TEXT = code_only(workflow("sast-semgrep.yml"))

    def test_is_reusable_only(self):
        self.assertRegex(self.TEXT, r"(?m)^on:\n  workflow_call:")

    def test_scan_job_gets_no_secrets(self):
        # The isolation guarantee: a compromised scanner image must never see
        # GEMINI_API_KEY or any other secret.
        self.assertNotRegex(self.TEXT, r"(?m)^\s*secrets:")
        self.assertNotRegex(self.TEXT, r"secrets\.\w")
        self.assertNotIn("github.token", self.TEXT)
        self.assertNotIn("GH_TOKEN", self.TEXT)

    def test_scan_job_is_read_only(self):
        grants = re.findall(r"(?m)^\s+(\w[\w-]*): (read|write)\s*$", self.TEXT)
        self.assertEqual(grants, [("contents", "read")])

    def test_checkout_does_not_persist_credentials(self):
        self.assertIn("persist-credentials: false", self.TEXT)

    def test_scan_step_is_soft_fail_and_records_status(self):
        scan = self.TEXT.split("- name: Run Semgrep", 1)[1].split("- name:", 1)[0]
        self.assertIn("continue-on-error: true", scan)
        self.assertIn("set -euo pipefail", scan)
        self.assertIn("scan-status.json", scan)
        self.assertIn("--metrics=off", scan)

    def test_source_mounted_read_only(self):
        self.assertIn('-v "$PWD/src:/src:ro"', self.TEXT)


@unittest.skipUnless(shutil.which("bash"), "bash required")
class TestValidationRegexes(unittest.TestCase):
    def assert_accepts(self, regex, values):
        for v in values:
            self.assertTrue(bash_matches(regex, v), f"should accept {v!r}")

    def assert_rejects(self, regex, values):
        for v in values:
            self.assertFalse(bash_matches(regex, v), f"should reject {v!r}")

    def test_semgrep_configs(self):
        regex = validation_regex(workflow("sast-semgrep.yml"), "semgrep_configs")
        self.assert_accepts(regex, ["p/default", "p/php,p/security-audit,p/owasp-top-ten,p/cwe-top-25",
                                    ",".join(["p/a"] * 10)])
        self.assert_rejects(regex, [
            "", "p/default,", ",p/default", "p/PHP", "p/php p/java",
            "./rules.yml", ".semgrep.yml", "r/php.lang.security.x", "https://evil/rules.yml",
            "--config=/etc", "p/php;id", "p/php$(id)", "p/../../x", "p/php\nnewline",
            ",".join(["p/a"] * 11),
        ])

    def test_artifact_name(self):
        regex = validation_regex(workflow("sast-semgrep.yml"), "artifact_name")
        self.assert_accepts(regex, ["semgrep-output", "a", "Semgrep_1.2", "x" * 64])
        self.assert_rejects(regex, ["", ".", "..", ".hidden", "-flag", "a/b", "a b", "x" * 65,
                                    "a\nb", "$(id)"])

    def test_artifact_manifest_entry(self):
        regex = validation_regex(workflow("gemini-report.yml"), "artifact_manifest_entry")
        self.assert_accepts(regex, ["semgrep-sarif=semgrep-output", "trivy-sarif=trivy.out_1"])
        self.assert_rejects(regex, ["semgrep-sarif=..", "semgrep-sarif=.", "semgrep-sarif=-x",
                                    "Semgrep=out", "semgrep-sarif=", "=out", "k=a/b",
                                    "k=a=b", "k=$(id)"])



def step_script(text, step_name):
    """The run: script of the step called `step_name`, de-indented."""
    marker = f"- name: {step_name}"
    offset = text.index(marker)
    start_line = text[:offset].count("\n") + 1
    for n, script in run_blocks(text):
        if n > start_line:
            lines = script.splitlines()
            indent = min(len(l) - len(l.lstrip()) for l in lines if l.strip())
            return "\n".join(l[indent:] for l in lines) + "\n"
    raise AssertionError(f"no run block for {step_name!r}")


FAKE_GH = """#!/usr/bin/env bash
# Fake `gh run download <id> --repo R --name NAME --dir DIR`: copies
# $FAKE_ARTIFACTS/NAME into DIR, or fails like a missing artifact.
set -euo pipefail
while [ $# -gt 0 ]; do
  case "$1" in
    --name) name="$2"; shift 2 ;;
    --dir) dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -d "$FAKE_ARTIFACTS/$name" ] || { echo "no artifact $name" >&2; exit 1; }
cp -R "$FAKE_ARTIFACTS/$name/." "$dir/"
"""


@unittest.skipUnless(shutil.which("bash"), "bash required")
class TestFetchStep(unittest.TestCase):
    """Runs the real fetch step from gemini-report.yml against a fake gh."""

    def run_fetch(self, manifest, artifacts):
        import os
        import tempfile
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work)
        root = Path(work)
        for name, files in artifacts.items():
            for rel, content in files.items():
                f = root / "artifacts" / name / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(content)
        (root / "bin").mkdir()
        gh = root / "bin" / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        (root / "ws").mkdir()
        script = step_script(workflow("gemini-report.yml"), "Download scanner artifacts and build parser args")
        env = dict(os.environ, PATH=f"{root / 'bin'}:{os.environ['PATH']}", MANIFEST=manifest,
                   RUN_ID="1", REPO="o/r", GH_TOKEN="x", FAKE_ARTIFACTS=str(root / "artifacts"))
        r = subprocess.run(["bash", "-c", script], cwd=root / "ws", env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        read = lambda n: [e for e in (root / "ws" / n).read_text().split("\0") if e]
        return read("parser_args.txt"), read("scan_status_args.txt")

    def test_status_file_kept_out_of_parser_queue_and_recorded(self):
        parser_args, status = self.run_fetch(
            "semgrep-sarif=semgrep-output,trivy-sarif=trivy-output,zap-json=zap-output",
            {"semgrep-output": {"semgrep.sarif": "{}", "scan-status.json": "{}"},
             "zap-output": {"zap.html": "<html>"}})
        self.assertEqual(len(parser_args), 1)
        self.assertTrue(parser_args[0].startswith("semgrep-sarif=_scanner_output/semgrep-output/"))
        self.assertTrue(parser_args[0].endswith("semgrep.sarif"))
        self.assertEqual(status[0], "semgrep-sarif=semgrep-output=ok="
                                    "_scanner_output/semgrep-output/scan-status.json")
        self.assertEqual(status[1], "trivy-sarif=trivy-output=missing=")
        self.assertEqual(status[2], "zap-json=zap-output=empty=")

    def test_caller_artifact_without_status_file(self):
        parser_args, status = self.run_fetch("semgrep-sarif=semgrep-output",
                                             {"semgrep-output": {"semgrep.sarif": "{}"}})
        self.assertEqual(len(parser_args), 1)
        self.assertEqual(status, ["semgrep-sarif=semgrep-output=ok="])

    def test_paths_with_spaces_and_metacharacters_survive(self):
        parser_args, _ = self.run_fetch("semgrep-sarif=out",
                                        {"out": {"dir with space/$(id) x.sarif": "{}"}})
        self.assertEqual(parser_args, ["semgrep-sarif=_scanner_output/out/dir with space/$(id) x.sarif"])


if __name__ == "__main__":
    unittest.main()
