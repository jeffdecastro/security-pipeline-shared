#!/usr/bin/env python3
"""Send normalized findings to Gemini and post (or update) a PR comment with the result."""
import json
import os
import subprocess
import sys
import urllib.request

MARKER = "<!-- gemini-security-report -->"
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"

PROMPT_TEMPLATE = """You are a security engineer writing a pull request comment for other developers.

You are given a JSON array of security findings already produced by scanners (Semgrep, Trivy, Nuclei, Brakeman, ZAP, etc). Each finding has: tool, cwe, severity, file, line, rule_id, description.

Rules you MUST follow:
- Do not invent findings. Only report on what is in the input array.
- Do not change the `severity` value given for a finding — that came from the scanner and is authoritative. You MAY re-rank/re-group findings by real-world exploitability and reachability, but state the original severity alongside your ranking.
- Deduplicate findings that clearly describe the same underlying issue (e.g. the same CWE hitting the same file/line from two tools).
- For each CWE group, explain in one or two plain-English sentences what the vulnerability class means and why it matters, referencing the CWE id.
- Produce a "Risk-based priority" ordering at the top: a short ranked list of the 3-5 things to fix first, with a one-line reason each (e.g. "internet-reachable", "confirmed by dynamic scan", "known CVE with public exploit", "auth bypass path").
- Keep the whole comment concise and skimmable: use markdown headers, tables, and collapsible <details> sections for the long tail of low-severity items.
- Do not include any text outside the markdown comment itself (no preamble like "Here is the comment").

Repository: {repo}
PR: #{pr_number}

Findings JSON:
{findings_json}
"""


def call_gemini(api_key, findings):
    prompt = PROMPT_TEMPLATE.format(
        repo=os.environ.get("GITHUB_REPOSITORY", "unknown"),
        pr_number=os.environ.get("PR_NUMBER", "unknown"),
        findings_json=json.dumps(findings, indent=2),
    )
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(
        f"{API_URL}?key={api_key}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read())
    return result["candidates"][0]["content"]["parts"][0]["text"]


def upsert_pr_comment(repo, pr_number, body_text):
    full_body = f"{MARKER}\n{body_text}"
    existing = subprocess.run(
        ["gh", "api", f"repos/{repo}/issues/{pr_number}/comments", "--paginate",
         "--jq", f'.[] | select(.body | startswith("{MARKER}")) | .id'],
        capture_output=True, text=True, check=True,
    ).stdout.strip().splitlines()

    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(full_body)
        body_file = f.name

    if existing:
        comment_id = existing[-1]
        subprocess.run(
            ["gh", "api", f"repos/{repo}/issues/comments/{comment_id}", "-X", "PATCH",
             "-f", f"body=@{body_file}"],
            check=True,
        )
    else:
        subprocess.run(
            ["gh", "api", f"repos/{repo}/issues/{pr_number}/comments", "-X", "POST",
             "-f", f"body=@{body_file}"],
            check=True,
        )


def main():
    if len(sys.argv) != 2:
        print("usage: gemini_report.py <normalized-findings.json>", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("::error::GEMINI_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    findings = json.loads(open(sys.argv[1]).read())
    repo = os.environ["GITHUB_REPOSITORY"]
    pr_number = os.environ["PR_NUMBER"]

    if not findings:
        report = "### No security findings to report for this PR."
    else:
        report = call_gemini(api_key, findings)

    upsert_pr_comment(repo, pr_number, report)


if __name__ == "__main__":
    main()
