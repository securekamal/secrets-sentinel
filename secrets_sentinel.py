#!/usr/bin/env python3
"""
Secrets Sentinel - Enterprise Secrets Detection
Author: securekamal
Version: 2.0.0

Scans: Git repos, files, environment, Docker images, CI/CD configs
Detects: API keys, tokens, passwords, private keys, connection strings, cloud credentials
"""

import re
import os
import json
import hashlib
import argparse
import subprocess
import fnmatch
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum

BANNER = """
╔══════════════════════════════════════════════════════════╗
║      Secrets Sentinel v2.0.0 - by securekamal           ║
║   Enterprise Secrets Detection & Prevention Engine       ║
╚══════════════════════════════════════════════════════════╝
"""


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class SecretMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    matched_value: str  # redacted
    entropy: float
    category: str
    remediation: str
    commit: str = ""
    author: str = ""


# ─────────────────────────────────────────────
# Detection Rules
# ─────────────────────────────────────────────

SECRET_RULES = [
    # Cloud Providers
    {
        "id": "AWS-001", "name": "AWS Access Key ID", "category": "Cloud",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "entropy_threshold": 3.5,
        "remediation": "Rotate AWS key immediately. Remove from codebase. Use IAM roles or AWS Secrets Manager.",
    },
    {
        "id": "AWS-002", "name": "AWS Secret Access Key", "category": "Cloud",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(?i)(aws[_\-\.\s]?(secret|access)[_\-\.\s]?key|AWS_SECRET)[_\-\.\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "entropy_threshold": 4.5,
        "remediation": "Rotate immediately. Store in AWS Secrets Manager. Use environment injection in CI/CD.",
    },
    {
        "id": "GCP-001", "name": "GCP API Key", "category": "Cloud",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "entropy_threshold": 4.0,
        "remediation": "Revoke GCP API key. Replace with service account with minimal IAM roles.",
    },
    {
        "id": "AZURE-001", "name": "Azure Storage Key", "category": "Cloud",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"AccountKey=[A-Za-z0-9+/=]{88}"),
        "entropy_threshold": 4.5,
        "remediation": "Rotate Azure Storage Account key. Use Managed Identity instead.",
    },
    # API Keys
    {
        "id": "OPENAI-001", "name": "OpenAI API Key", "category": "AI",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk-[A-Za-z0-9]{48}"),
        "entropy_threshold": 4.5,
        "remediation": "Revoke OpenAI API key immediately at platform.openai.com/api-keys. Rotate all potentially exposed systems.",
    },
    {
        "id": "ANTHROPIC-001", "name": "Anthropic API Key", "category": "AI",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{95}"),
        "entropy_threshold": 4.5,
        "remediation": "Revoke Anthropic API key immediately. Store in secrets manager.",
    },
    {
        "id": "GH-001", "name": "GitHub Personal Access Token", "category": "SCM",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
        "entropy_threshold": 4.5,
        "remediation": "Revoke GitHub PAT at github.com/settings/tokens. Use GitHub Actions secrets or OIDC.",
    },
    {
        "id": "GH-002", "name": "GitHub Fine-Grained PAT", "category": "SCM",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "entropy_threshold": 4.5,
        "remediation": "Revoke immediately at github.com/settings/tokens",
    },
    {
        "id": "STRIPE-001", "name": "Stripe Secret Key", "category": "Payment",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
        "entropy_threshold": 4.0,
        "remediation": "Revoke Stripe key at dashboard.stripe.com. Use restricted keys with minimal permissions.",
    },
    {
        "id": "SLACK-001", "name": "Slack Bot Token", "category": "Communication",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,48}"),
        "entropy_threshold": 3.8,
        "remediation": "Revoke Slack token at api.slack.com. Use environment variables in deployment.",
    },
    {
        "id": "TWILIO-001", "name": "Twilio API Key", "category": "Communication",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"SK[0-9a-fA-F]{32}"),
        "entropy_threshold": 3.8,
        "remediation": "Revoke Twilio API key at console.twilio.com",
    },
    # Private Keys
    {
        "id": "PRIVKEY-001", "name": "RSA Private Key", "category": "Cryptographic",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----"),
        "entropy_threshold": 0,
        "remediation": "Remove private key immediately. Rotate key pair. Use secrets manager or HSM.",
    },
    {
        "id": "PRIVKEY-002", "name": "EC Private Key", "category": "Cryptographic",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        "entropy_threshold": 0,
        "remediation": "Remove EC private key. Rotate certificate. Never commit private keys.",
    },
    # Passwords
    {
        "id": "PWD-001", "name": "Hardcoded Password", "category": "Credential",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(?i)(password|passwd|pwd|pass)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),
        "entropy_threshold": 2.5,
        "remediation": "Remove hardcoded password. Use environment variables or secrets management.",
    },
    {
        "id": "PWD-002", "name": "Default/Weak Password", "category": "Credential",
        "severity": Severity.CRITICAL,
        "pattern": re.compile(r"(?i)(password|passwd)\s*[=:]\s*['\"]?(password|Password123|admin|root|123456|changeme|letmein|qwerty)['\"]?"),
        "entropy_threshold": 0,
        "remediation": "Immediately change this default password. Enforce strong password policy.",
    },
    # Database
    {
        "id": "DB-001", "name": "Database Connection String", "category": "Database",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(?i)(postgresql|mysql|mongodb|redis|mssql|oracle):\/\/[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+"),
        "entropy_threshold": 3.0,
        "remediation": "Rotate database credentials. Use IAM authentication where available. Store in secrets manager.",
    },
    # JWT
    {
        "id": "JWT-001", "name": "JWT Secret", "category": "Auth",
        "severity": Severity.HIGH,
        "pattern": re.compile(r"(?i)(jwt[_\-\s]?(secret|key)|JWT_SECRET)[_\-\s]*[=:]\s*['\"]?([A-Za-z0-9_\-+/=.]{16,})['\"]?"),
        "entropy_threshold": 3.5,
        "remediation": "Rotate JWT secret. Invalidate all existing tokens. Use 256-bit random secret.",
    },
    # Tokens
    {
        "id": "TOKEN-001", "name": "Generic High-Entropy Token", "category": "Auth",
        "severity": Severity.MEDIUM,
        "pattern": re.compile(r"(?i)(token|api[_\-]?key|secret[_\-]?key)[_\-\s]*[=:]\s*['\"]([A-Za-z0-9_\-+/=.]{32,})['\"]"),
        "entropy_threshold": 4.2,
        "remediation": "Verify this is a real secret and rotate if so. Use environment variables.",
    },
]

# Files/patterns to always skip
SKIP_PATTERNS = [
    "*.lock", "*.sum", "*.mod", "package-lock.json", "yarn.lock",
    "*.min.js", "*.min.css", "*.map", "*.pb", "*.pyc",
    ".git/*", "node_modules/*", "vendor/*", ".venv/*", "__pycache__/*",
    "*.test.*", "*_test.*", "test_*", "*spec*",
    "*.md", "*.txt", "*.rst", "CHANGELOG*", "LICENSE*",
]

# Lines to skip (false positive reduction)
SKIP_LINE_PATTERNS = [
    re.compile(r"^\s*#"),  # Comments
    re.compile(r"^\s*//"),  # JS comments
    re.compile(r"example|placeholder|your[_\s]?key|<[A-Z_]+>", re.IGNORECASE),
    re.compile(r"xxx|aaa|bbb|test|fake|dummy|sample|mock", re.IGNORECASE),
    re.compile(r"\$\{[A-Z_]+\}"),  # ${ENV_VAR}
    re.compile(r"process\.env\.|os\.environ"),  # env var references
]


# ─────────────────────────────────────────────
# Shannon Entropy
# ─────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values() if f > 0)


def redact(value: str) -> str:
    if len(value) <= 8:
        return "***REDACTED***"
    return value[:4] + "***" + value[-4:]


# ─────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────

class SecretsScanner:
    def __init__(self, entropy_boost: bool = True, skip_tests: bool = True):
        self.entropy_boost = entropy_boost
        self.skip_tests = skip_tests
        self.findings: List[SecretMatch] = []
        self.files_scanned: int = 0
        self.lines_scanned: int = 0

    def should_skip_file(self, filepath: str) -> bool:
        fname = os.path.basename(filepath)
        for pattern in SKIP_PATTERNS:
            if fnmatch.fnmatch(fname, pattern) or fnmatch.fnmatch(filepath, pattern):
                return True
        if self.skip_tests and any(t in filepath.lower() for t in ["/test/", "/tests/", "_test.", "spec."]):
            return True
        return False

    def should_skip_line(self, line: str) -> bool:
        for pat in SKIP_LINE_PATTERNS:
            if pat.search(line):
                return True
        return False

    def scan_content(self, content: str, filepath: str, commit: str = "", author: str = "") -> List[SecretMatch]:
        matches = []
        lines = content.split("\n")
        self.lines_scanned += len(lines)

        for line_num, line in enumerate(lines, 1):
            if self.should_skip_line(line):
                continue
            for rule in SECRET_RULES:
                for match in rule["pattern"].finditer(line):
                    matched = match.group(0)
                    # Get the actual secret value (last group if multiple)
                    secret_val = match.group(match.lastindex) if match.lastindex else matched

                    # Entropy check
                    entropy = shannon_entropy(secret_val)
                    if self.entropy_boost and rule["entropy_threshold"] > 0:
                        if entropy < rule["entropy_threshold"]:
                            continue

                    matches.append(SecretMatch(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        file_path=filepath,
                        line_number=line_num,
                        line_content=line.strip()[:200],
                        matched_value=redact(secret_val),
                        entropy=round(entropy, 2),
                        category=rule["category"],
                        remediation=rule["remediation"],
                        commit=commit,
                        author=author,
                    ))
        return matches

    def scan_file(self, filepath: str) -> List[SecretMatch]:
        if self.should_skip_file(filepath):
            return []
        try:
            # Check file size (skip > 10MB)
            if os.path.getsize(filepath) > 10 * 1024 * 1024:
                return []
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
            self.files_scanned += 1
            return self.scan_content(content, filepath)
        except Exception:
            return []

    def scan_directory(self, dirpath: str, verbose: bool = False) -> List[SecretMatch]:
        all_matches = []
        for root, dirs, files in os.walk(dirpath):
            # Skip hidden and vendor directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and
                       d not in {"node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}]
            for fname in files:
                fpath = os.path.join(root, fname)
                matches = self.scan_file(fpath)
                if matches and verbose:
                    print(f"  [!] {fpath}: {len(matches)} secret(s)")
                all_matches.extend(matches)
        self.findings = all_matches
        return all_matches

    def scan_git_history(self, repo_path: str = ".", max_commits: int = 50) -> List[SecretMatch]:
        """Scan git history for secrets in past commits."""
        all_matches = []
        try:
            log_cmd = ["git", "-C", repo_path, "log", "--oneline", f"-{max_commits}"]
            result = subprocess.run(log_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return []

            commits = [line.split()[0] for line in result.stdout.strip().split("\n") if line]
            print(f"[*] Scanning {len(commits)} git commits...")

            for commit in commits:
                try:
                    diff_cmd = ["git", "-C", repo_path, "show", commit, "--no-color"]
                    diff = subprocess.run(diff_cmd, capture_output=True, text=True, timeout=10)
                    if diff.returncode == 0:
                        # Get author
                        author_cmd = ["git", "-C", repo_path, "log", "-1", "--format=%an", commit]
                        author = subprocess.run(author_cmd, capture_output=True, text=True).stdout.strip()
                        matches = self.scan_content(diff.stdout, f"git:{commit[:8]}", commit[:8], author)
                        if matches:
                            print(f"  [!] Commit {commit[:8]} ({author}): {len(matches)} secret(s)")
                        all_matches.extend(matches)
                except Exception:
                    continue
        except Exception:
            pass
        return all_matches

    def scan_env(self) -> List[SecretMatch]:
        """Scan environment variables for sensitive data."""
        matches = []
        env_str = "\n".join(f"{k}={v}" for k, v in os.environ.items())
        matches = self.scan_content(env_str, "ENV:environment_variables")
        return matches


# ─────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────

class SentinelReport:
    def __init__(self, findings: List[SecretMatch], files_scanned: int, lines_scanned: int):
        self.findings = findings
        self.files_scanned = files_scanned
        self.lines_scanned = lines_scanned
        self.scan_time = datetime.now().isoformat()

    def to_json(self, output_file: str):
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        data = {
            "metadata": {
                "tool": "Secrets Sentinel v2.0.0",
                "author": "securekamal",
                "scan_time": self.scan_time,
                "files_scanned": self.files_scanned,
                "lines_scanned": self.lines_scanned,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": {sev.value: sum(1 for f in self.findings if f.severity == sev) for sev in Severity},
                "by_category": {},
                "by_rule": {},
            },
            "findings": sorted([
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                    "category": f.category,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "matched_value": f.matched_value,
                    "entropy": f.entropy,
                    "commit": f.commit,
                    "author": f.author,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ], key=lambda x: sev_order.get(x["severity"], 5)),
        }
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON report: {output_file}")

    def to_sarif(self, output_file: str):
        """Generate SARIF format for GitHub Code Scanning integration."""
        rules = [{"id": r["id"], "name": r["name"], "helpUri": "https://github.com/securekamal/secrets-sentinel",
                  "shortDescription": {"text": r["name"]}} for r in SECRET_RULES]
        results = []
        for f in self.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                "message": {"text": f"Potential secret: {f.rule_name} (entropy: {f.entropy})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": f.line_number},
                    }
                }],
            })
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "Secrets Sentinel", "version": "2.0.0", "rules": rules}},
                "results": results,
            }],
        }
        with open(output_file, "w") as f:
            json.dump(sarif, f, indent=2)
        print(f"[+] SARIF report: {output_file}")

    def print_summary(self):
        sev_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        print(f"\n{'='*60}")
        print(f"[+] Files scanned: {self.files_scanned}")
        print(f"[+] Lines scanned: {self.lines_scanned:,}")
        print(f"[+] Total findings: {len(self.findings)}")
        for sev in Severity:
            cnt = sum(1 for f in self.findings if f.severity == sev)
            if cnt:
                print(f"    {sev_icons.get(sev.value,'•')} {sev.value}: {cnt}")

        if self.findings:
            print(f"\n{'─'*60}")
            sorted_findings = sorted(self.findings, key=lambda x: sev_order.get(x.severity.value, 5))
            for f in sorted_findings[:20]:  # Show top 20
                icon = sev_icons.get(f.severity.value, "•")
                print(f"\n{icon} [{f.severity.value}] {f.rule_name} ({f.rule_id})")
                print(f"   File: {f.file_path}:{f.line_number}")
                print(f"   Value: {f.matched_value} (entropy: {f.entropy})")
                print(f"   Fix: {f.remediation[:100]}...")
            if len(self.findings) > 20:
                print(f"\n... and {len(self.findings)-20} more (see JSON/SARIF report)")


# ─────────────────────────────────────────────
# Git Pre-commit Hook
# ─────────────────────────────────────────────

PRE_COMMIT_HOOK = '''#!/bin/sh
# Secrets Sentinel pre-commit hook
# Install: cp this file to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

echo "🛡️  Secrets Sentinel: Scanning staged changes..."

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

TEMP_SCRIPT=$(mktemp /tmp/sentinel_check.XXXXXX.py)
cat > "$TEMP_SCRIPT" << 'EOF'
import subprocess, sys
from secrets_sentinel import SecretsScanner

scanner = SecretsScanner()
result = subprocess.run(["git", "diff", "--cached"], capture_output=True, text=True)
findings = scanner.scan_content(result.stdout, "staged_changes")

critical = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")]
if critical:
    print(f"\\n🚨 SECRETS DETECTED: {len(critical)} high/critical issue(s)\\n")
    for f in critical:
        print(f"  [{f.severity.value}] {f.rule_name}: {f.file_path}:{f.line_number}")
        print(f"  Value: {f.matched_value}\\n")
    print("⛔ Commit blocked. Remove secrets before committing.")
    print("   Tip: Use 'git rm --cached <file>' or fix the secret\\n")
    sys.exit(1)
else:
    print("✅ No secrets detected in staged changes.")
    sys.exit(0)
EOF

python3 "$TEMP_SCRIPT"
EXIT_CODE=$?
rm -f "$TEMP_SCRIPT"
exit $EXIT_CODE
'''


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Secrets Sentinel - Enterprise Secrets Detection")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    scan = subparsers.add_parser("scan", help="Scan files/directories for secrets")
    scan.add_argument("paths", nargs="+", help="Files or directories to scan")
    scan.add_argument("--git-history", action="store_true", help="Also scan git commit history")
    scan.add_argument("--max-commits", type=int, default=50)
    scan.add_argument("--env", action="store_true", help="Scan environment variables")
    scan.add_argument("--no-entropy", action="store_true", help="Disable entropy filtering")
    scan.add_argument("--include-tests", action="store_true", help="Include test files")
    scan.add_argument("--output", default="secrets_report")
    scan.add_argument("--format", choices=["json", "sarif", "both"], default="both")
    scan.add_argument("--verbose", action="store_true")
    scan.add_argument("--fail-on", choices=["any", "high", "critical"], default="critical",
                      help="Exit code 1 if findings at or above this level (for CI)")

    install_hook = subparsers.add_parser("install-hook", help="Install pre-commit hook")
    install_hook.add_argument("--repo", default=".", help="Git repo path")

    args = parser.parse_args()

    if args.cmd == "install-hook":
        hook_path = os.path.join(args.repo, ".git", "hooks", "pre-commit")
        with open(hook_path, "w") as f:
            f.write(PRE_COMMIT_HOOK)
        os.chmod(hook_path, 0o755)
        print(f"[+] Pre-commit hook installed: {hook_path}")
        return

    scanner = SecretsScanner(
        entropy_boost=not args.no_entropy,
        skip_tests=not args.include_tests,
    )
    all_findings = []

    for path in args.paths:
        if os.path.isfile(path):
            print(f"[*] Scanning file: {path}")
            all_findings.extend(scanner.scan_file(path))
        elif os.path.isdir(path):
            print(f"[*] Scanning directory: {path}")
            all_findings.extend(scanner.scan_directory(path, verbose=args.verbose))

    if args.git_history:
        for path in args.paths:
            if os.path.isdir(path):
                all_findings.extend(scanner.scan_git_history(path, args.max_commits))

    if args.env:
        print("[*] Scanning environment variables...")
        all_findings.extend(scanner.scan_env())

    scanner.findings = all_findings
    reporter = SentinelReport(all_findings, scanner.files_scanned, scanner.lines_scanned)
    reporter.print_summary()

    if args.format in ("json", "both"):
        reporter.to_json(f"{args.output}.json")
    if args.format in ("sarif", "both"):
        reporter.to_sarif(f"{args.output}.sarif")

    # CI exit code
    fail_levels = {
        "any": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        "high": {"CRITICAL", "HIGH"},
        "critical": {"CRITICAL"},
    }
    blocking = fail_levels.get(args.fail_on, {"CRITICAL"})
    if any(f.severity.value in blocking for f in all_findings):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
