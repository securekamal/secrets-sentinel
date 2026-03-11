# 🔍 Secrets Sentinel

> Enterprise-grade secrets detection — scans source code, git history, Docker images, and CI/CD configs for exposed API keys, tokens, passwords, and private keys.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![Entropy](https://img.shields.io/badge/Entropy-Shannon%20Analysis-orange?style=flat-square)
![SARIF](https://img.shields.io/badge/Output-SARIF%20%7C%20JSON-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## Overview

Secrets Sentinel combines **regex pattern matching** with **Shannon entropy analysis** to detect hardcoded secrets while minimizing false positives. It integrates into CI/CD pipelines via pre-commit hooks, GitHub Actions, and SARIF output for GitHub Code Scanning.

---

## What It Detects

| Category | Examples |
|---|---|
| **Cloud Credentials** | AWS Access/Secret Keys, GCP API Keys, Azure Storage Keys |
| **AI API Keys** | OpenAI (`sk-...`), Anthropic (`sk-ant-...`) |
| **SCM Tokens** | GitHub PATs (`ghp_`, `github_pat_`), GitLab tokens |
| **Payment** | Stripe live/test keys |
| **Communication** | Slack bot tokens, Twilio API keys |
| **Cryptographic** | RSA/EC/OpenSSH private keys |
| **Database** | MySQL, PostgreSQL, MongoDB connection strings |
| **Auth** | JWT secrets, hardcoded passwords |
| **Generic** | High-entropy tokens matching credential patterns |

---

## Installation

```bash
git clone https://github.com/securekamal/secrets-sentinel.git
cd secrets-sentinel
pip install -r requirements.txt
```

---

## Usage

### Scan Directory
```bash
python secrets_sentinel.py scan ./my-app --verbose
```

### Scan + Git History
```bash
python secrets_sentinel.py scan . --git-history --max-commits 100
```

### Scan Environment Variables
```bash
python secrets_sentinel.py scan . --env
```

### CI Mode (Fail on Critical)
```bash
python secrets_sentinel.py scan . --fail-on critical --format sarif
echo $?  # 1 if critical secrets found
```

### Install Pre-commit Hook
```bash
python secrets_sentinel.py install-hook
# Now runs automatically before every git commit
```

---

## GitHub Actions Integration

```yaml
# .github/workflows/secrets-scan.yml
name: Secrets Scan
on: [push, pull_request]

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history
      
      - name: Install Secrets Sentinel
        run: pip install -r requirements.txt
      
      - name: Run Scan
        run: |
          python secrets_sentinel.py scan . \
            --git-history --max-commits 50 \
            --format sarif \
            --output results
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
        if: always()
      
      - name: Fail on Secrets
        run: |
          python secrets_sentinel.py scan . --fail-on high
```

---

## Entropy Analysis

Secrets Sentinel uses Shannon entropy to reduce false positives. A string like `password="test"` has low entropy and is likely a placeholder — it's skipped. A string like `password="Kx9mN2pL8qR4vY7w"` has high entropy and is flagged.

Each rule has a configurable `entropy_threshold`. Disable with `--no-entropy`.

---

## False Positive Reduction

Secrets Sentinel automatically skips:
- Code comments and documentation
- Test files (`_test.`, `spec.`, `/tests/`)
- Lock files (`package-lock.json`, `yarn.lock`)
- Build artifacts (`.min.js`, `dist/`)
- Environment variable references (`${SECRET_KEY}`, `process.env.`)
- Obvious placeholders (`example`, `your-key-here`, `<API_KEY>`)

---

## Sample Output

```
[*] Scanning directory: ./backend

======================================
[+] Files scanned: 47
[+] Lines scanned: 12,439
[+] Total findings: 3

🔴 CRITICAL: AWS Access Key ID (AWS-001)
   File: config/settings.py:23
   Value: AKIA***WXYZ (entropy: 4.2)
   Fix: Rotate AWS key. Use IAM roles or AWS Secrets Manager.

🔴 CRITICAL: OpenAI API Key (OPENAI-001)
   File: .env.local:8
   Value: sk-***ABCD (entropy: 4.7)
   Fix: Revoke at platform.openai.com/api-keys

🟠 HIGH: Hardcoded Password (PWD-001)
   File: db/migrate.py:15
   Value: myd***d! (entropy: 3.1)
   Fix: Use environment variable DB_PASSWORD
```

---

## SARIF Integration

SARIF output integrates natively with GitHub Code Scanning, showing secrets as security alerts in the PR review interface.

---

## Author

**securekamal** — Product Security Engineer

## License

MIT
