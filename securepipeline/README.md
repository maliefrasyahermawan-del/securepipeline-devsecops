# SecurePipeline

Automated DevSecOps CI/CD pipeline using GitHub Actions. Every commit is scanned
for security vulnerabilities across three stages before any deployment is allowed.

## What It Does

SecurePipeline integrates five security scanners into a GitHub Actions workflow:

| Scanner | Type | What It Finds |
|---------|------|---------------|
| **Gitleaks** | Secret detection | Hardcoded API keys, passwords, tokens in git history |
| **Semgrep** | SAST | SQL injection, missing auth, insecure patterns in Python code |
| **OWASP Dependency Check** | SCA | Known CVEs in Python packages (`requirements.txt`) |
| **Trivy** | Container scan | CVEs in Docker image layers + Dockerfile misconfigurations |
| **OWASP ZAP** | DAST | Runtime vulnerabilities in the running app (missing headers, open endpoints) |

Deployment is **automatically blocked** if any CRITICAL or HIGH severity finding is detected.

---

## Pipeline Architecture

```
Push / PR
    │
    ▼
┌─────────────────────────────┐
│  STAGE 1 — Pre-Build Scan   │  (runs on every push)
│  ├── Gitleaks (secrets)     │──── FAIL → pipeline stops
│  ├── Semgrep (SAST)         │
│  └── OWASP Dep Check (SCA)  │
└─────────────┬───────────────┘
              │ PASS
              ▼
┌─────────────────────────────┐
│  STAGE 2 — Build + Container│
│  ├── docker build           │
│  ├── Trivy image scan (CVE) │
│  └── Trivy config scan      │
└─────────────┬───────────────┘
              │ PASS
              ▼
┌─────────────────────────────┐
│  STAGE 3 — Staging + DAST   │
│  ├── docker run (staging)   │
│  ├── OWASP ZAP baseline     │
│  └── docker stop            │
└─────────────┬───────────────┘
              │ always()
              ▼
┌─────────────────────────────┐
│  FINAL — Aggregate Report   │
│  ├── aggregate_results.py   │
│  ├── Post PR comment        │
│  ├── Slack notification     │
│  └── Gate: fail on CRIT/HIGH│
└─────────────────────────────┘
```

---

## Setup Instructions

### 1. Fork / Create the Repository

```bash
# Create a new GitHub repo and push this project
git init
git add .
git commit -m "Initial commit — SecurePipeline"
git remote add origin https://github.com/YOUR_USERNAME/securepipeline.git
git push -u origin main
```

### 2. Configure GitHub Secrets

Navigate to your repo → **Settings → Secrets and variables → Actions → New repository secret**.

| Secret Name | Required | Description |
|-------------|----------|-------------|
| `SLACK_WEBHOOK` | Optional | Slack Incoming Webhook URL for notifications |
| `GITLEAKS_LICENSE` | Optional | Gitleaks commercial license (free tier works without it) |

> Note: `GITHUB_TOKEN` is provided automatically by GitHub Actions — no setup needed.

### 3. Trigger the Pipeline

Push any commit or open a pull request:

```bash
git push origin main
```

The pipeline starts automatically. Watch it at:
`https://github.com/YOUR_USERNAME/securepipeline/actions`

[Gambar: Pipeline success screen]

---

## Demo Workflow — Seeing the Gates in Action

The app is **intentionally vulnerable** to demonstrate each gate:

### Step 1 — Gitleaks blocks the pipeline
Push as-is. Gitleaks detects hardcoded secrets in `app/main.py`:
```
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD    = "supersecret123"
```
**Fix:** Remove hardcoded values, use environment variables:
```python
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
DB_PASSWORD    = os.getenv("DB_PASSWORD")
```
Add the values to GitHub Secrets, not to code.

### Step 2 — Semgrep finds SQL injection
After fixing secrets, Semgrep flags `database.py`:
```python
# Vulnerable
query = f"SELECT ... WHERE id = {user_id}"

# Fixed
query = "SELECT ... WHERE id = ?"
rows = conn.execute(query, (user_id,)).fetchall()
```
Also flags `/admin` endpoint missing authentication dependency.

### Step 3 — Trivy finds CVE in Pillow 8.2.0
After fixing SAST findings, Trivy flags `Pillow==8.2.0` (multiple HIGH/CRITICAL CVEs).
**Fix:** Upgrade in `app/requirements.txt`:
```
Pillow==10.4.0
```

### Step 4 — ZAP finds missing security headers
After upgrading dependencies, ZAP flags missing HTTP security headers.
**Fix:** Add security headers middleware to `app/main.py`:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

### Step 5 — All gates pass ✓
Pipeline goes green. Deployment proceeds.

---

## Reading security-summary.json

After each run, download the `security-summary` artifact from the Actions run:

```json
{
  "passed": false,
  "total_findings": 12,
  "critical": 2,
  "high": 4,
  "medium": 5,
  "low": 1,
  "scanners": {
    "semgrep": { "status": "ok", "findings": 3 },
    "trivy-report": { "status": "ok", "findings": 7 },
    "dependency-check-report": { "status": "ok", "findings": 2 },
    "zap-report": { "status": "ok", "findings": 0 }
  },
  "findings": [ ... ]
}
```

- `passed: false` + any `critical > 0` or `high > 0` → pipeline exit code 1
- `passed: true` → all gates clear, deployment allowed

---

## Fixing Each Finding Type

### SQL Injection (Semgrep / ZAP)
Use parameterized queries. Never concatenate user input into SQL strings.
```python
# Bad
conn.execute(f"SELECT * FROM users WHERE id = {user_id}")
# Good
conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### Hardcoded Secrets (Gitleaks)
Move all credentials to GitHub Secrets and read via `os.getenv()`.
Rotate any leaked credentials immediately — they may have been indexed by scanners.

### Outdated Dependencies with CVEs (Dependency Check / Trivy)
Check the CVE IDs in the report, then upgrade:
```bash
pip install --upgrade Pillow requests
pip freeze > app/requirements.txt
```

### Running as Root in Container (Trivy)
Add a non-root user to the Dockerfile:
```dockerfile
RUN adduser --disabled-password --no-create-home appuser
USER appuser
```

### Missing Security Headers (ZAP)
Add middleware or use a reverse proxy (nginx) to set:
`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `HSTS`.

---

## Extending the Pipeline

To add a new scanner:

1. Add a new step to the appropriate job in `.github/workflows/devsecops.yml`
2. Write output to `scan-results/<scanner-name>.json`
3. Add a parser function in `scripts/aggregate_results.py`
4. Register the filename in `SCANNER_FILES` dict

Example scanners to add:
- **Bandit** — Python-specific SAST: `pip install bandit && bandit -r app/ -f json -o scan-results/bandit.json`
- **Safety** — Python dependency check: `pip install safety && safety check --json > scan-results/safety.json`
- **Checkov** — IaC scanning for Terraform/K8s: `checkov -d . -o json > scan-results/checkov.json`

---

## Project Structure

```
securepipeline/
├── .github/workflows/devsecops.yml   # Main pipeline definition
├── app/
│   ├── main.py                        # FastAPI app (intentionally vulnerable)
│   ├── database.py                    # SQLite handler (SQLi demo)
│   ├── models.py                      # Pydantic request/response models
│   └── requirements.txt               # Pinned old versions with CVEs
├── Dockerfile                         # Intentional: root user, no HEALTHCHECK
├── .dockerignore
├── .gitleaks.toml                     # Custom Gitleaks rules + allowlist
├── .semgrep.yml                       # Custom Semgrep rules
├── scripts/
│   └── aggregate_results.py           # Aggregates all scan JSON → summary
├── tests/
│   └── test_main.py                   # Pytest suite for API endpoints
└── README.md
```

---

## Running Locally

```bash
# Install dependencies
pip install -r app/requirements.txt

# Run the app
uvicorn app.main:app --reload --port 8000

# Run tests
pip install pytest httpx
pytest tests/ -v

# Run Semgrep locally
pip install semgrep
semgrep --config .semgrep.yml app/

# Build and scan Docker image
docker build -t securepipeline-app:local .
trivy image securepipeline-app:local
```

---

*SecurePipeline is a portfolio project demonstrating DevSecOps practices.*
*The target app is intentionally vulnerable — do not deploy to production.*
