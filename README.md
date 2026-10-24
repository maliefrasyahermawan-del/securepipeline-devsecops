# SecurePipeline — DevSecOps CI/CD Security Gates

> A GitHub Actions-based DevSecOps demonstration that scans code, dependencies, containers, and a staging application before deployment is permitted.

## What this project does

SecurePipeline demonstrates how multiple security checks can be assembled into a CI/CD gate. Each push or pull request runs secret detection, static analysis, dependency scanning, container scanning, and dynamic application testing. The pipeline aggregates results and fails the delivery process when HIGH or CRITICAL findings remain.

## Core functions

- Detect hardcoded secrets with Gitleaks.
- Scan source patterns with Semgrep.
- Identify vulnerable dependencies with OWASP Dependency Check.
- Scan images and Dockerfile configuration with Trivy.
- Run OWASP ZAP baseline testing against a temporary staging container.
- Aggregate scanner output into a unified security summary, pull-request comment, and optional Slack notification.

## Architecture

```text
Push / pull request
  │
  ▼
Stage 1: Gitleaks + Semgrep + dependency scan
  │ pass
  ▼
Stage 2: Docker build + Trivy image/config scan
  │ pass
  ▼
Stage 3: temporary staging container + OWASP ZAP
  │
  ▼
Aggregate reports → severity gate → allow or block deployment
```

## Technology

- GitHub Actions and Docker
- Gitleaks, Semgrep, OWASP Dependency Check, Trivy, and OWASP ZAP
- FastAPI demo service
- Python aggregation script

## Run locally

The workflow is intended to run from GitHub Actions after the repository is pushed. To run the sample service locally:

```bash
cd securepipeline
python -m venv .venv
.venv\Scripts\activate
pip install -r app/requirements.txt
uvicorn app.main:app --reload
```

## Repository layout

```text
securepipeline/
├── .github/workflows/  # DevSecOps workflow definition
├── app/                # Deliberately vulnerable FastAPI demo app
├── scripts/            # Report aggregation
├── Dockerfile          # Container used in the pipeline
├── .gitleaks.toml      # Secret-scanning configuration
└── .semgrep.yml        # Static-analysis configuration
```

## Important safety note

The demonstration app and dependency versions intentionally contain insecure patterns so the gates have findings to detect. Do not deploy the sample application, its example credentials, or its outdated dependencies to a production environment. Replace the intentionally vulnerable components before adapting this pipeline for a real service.
