# 🛡️ REST API Security CI/CD Orchestrator
### *Enterprise DevSecOps Automation Testbed & Security Policy Enforcement Engine*

![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)
![SAST](https://img.shields.io/badge/SAST-Semgrep-00B4D8?logo=semgrep&logoColor=white)
![DAST](https://img.shields.io/badge/DAST-OWASP%20ZAP-FF5722?logo=owasp&logoColor=white)
![SCA](https://img.shields.io/badge/SCA-Dependency--Check-4CAF50?logo=npm&logoColor=white)
![Backend](https://img.shields.io/badge/Backend-Node.js%20%7C%20Express-68A063?logo=node.js&logoColor=white)
![Automation](https://img.shields.io/badge/Automation-Python%203-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-ISC-blue)

---

## 📌 Executive Summary

Modern software supply chain attacks and API breaches frequently stem from late-cycle security audits where critical flaws reach staging or production unchecked. The **REST API Security CI/CD Orchestrator** is an enterprise-grade DevSecOps reference architecture engineered to demonstrate **"Shift-Left" security principles**.

This platform combines an intentionally vulnerable Node.js/Express REST API with an automated continuous security testing pipeline. By executing **Software Composition Analysis (SCA)**, **Static Application Security Testing (SAST)**, and **Dynamic Application Security Testing (DAST)** on every push and pull request, it enforces zero-tolerance build-blocking gates via an extensible Python security orchestrator (`security_gate.py`).

---

## 🏛️ Architecture & Pipeline Flow

```
                                    +------------------------------------------+
                                    |  Developer Push / Pull Request to main  |
                                    +------------------------------------------+
                                                         |
                                  +----------------------+---------------------+
                                  |                      |                     |
                                  v                      v                     v
                        +-------------------+  +-------------------+  +-------------------+
                        |     SCA Gate      |  |     SAST Gate     |  |     DAST Gate     |
                        | OWASP Dep-Check / |  |   Semgrep Engine  |  |  Node.js Daemon + |
                        |     NPM Audit     |  |  Custom + OWASP   |  |   OWASP ZAP Scan  |
                        +-------------------+  +-------------------+  +-------------------+
                                  |                      |                     |
                                  | (JSON Report)        | (JSON Report)       | (JSON Report)
                                  v                      v                     v
                        +-----------------------------------------------------------------+
                        |                 security_gate.py (Policy Engine)                |
                        |      * Parses findings across multiple scanner schemas          |
                        |      * Normalizes severities (CVSS / CWE / Risk Codes)          |
                        |      * Enforces --fail-on CRITICAL,HIGH threshold               |
                        |      * Exports Markdown summaries to $GITHUB_STEP_SUMMARY       |
                        +-----------------------------------------------------------------+
                                                         |
                                    +--------------------+--------------------+
                                    |                                         |
                                    v [High/Critical Found]                   v [Zero High/Critical]
                         +----------------------+                  +----------------------+
                         |   🚨 BUILD BROKEN    |                  |  ✅ PIPELINE PASSED   |
                         | Non-zero Exit Code 1 |                  |  Zero-Exit Code (0)  |
                         | PR Merging Blocked   |                  |  Deployment Allowed  |
                         +----------------------+                  +----------------------+
```

---

## 🎯 OWASP Top 10 Injected Vulnerabilities Matrix

The REST API implements real-world, deterministic security flaws designed to test pipeline detection capabilities:

| Vulnerability Class | OWASP Classification | CWE ID | Source Location | Detection Gate | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Hardcoded Secrets** | OWASP Top 10 A05:2021<br>*(Security Misconfiguration)* | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [`src/middleware/auth.js`](file:///s:/gravity%20projects/REST%20API%20Security%20CICD%20Orchestrator/src/middleware/auth.js#L10)<br>[`src/routes/auth.js`](file:///s:/gravity%20projects/REST%20API%20Security%20CICD%20Orchestrator/src/routes/auth.js#L80) | **SAST (Semgrep)** | **CRITICAL / HIGH** |
| **NoSQL Injection** | OWASP Top 10 A03:2021<br>*(Injection)* / API8:2023 | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | [`src/routes/auth.js`](file:///s:/gravity%20projects/REST%20API%20Security%20CICD%20Orchestrator/src/routes/auth.js#L68) | **SAST (Semgrep)**<br>**DAST (OWASP ZAP)** | **HIGH** |
| **Broken Object Level Authorization (BOLA)** | OWASP API Top 10 API1:2023<br>*(Broken Object Level Auth)* | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | [`src/routes/user.js`](file:///s:/gravity%20projects/REST%20API%20Security%20CICD%20Orchestrator/src/routes/user.js#L28)<br>[`src/routes/user.js`](file:///s:/gravity%20projects/REST%20API%20Security%20CICD%20Orchestrator/src/routes/user.js#L61) | **SAST (Semgrep)**<br>**DAST (OWASP ZAP)** | **HIGH** |

### Exploit Demonstration Details

#### 1. Hardcoded Secrets (CWE-798)
- **Flaw**: Cryptographic signing key `HARDCODED_JWT_SECRET = "supersecret_jwt_devsecops_orchestrator_key_2026"` is committed in plaintext.
- **Risk**: Any actor reading the source code can forge arbitrary JWTs with `role: "admin"` to achieve complete API takeover.

#### 2. NoSQL Injection (CWE-943)
- **Flaw**: `POST /api/auth/login` passes unsanitized JSON bodies directly into Mongoose `User.findOne({ email: req.body.email, password: req.body.password })`.
- **Exploit Payload**:
  ```bash
  curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": {"$ne": null}, "password": {"$gt": ""}}'
  ```
- **Result**: MongoDB matches non-empty values, immediately bypassing authentication and returning a signed JWT for the primary administrator account (`alice_admin`).

#### 3. Broken Object Level Authorization / BOLA (CWE-639)
- **Flaw**: `GET /api/users/:id` and `PUT /api/users/:id` look up records strictly using the `:id` path parameter without checking if `req.user.id === req.params.id`.
- **Exploit**: An unprivileged user with a valid token simply supplies another user's Mongo ID:
  ```bash
  curl -X GET http://localhost:5000/api/users/660000000000000000000002 \
    -H "Authorization: Bearer <ALICE_JWT_TOKEN>"
  ```
- **Result**: Immediate leakage of sensitive PII, including private salary ($95,000) and Social Security Numbers (`888-23-4567`).

---

## 🤖 The Security Automation Engine (`security_gate.py`)

The pipeline relies on a modular Python orchestrator (`scripts/security_gate.py`) operating without external third-party dependencies to ensure seamless portability across all runner environments.

### Key Capabilities:
- **Universal Schema Parser**: Normalizes outputs from:
  - **Semgrep SAST** (`results[]`)
  - **OWASP ZAP DAST** (`site[].alerts[]`)
  - **OWASP Dependency-Check SCA** (`dependencies[].vulnerabilities[]`)
  - **NPM Audit SCA** (`vulnerabilities{}`)
- **Policy as Code Enforcement**: Configurable `--fail-on` thresholds (defaults to `CRITICAL,HIGH`).
- **Deterministic Process Exit**: Emits exit code `1` upon violation to automatically fail CI jobs and trigger branch protection rules.
- **GitHub Step Summary Integration**: Generates formatted Markdown tables uploaded straight to the GitHub Actions workflow UI.
- **Cross-Platform Resilience**: Auto-detects and supports UTF-8, UTF-8-BOM, and UTF-16 (handling PowerShell `>` redirects on Windows and Linux runners).

### CLI Usage:
```bash
# Auto-detect tool and enforce High/Critical policy
python security_gate.py --file reports/semgrep-report.json

# Explicit tool configuration with GitHub summary export
python security_gate.py \
  --file reports/zap-report.json \
  --tool zap \
  --fail-on CRITICAL,HIGH \
  --export-markdown reports/zap-summary.md
```

---

## 🚀 Running the Project Locally

### 1. Prerequisites
- **Node.js** >= 18.x
- **Python** >= 3.8
- **Docker** (optional, for local OWASP ZAP container scans)
- **MongoDB** (optional; the application includes an automatic zero-dependency in-memory mock fallback)

### 2. Installation & Setup
```bash
# Clone the repository
git clone https://github.com/Santhosh939s/REST-API-Security-CICD-Orchestrator.git
cd REST-API-Security-CICD-Orchestrator

# Install dependencies
npm install

# Configure environment (optional)
cp .env.example .env
```

### 3. Start the API Service
```bash
npm start
# Server listens on port 5000
# [!] In-memory fallback activates automatically if MongoDB is not running locally
```

### 4. Verify Health & Seed Data
```bash
# Check liveness
curl http://localhost:5000/health

# Seed mock accounts (Alice Admin & Bob Developer)
curl -X POST http://localhost:5000/api/seed
```

### 5. Execute Security Scans Locally

#### Run SAST (Semgrep)
```bash
pip install semgrep
semgrep scan --config .semgrep.yml --json -o reports/semgrep-report.json
python security_gate.py --file reports/semgrep-report.json
```

#### Run SCA (NPM Audit / Dependency-Check)
```bash
npm audit --json > reports/sca-report.json
python security_gate.py --file reports/sca-report.json
```

#### Run DAST (OWASP ZAP via Docker)
```bash
# Start API in one terminal
node server.js

# In another terminal, trigger ZAP Baseline scan:
docker run --rm --net=host -v $(pwd)/reports:/zap/wrk/:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -J zap-report.json -r zap-report.html -I

# Evaluate with gatekeeper
python security_gate.py --file reports/zap-report.json
```

---

## ⚙️ GitHub Actions Workflow (`devsecops-pipeline.yml`)

The CI/CD pipeline triggers automatically on every push or pull request targeting `main`:

```yaml
jobs:
  sca-gate:
    name: "SCA Gate: OWASP Dependency-Check"
    # Scans package.json for third-party CVEs and executes security_gate.py

  sast-gate:
    name: "SAST Gate: Semgrep Code Scan"
    # Executes custom repository rules (.semgrep.yml) + OWASP Top 10 rulesets

  dast-gate:
    name: "DAST Gate: OWASP ZAP Staging Scan"
    # Spins up background Node.js service, polls /health, seeds test data,
    # executes containerized OWASP ZAP baseline scan, and evaluates findings
```

### Security Artifacts Produced:
- `sast-security-reports`: Semgrep JSON reports and violation logs.
- `dast-security-reports`: OWASP ZAP HTML interactive report & JSON findings.
- `sca-security-reports`: Dependency-Check & NPM audit reports.
- **GitHub Step Summaries**: Visual tables displaying gate decision, severity breakdown, and CWE mappings directly on GitHub's Action Run overview page.

---

## 🧑‍💻 DevSecOps Competencies Demonstrated

- **Application Security Engineering**: Practical modeling and demonstration of OWASP Top 10 API vulnerabilities (BOLA, NoSQL Injection, Secret Leakage).
- **Automated Security Pipelines**: Multi-stage orchestration linking static analysis, containerized dynamic testing, and software composition analysis.
- **Custom Security Tooling**: Python-based normalization engine providing policy-as-code enforcement without vendor lock-in.
- **Vulnerability Management & Triage**: Clear remediation guidance, CWE mapping, and automated build-breaking thresholds to prevent insecure releases.
- **Cloud-Native CI/CD Resilience**: Clean background daemon lifecycle management, container network bridging, and fallback test harnesses.

---

## 📄 License & Disclaimer

This project is licensed under the [ISC License](LICENSE).

> ⚠️ **DISCLAIMER**: The code in this repository contains intentionally vulnerable endpoints constructed exclusively for educational, DevSecOps training, and security tool benchmarking purposes. Do NOT deploy this API to production environments.
