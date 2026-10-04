# Secure File Transfer System — DevSecOps

A Flask-based secure file-transfer application, delivered through an end-to-end CI/CD, containerized, orchestrated and monitored DevSecOps workflow.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-Web%20App-000000?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Kubernetes-Orchestrated-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes">
  <img src="https://img.shields.io/badge/Ansible-Config%20Management-EE0000?logo=ansible&logoColor=white" alt="Ansible">
  <img src="https://img.shields.io/badge/Prometheus-Monitoring-E6522C?logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/Grafana-Dashboard-F46800?logo=grafana&logoColor=white" alt="Grafana">
  <img src="https://img.shields.io/badge/GitHub%20Actions-CI%2FCD-2088FF?logo=githubactions&logoColor=white" alt="GitHub Actions">
</p>

> BTech DevOps CA | TH1

---

## Overview

| | |
|---|---|
| **Application** | Secure file transfer using hybrid cryptography |
| **Backend** | Flask + Gunicorn |
| **Encryption** | AES-256-EAX + RSA-2048-OAEP (PyCryptodome) |
| **CI/CD** | GitHub Actions → Docker → Kubernetes |
| **Configuration** | Ansible + systemd |
| **Observability** | Prometheus + Grafana |
| **Security** | Non-root containers, dropped capabilities, dependency & image scanning |

## Authors

| # | Name | Student ID |
|---|------|------------|
| 1 | Mithlesh Yadav | 23070122265 |
| 2 | Velagala Prapul Krishna Reddy | 23070122232 |
| 3 | Rishi Modi | 23070122180 |

---

## Architecture

```mermaid
flowchart LR
    A[Developer] --> B[GitHub]
    B --> C[GitHub Actions]
    C --> D[Tests + Security Scan]
    C --> E[Docker Build]
    E --> F[Kubernetes]
    G[Ansible] --> F
    F --> H[Secure File Transfer App]
    H --> I[/metrics]
    I --> J[Prometheus]
    J --> K[Grafana]
```

## Phase Summary

| Phase | Requirement | Implementation | Status |
|:-----:|-------------|----------------|:------:|
| 1 | Deployment strategy / CI-CD | GitHub Actions | ✅ |
| 2 | Configuration management / IaC | Ansible + systemd | ✅ |
| 3 | Containerization / Orchestration | Docker + Kubernetes | ✅ |
| 4 | Monitoring / Logging | Prometheus + Grafana | ✅ |
| 5 | Reflection / Report | Architecture, results, lessons | ✅ |
| 6 | External challenge / Bonus | Optional — requires submission proof | ⭕ |

---

## Repository Structure

```text
SecureFileTransfer-DevSecOps/
├── .github/workflows/ci-cd.yml      # CI/CD pipeline
├── ansible/
│   ├── files/secure-file-transfer.service
│   ├── inventory
│   └── setup.yml
├── core/                            # crypto, keygen, logger, network
├── k8s/
│   ├── deployment.yaml
│   └── service.yaml
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/
├── tests/test_application.py
├── web/                             # Flask app + templates
├── Dockerfile
├── docker-compose.monitoring.yml
├── main.py
└── requirements.txt
```

---

## Quick Start

```bash
git clone https://github.com/MITHLESH55/SecureFileTransfer-DevSecOps.git
cd SecureFileTransfer-DevSecOps

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt

python main.py                    # run locally
python -m pytest -v               # run tests
```

**Docker**

```bash
docker build -t secure-file-transfer:v1 .
docker run --rm -p 5000:5000 secure-file-transfer:v1
```

---

## Pipeline & Delivery

### 1. CI/CD — GitHub Actions

`.github/workflows/ci-cd.yml`

```text
Push / PR → Checkout → Install deps → pytest → Dependency scan
          → Docker build → Image scan → Publish / deploy → K8s smoke tests
```

- Automated unit and integration tests
- Dependency and container vulnerability scanning
- Reproducible Docker builds
- Smoke tests on `/api/version` and `/metrics`

### 2. Configuration Management — Ansible

```bash
ansible-playbook -i ansible/inventory ansible/setup.yml
```

- Installs runtime packages, creates dedicated `sftapp` user/group
- Provisions `/opt/secure-file-transfer` with an isolated virtualenv
- Deploys app files and a systemd-managed Gunicorn service
- Health-checks `/api/version` after deployment

**systemd hardening:** `NoNewPrivileges=true` · `PrivateTmp=true` · `ProtectHome=true` · `ProtectSystem=strict` · restricted write paths · non-login service user

### 3. Containerization & Orchestration

**Docker** — multi-stage build: builder → minimal runtime → security updates → non-root `appuser` → Gunicorn.

**Kubernetes** — Deployment + Service with readiness/liveness probes, resource requests/limits, non-root security context, dropped Linux capabilities and rolling-update strategy.

```bash
minikube start --driver=docker
minikube image load secure-file-transfer:v1
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl rollout status deployment/secure-file-transfer
kubectl port-forward service/secure-file-transfer 5005:5000
# → http://localhost:5005/api/version
```

| Test | Result |
|------|:------:|
| Rolling update `v1 → v2` | ✅ |
| Rollback `v2 → v1` (verified `1.0.0` via `/api/version`) | ✅ |

> **Note:** Transfer state is held in memory, so the deployment runs at **1 replica**. A multi-replica setup would require externalised shared state.

### 4. Monitoring — Prometheus + Grafana

The app exposes `GET /metrics`; Prometheus scrapes `sft-app:5000` every 5 seconds.

```bash
docker compose -f docker-compose.monitoring.yml up -d
```

| Service | URL |
|---------|-----|
| Secure File Transfer | http://localhost:5003 |
| Prometheus | http://localhost:9091 |
| Grafana | http://localhost:3001 |

Grafana dashboard: **Secure File Transfer - DevOps Monitoring**

| Metric | Purpose |
|--------|---------|
| Application Uptime | Availability |
| Request Rate | Requests per second |
| Average Latency | Response performance |
| Error Rate | Failed request percentage |

---

## Testing & Validation

```bash
python -m pytest -v
```

7 tests passing — covering sender/receiver pages, version endpoint, RSA key generation, secure end-to-end transfer and invalid transfer handling.

```bash
# Kubernetes
kubectl get deployment,pods,service

# Prometheus
curl http://localhost:<prometheus-port>/-/ready
curl http://localhost:<prometheus-port>/api/v1/targets
```

---

## Security

| Layer | Controls |
|-------|----------|
| **Application** | AES-256-EAX authenticated encryption, RSA-2048-OAEP key protection |
| **Container / Runtime** | Non-root user, dropped capabilities, privilege escalation disabled, minimal image, hardened systemd unit |
| **Pipeline** | Dependency scan and container image scan before deployment |

---

## Useful Commands

```bash
# Docker
docker images secure-file-transfer
docker scout cves secure-file-transfer:v1

# Kubernetes
kubectl rollout history deployment/secure-file-transfer
kubectl rollout undo deployment/secure-file-transfer

# Monitoring
docker compose -f docker-compose.monitoring.yml ps
```

---

## Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| Docker host-port conflicts | Remapped host ports; container ports unchanged |
| Image vulnerabilities | Hardened runtime image; added scanning to CI |
| Docker Desktop Kubernetes failed to start | Switched to Minikube (Docker driver) |
| Rollback consistency | Updated image and `APP_VERSION` in a single Deployment revision |
| Monitoring connectivity | Used Compose network target `sft-app:5000` |
| Stateful application | Kept replicas at 1 due to in-memory state |

## Lessons Learned

- CI/CD makes testing and delivery repeatable.
- Ansible reduces configuration drift.
- Docker provides a consistent runtime.
- Kubernetes enables controlled rollout and rollback.
- Prometheus + Grafana make behavior observable.
- Security checks work best *before* deployment, not after.

## Future Enhancements

- [ ] Shared storage/database for transfer state
- [ ] Multi-replica high availability
- [ ] TLS/HTTPS with certificate management
- [ ] Kubernetes Ingress
- [ ] Secret management (Kubernetes Secrets / Vault)
- [ ] Persistent audit logging
- [ ] Centralized logs (Loki / ELK)
- [ ] Production cloud deployment

---

## Academic Submission Mapping

| CA Requirement | Evidence |
|----------------|----------|
| Deployment strategy | `.github/workflows/ci-cd.yml` |
| Configuration management | `ansible/setup.yml`, `ansible/inventory` |
| Service configuration | `ansible/files/secure-file-transfer.service` |
| Dockerization | `Dockerfile` |
| Kubernetes deployment / service | `k8s/deployment.yaml`, `k8s/service.yaml` |
| Rolling update | `kubectl rollout history` / v2 verification |
| Rollback | `kubectl rollout undo` / v1 verification |
| Metrics | `/metrics` endpoint |
| Prometheus | `monitoring/prometheus.yml` |
| Grafana | `monitoring/grafana/` |
| Tests | `tests/test_application.py` |
| Documentation | `README.md` |

---

<p align="center">
  <b>Secure File Transfer System • DevOps / DevSecOps CA</b><br>
  Built with Python, Docker, Kubernetes, Ansible, GitHub Actions, Prometheus & Grafana<br>
  <a href="https://github.com/MITHLESH55/SecureFileTransfer-DevSecOps">GitHub Repository</a>
</p>
