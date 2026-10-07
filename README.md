# PraxisTermin – Terminbuchung für die Ärztehaus Lindle

Prüfungsleistung **Security by Design** (STG-TINF24F) · Team: Manuel Sposato, Laszlo
Version: siehe [`VERSION.txt`](VERSION.txt)

Ein kleines, vollständiges Terminbuchungssystem (React-Frontend, FastAPI-Backend,
PostgreSQL), entwickelt nach Security-by-Design-Prinzipien und ausgeliefert über eine
reproduzierbare CI/CD-Lieferkette (SBOM, SAST, SCA, Secret-Scan, Quality Gate,
Container-Registry) auf ein lokales Kubernetes-Cluster (kind).

> **Status (Woche 1):** Architektur, Security Requirements, Designsystem und Projektplan
> sind definiert. Code, Manifeste und Pipeline folgen gemäß [Projektplan](docs/04-projektplan.md).

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/01-architektur.md](docs/01-architektur.md) | Architekturentscheidung: Ziel, Rollen, Tech-Stack, Komponenten, Laufzeit, Auth-Design, Datenmodell, API, Lieferkette, ADRs, Abweichungen |
| [docs/diagrams/architektur.svg](docs/diagrams/architektur.svg) | Architekturdiagramm der gesamten Systemlandschaft ([Mermaid-Quelle](docs/diagrams/architektur.mmd)) |
| [docs/02-security-requirements.md](docs/02-security-requirements.md) | 10 verpflichtende + 3 empfohlene Security Requirements mit Umsetzungsort und Nachweis |
| [docs/03-design-system.md](docs/03-design-system.md) | Designsystem „Lindle“: Tokens, Komponenten, Seiten, Buchungsflow, Barrierefreiheit |
| [docs/04-projektplan.md](docs/04-projektplan.md) | Aufgabenteilung, Zeitplan, Arbeitsweise, Risiken |
| docs/threat-model/ | Systemmodell, DFD, STRIDE, Attack Tree (folgt in Woche 3–6) |

## Repository-Struktur

```
.
├── frontend/                 React 19 + TypeScript + Vite + Tailwind + shadcn/ui
├── backend/                  FastAPI (Python 3.12), SQLAlchemy, Alembic
├── infrastructure/
│   ├── kind/                 kind-Cluster-Konfiguration (Port-Mapping 80/443)
│   └── k8s/                  Kustomize: base/ + overlays/{local,ci}
├── .github/workflows/        CI/CD-Pipeline (GitHub Actions)
├── scripts/                  Hilfsskripte (Secrets erzeugen, Quality Gate, Smoke-Test)
├── evidence/
│   ├── backend/{run,sast,sbom,sca,secrets}/   Nachweise aller Pipeline-Runs (Backend-Image)
│   └── frontend/{run,sast,sbom,sca,secrets}/  Nachweise aller Pipeline-Runs (Frontend-Image)
├── docs/                     Architektur, Requirements, Designsystem, Threat Model, Diagramme
├── Makefile                  Blaupause: make up / down / smoke / bundle
├── VERSION.txt               Semantische Version der Anwendung
└── README.md
```

## Setup-Guide

### Voraussetzungen

| Werkzeug | Version | Installation (Windows, PowerShell als Admin) | macOS |
|---|---|---|---|
| Docker Desktop | aktuell | https://www.docker.com/products/docker-desktop/ | `brew install --cask docker` |
| kubectl | ≥ 1.30 | in Docker Desktop enthalten | `brew install kubectl` |
| kind | ≥ 0.24 | `choco install kind` | `brew install kind` |
| GNU Make | ≥ 4 | `choco install make` | vorinstalliert |
| Git Bash | aktuell | mit Git for Windows | – |
| Node.js | 22 LTS | `choco install nodejs-lts` | `brew install node@22` |
| Python | 3.12 | `choco install python312` | `brew install python@3.12` |
| Optional lokal: Trivy, Syft, Gitleaks, Semgrep | aktuell | `choco install trivy`; Rest via Docker-Images im Makefile | `brew install trivy syft gitleaks semgrep` |

Unter Windows werden `make`-Ziele aus der **Git Bash** ausgeführt (das Makefile nutzt POSIX-sh).

### Schnellstart (Zielzustand, sobald Code und Manifeste vorhanden sind)

```bash
make up
```

führt aus: kind-Cluster erstellen → ingress-nginx installieren → Namespace und Secrets
erzeugen → Images laden (Pull per Digest aus GHCR oder lokaler Build + `kind load`) →
Manifeste anwenden → auf Health warten → `Ready` ausgeben.

Danach ist die Anwendung unter **https://localhost** erreichbar (selbstsigniertes Zertifikat,
einmalig im Browser akzeptieren). Das Initialpasswort des Admin-Kontos gibt `make up` einmalig
aus bzw. liegt im Kubernetes-Secret `admin-bootstrap`; der erste Login erzwingt Passwortwechsel
und MFA-Einrichtung.

Weitere Ziele:

```bash
make down      # Cluster löschen
make smoke     # Health- und Header-Checks über den Ingress
make build     # beide Images lokal bauen
make scan      # SBOM, SAST, SCA, Secret-Scan lokal ausführen (Docker-basiert)
make bundle    # Abgabe-Zip erzeugen (Images als .tar, digest.txt, Reports, Repo-Zip)
```

### Lokale Entwicklung ohne Cluster

```bash
# Backend
cd backend && python -m venv .venv && . .venv/Scripts/activate   # Windows Git Bash
pip install -e ".[dev]" && cp .env.example .env && uvicorn app.main:app --reload

# Frontend
cd frontend && npm ci && npm run dev
```

(Details folgen mit dem Code in Woche 2.)

## Sicherheitsüberblick

- Authentifizierung mit Argon2id, serverseitigen Sessions (`__Host-`Cookie, HttpOnly, Secure, SameSite=Strict) und TOTP-MFA (Pflicht für Praxispersonal, Ärzt:innen und Admin)
- Serverseitige Autorisierung (RBAC + objektbezogene Prüfung), strikte Eingabevalidierung, Fehlerantworten ohne Informationslecks
- Keine Secrets im Repository: alle Secrets werden zur Deploy-Zeit erzeugt; Gitleaks bricht die Pipeline bei jedem Fund ab
- Pipeline: SBOM (Syft) → SAST (Semgrep, Bandit) → SCA (Trivy, pip-audit, npm audit) → Secret-Scan (Gitleaks) → Build → Image-Scan → Quality Gate (Abbruch bei Secrets oder CVSS ≥ 7.0) → Push nach GHCR → Deploy-Test in kind → Evidence
- Kubernetes Least Privilege: eigener Namespace, ServiceAccounts ohne Rechte, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, NetworkPolicy default-deny

Vollständige Liste: [Security Requirements](docs/02-security-requirements.md).

## Lizenz / Hinweis

Studienprojekt. Alle Praxisdaten, Namen und Kontaktangaben sind fiktiv.
