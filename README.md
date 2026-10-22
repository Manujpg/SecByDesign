# PraxisTermin – Terminbuchung für die Ärztehaus Lindle

Prüfungsleistung **Security by Design** (STG-TINF24F) · Team: Manuel Sposato, Laszlo
Version: siehe [`VERSION.txt`](VERSION.txt)

Ein kleines, vollständiges Terminbuchungssystem (React-Frontend, FastAPI-Backend,
PostgreSQL), entwickelt nach Security-by-Design-Prinzipien und ausgeliefert über eine
reproduzierbare CI/CD-Lieferkette (SBOM, SAST, SCA, Secret-Scan, Quality Gate,
Container-Registry) auf ein lokales Kubernetes-Cluster (kind).

> **Status (19.10.2026):** Architektur, Security Requirements, Designsystem und Projektplan
> sind definiert. Backend-Kern (Paket M2) mit Datenmodell, Migrationen, Fehlerbehandlung,
> Health-Endpunkten und gehärtetem Dockerfile steht, siehe [backend/README.md](backend/README.md).
> Frontend, Manifeste und Pipeline folgen gemäß [Projektplan](docs/04-projektplan.md).

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
├── backend/                  FastAPI (Python 3.14), SQLAlchemy, Alembic
├── infrastructure/
│   ├── kind/                 kind-Cluster-Konfiguration (Port-Mapping 127.0.0.1:80/443)
│   ├── gateway/              Envoy Gateway: GatewayClass + Proxy-Konfiguration (NodePort für kind)
│   └── k8s/                  Kustomize: base/ (Namespace, SAs, Quota, Gateway, Routen) + overlays/{local,ci}
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
| kind | ≥ 0.24 | in WSL2 (siehe unten) | `brew install kind` |
| GNU Make | ≥ 4 | in WSL2: `sudo apt install make` | vorinstalliert |
| Git Bash | aktuell | mit Git for Windows | – |
| Node.js | 22 LTS | `choco install nodejs-lts` | `brew install node@22` |
| Python | 3.14 | `choco install python314` | `brew install python@3.14` |
| Optional lokal: Trivy, Syft, Gitleaks, Semgrep | aktuell | `choco install trivy`; Rest via Docker-Images im Makefile | `brew install trivy syft gitleaks semgrep` |

**Windows-Hinweis:** Ist die „Intelligente App-Steuerung“ (Smart App Control) aktiv, blockiert
Windows unsignierte Programme wie `make.exe` und `kind.exe`. `make up` läuft deshalb unter Windows
in **WSL2 (Ubuntu)**, das Docker Desktop ohnehin nutzt. Einmalige Einrichtung in der Ubuntu-Shell:

```bash
sudo apt update && sudo apt install -y make curl openssl
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64 && chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind
# falls "kubectl" in WSL fehlt (passend zur Cluster-Version 1.35):
curl -LO https://dl.k8s.io/release/v1.35.0/bin/linux/amd64/kubectl && chmod +x ./kubectl && sudo mv ./kubectl /usr/local/bin/kubectl
```

Die Ports 80 und 443 auf `127.0.0.1` müssen frei sein (kein lokaler Webserver, IIS o. Ä.).

In Docker Desktop unter Settings → Resources → WSL Integration muss „Ubuntu“ aktiviert sein.
Das Repository erreicht man in WSL unter `/mnt/c/Users/<name>/Desktop/SecByDesign`.

### Schnellstart (Zielzustand, sobald Code und Manifeste vorhanden sind)

```bash
make up
```

führt aus: kind-Cluster erstellen → Envoy Gateway installieren (Hash-geprüft) → Namespace,
TLS-Zertifikat und Secrets erzeugen → Images laden (Pull per Digest aus GHCR oder lokaler Build + `kind load`) →
Manifeste anwenden → auf Health warten → `Ready` ausgeben.

Danach ist die Anwendung unter **https://localhost** erreichbar (selbstsigniertes Zertifikat,
einmalig im Browser akzeptieren). Das Initialpasswort des Admin-Kontos gibt `make up` einmalig
aus bzw. liegt im Kubernetes-Secret `admin-bootstrap`; der erste Login erzwingt Passwortwechsel
und MFA-Einrichtung.

Weitere Ziele:

```bash
make infra     # nur Plattform: Cluster, Gateway, Namespace, TLS, Least-Privilege-Prüfung
make check-k8s # Least Privilege im Namespace prüfen (PSA, ServiceAccounts, RBAC, Quota)
make down      # Cluster löschen
make smoke     # Health- und Header-Checks über das Gateway
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

Details zum Backend: [backend/README.md](backend/README.md).

## Sicherheitsüberblick

- Authentifizierung mit Argon2id, serverseitigen Sessions (`__Host-`Cookie, HttpOnly, Secure, SameSite=Strict) und TOTP-MFA (Pflicht für Praxispersonal, Ärzt:innen und Admin)
- Serverseitige Autorisierung (RBAC + objektbezogene Prüfung), strikte Eingabevalidierung, Fehlerantworten ohne Informationslecks
- Keine Secrets im Repository: alle Secrets werden zur Deploy-Zeit erzeugt; Gitleaks bricht die Pipeline bei jedem Fund ab
- Pipeline: SBOM (Syft) → SAST (Semgrep, Bandit) → SCA (Trivy, pip-audit, npm audit) → Secret-Scan (Gitleaks) → Build → Image-Scan → Quality Gate (Abbruch bei Secrets oder CVSS ≥ 7.0) → Push nach GHCR → Deploy-Test in kind → Evidence
- Kubernetes Least Privilege: eigener Namespace, ServiceAccounts ohne Rechte, `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, NetworkPolicy default-deny

Vollständige Liste: [Security Requirements](docs/02-security-requirements.md).

## Lizenz / Hinweis

Studienprojekt. Alle Praxisdaten, Namen und Kontaktangaben sind fiktiv.
