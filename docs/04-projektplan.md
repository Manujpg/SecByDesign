# Projektplan und Aufgabenteilung – PraxisTermin

> Stand: 02.10.2026 (Woche 1) · Laufzeit: 10 Wochen + Puffer, Daten werden nach
> Bekanntgabe des Abgabetermins angepasst.

## 1. Rollen im Team

| | Manuel (M) | Laszlo (L) |
|---|---|---|
| Schwerpunkt | Anwendung (Backend-Kern, Frontend-Grundgerüst) und **CI/CD-Lieferkette** | **Kubernetes-Sicherheit**, Deployment/Reproduzierbarkeit, ausgewählte Fachfunktionen |
| Bewertungsgewicht (ca.) | Secure Coding & App-Security 15 + MFA 10, CI/CD 20, Anteil Architektur | Kubernetes Security 15, Repository & Reproduzierbarkeit 7, Threat Modeling 15 (Federführung), Anteil Architektur |
| Doku-Kapitel | Ziel/Architektur/Tech-Stack, Security Requirements, Sicherheitsfeatures der Anwendung, Pipeline | Komponentenbeschreibung K8s, Threat Modeling (DFD, STRIDE, Attack Tree), Deployment-Prozess, nicht-sichere Parts, Lessons Learned |

Die Punkte verteilen sich damit etwa gleich. Keiner muss „die Website“ im klassischen Sinn
bauen: Die Oberfläche entsteht fast vollständig aus shadcn/ui-Komponenten nach dem
Designsystem, der Eigenanteil liegt bei drei kleinen Komponenten und den Seiten-Skeletten.

## 2. Aufgabenpakete

### Manuel

| # | Paket | Inhalt | Ergebnis |
|---|---|---|---|
| M1 | Repo & Grundgerüst | Ordnerstruktur, README, VERSION.txt, .gitignore, Branch Protection, GHCR | lauffähiges leeres Repo |
| M2 | Backend-Kern | FastAPI-Skeleton, Settings aus Env, SQLAlchemy-Modelle, Alembic, Fehler-Handler mit Request-ID, Health-Endpunkte | `uvicorn` startet, `/healthz` grün |
| M3 | Auth & Sessions | Registrierung, Argon2id, Login, Sessions (Cookie), Logout, Passwortwechsel, Brute-Force-Zähler, Admin-Bootstrap mit `must_change_password` | SR-01, SR-05, SR-07, SR-08 |
| M4 | MFA | TOTP-Setup/Confirm/Verify, Recovery-Codes, Pflicht für privilegierte Rollen | SR-02 (+10 P.) |
| M5 | RBAC & Patient-API | `require_role`/`require_owner`, Services/Doctors/Slots lesen, Termin buchen/stornieren, Audit-Log | SR-03, SR-04, SR-11 |
| M6 | Frontend-Grundgerüst | Vite + Tailwind + shadcn, Tokens, AppShell, Auth-Seiten, MFA-Seiten, Buchungsflow, „Meine Termine“, Pflichtseiten | Designsystem umgesetzt |
| M7 | Dockerfiles | Multi-Stage Backend (python-slim, non-root) und Frontend (node build → nginx-unprivileged), Digest-Pins, nginx-Security-Header/CSP | zwei Images, lokal baubar |
| M8 | Pipeline Scans | Workflow: SBOM (Syft), SAST (Semgrep, Bandit), SCA (Trivy fs, pip-audit, npm audit), Secret-Scan (Gitleaks), Reports als Artefakte | Evidence-Ordner füllen sich |
| M9 | Pipeline Build & Gate | Container-Build, Image-Scan, Image-SBOM, `quality-gate.py`, Push nach GHCR mit Digest-Ausgabe, cosign (Bonus), Evidence-Commit | Gate bricht nachweislich ab |
| M10 | Doku-Anteile | Kapitel a, d, f (Pipeline) und Security Requirements | |

### Laszlo

| # | Paket | Inhalt | Ergebnis |
|---|---|---|---|
| L1 | kind & Ingress | `infrastructure/kind/cluster.yaml` (Port-Mapping 80/443), ingress-nginx-Installation, selbstsigniertes TLS-Zertifikat als Secret | Cluster lokal startbar |
| L2 | Namespace & Identität | Namespace `praxis-termine`, drei ServiceAccounts ohne Rechte, `automountServiceAccountToken: false`, ResourceQuota/LimitRange | SR-10 (a, b) |
| L3 | Workloads gehärtet | Deployments Frontend/Backend, StatefulSet Postgres mit PVC, Init-Container Migration, Probes, Requests/Limits, vollständiger SecurityContext, emptyDir für Schreibpfade | SR-10 (c) |
| L4 | NetworkPolicies | default-deny Ingress+Egress, Allow: Ingress-Controller → Frontend/Backend, Backend → Postgres, DNS-Egress; Connectivity-Tests | SR-10 (d) |
| L5 | Secrets & Konfiguration | `scripts/generate-secrets.sh` (DB-Passwörter, Session-Key, Admin-Initialpasswort), ConfigMap, DB-Init-Skript mit zwei DB-Rollen, Kustomize base/overlays | SR-06 (K8s-Seite) |
| L6 | Makefile | `make up` (Cluster → Ingress → Namespace → Secrets → Image laden → Manifeste → Warten → „Ready“), `make down`, `make smoke`, `make bundle` (Abgabe-Zip) | Reproduzierbarkeit 7 P. |
| L7 | Deploy-Stage Pipeline | Job `deploy-test`: kind im Runner, Pull per Digest aus GHCR, Overlay `ci`, Rollout-Wait, Smoke-Test, Logs als Evidence (`run/`) | Pipeline deployt über Registry |
| L8 | Fachfunktionen Praxis | Backend-Endpunkte + Seiten für Personal (Terminverwaltung, Patientensuche, Slot-Pflege) und Ärzt:in (Tagesplan, Status) | Rollen STAFF/DOCTOR nutzbar |
| L9 | Admin-Funktionen | Benutzer-/Rollenverwaltung, Ärzt:innen, Leistungen, Audit-Ansicht (Backend + Frontend) | Rolle ADMIN nutzbar |
| L10 | Threat Modeling (Federführung) | DFD mit Vertrauensgrenzen, STRIDE-Tabellen (gemeinsamer Workshop), Attack Tree Worst Case, Gegenmaßnahmen-Mapping | Ordner `docs/threat-model` |
| L11 | Doku-Anteile | Kapitel b, c, e, f (Deployment), g; Präsentations-Demo-Skript | |

### Gemeinsam

| Paket | Inhalt |
|---|---|
| G1 | Architektur und Security Requirements verabschieden (Woche 1), Praxisname bestätigen |
| G2 | STRIDE-Workshop (Woche 3): Komponenten und grenzüberschreitende Datenflüsse gemeinsam bewerten, Zuordnung „umgesetzt / begründet nicht umgesetzt“ |
| G3 | Code-Reviews über Pull Requests (jeder reviewt den anderen), Security-Checkliste im PR-Template |
| G4 | Integrationstests Ende Woche 6 und Woche 8 (voller Durchlauf `make up` + Pipeline) |
| G5 | Doku-Zusammenführung, Lessons Learned, Präsentation (15 min, Demo-Ablauf üben) |

## 3. Zeitplan (10 Wochen)

| Woche | Manuel | Laszlo | Meilenstein |
|---|---|---|---|
| **1** (02.–08.10.) | M1 Repo, Architektur, Security Requirements, Designsystem | Toolchain installieren, L1 kind + Ingress, Mitarbeit Architektur | Architektur & SRs verabschiedet, Repo auf GitHub |
| **2** | M2 Backend-Kern, M7 Dockerfile Backend (erster Build) | L2 Namespace/SA, L3 Workloads (mit Platzhalter-Images), L5 Secrets-Skript | Backend läuft im Cluster, `/healthz` über Ingress |
| **3** | M3 Auth & Sessions, M8 Pipeline Scans (erste Reports) | L4 NetworkPolicies, L6 Makefile v1, **G2 STRIDE-Workshop** | `make up` → „Ready“; erste Evidence-Dateien |
| **4** | M5 RBAC & Patient-API, M6 Frontend-Grundgerüst + Auth-Seiten | L10 DFD + STRIDE-Tabellen, L7 Deploy-Stage Pipeline | Pipeline durchgängig grün inkl. Deploy-Test |
| **5** | M4 MFA, M6 Buchungsflow | L8 Praxis-Funktionen (Backend) | Patient:in kann buchen |
| **6** | M9 Build & Quality Gate, Image-Scan, Push mit Digest, Evidence-Commit | L8 Praxis-Seiten (Frontend), L10 Attack Tree | **G4 Integrationstest 1** |
| **7** | Secure-Coding-Review, Tests, Header/CSP-Feinschliff | L9 Admin-Funktionen | Alle Rollen nutzbar |
| **8** | cosign (Bonus), Pipeline-Härtung (SHA-Pins, Permissions), Doku a/d/f | L6 Makefile final, `make bundle`, Doku b/c/e | **G4 Integrationstest 2** |
| **9** | Doku-Finish, nicht-sichere Parts, Lessons Learned | Doku-Finish, Demo-Skript | Dokumentation vollständig |
| **10** | Abgabe-Zip, VERSION.txt, finale Evidence | Repo-Freigabe an Dozent, Präsentation üben | **Abgabe + Präsentation** |

## 4. Arbeitsweise

- **Branches:** `main` geschützt (PR erforderlich, alle Checks grün). Feature-Branches
  `feat/<paket>` (z. B. `feat/m3-auth`, `feat/l4-netpol`). Kleine PRs, täglich mergen.
- **Pipeline:** Auf PRs laufen alle Scans und Gates ohne Push/Deploy; auf `main` die volle Pipeline.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `infra:`). Pushes/Pulls über GitHub Desktop.
- **Secrets:** Nie committen. Lokale Werte in `.env` (ignoriert), Vorlage `.env.example`.
- **Definition of Done je Paket:** Code + Tests grün, Pipeline grün, zugehöriges Doku-Kapitel
  aktualisiert, Security Requirement in `02-security-requirements.md` als „umgesetzt“ markiert.
- **Kommunikation:** Kurzes Sync zweimal pro Woche; Entscheidungen landen in `01-architektur.md`, Abschnitt 10.

## 5. Risiken und Gegenmaßnahmen

| Risiko | Auswirkung | Gegenmaßnahme |
|---|---|---|
| Quality Gate blockiert durch HIGH-CVE in Basis-Image | Pipeline rot, kein Push | Schlanke Basis-Images (python:3.14-alpine statt slim, siehe ADR A13; nginx-unprivileged alpine), wöchentliches Rebuild, dokumentierte Ausnahmen nur mit Begründung in `.trivyignore` |
| kind im GitHub-Runner zu langsam/instabil | Deploy-Test flaky | Timeouts großzügig, ein Replica, Images per Digest cachen; Fallback: Deploy-Test nur auf `main` |
| Frontend-Aufwand unterschätzt | Zeitverzug | Strikt shadcn/ui, Seiteninventar nicht erweitern, Admin-Seiten als einfache Tabellen |
| Evidence-Commit aus Pipeline kollidiert mit Branch Protection | Evidence fehlt im Repo | Bot-Commit mit `[skip ci]` auf `main` per PAT mit `contents:write`, alternativ Evidence-PR |
| Windows-Toolchain (make, bash) | `make up` läuft nicht auf Windows; **eingetreten 19.10.:** Smart App Control blockiert `make.exe`, `kind.exe` und kompilierte Python-Erweiterungen | `make up` in WSL2 (ADR A14); Backend-Tests unter Windows mit SQLAlchemy ohne C-Erweiterung; CI läuft unter Linux und ist nicht betroffen |

## 6. Nächste konkrete Schritte (diese Woche)

1. **Manuel:** GitHub-Repo (privat) anlegen, dieses Grundgerüst committen, Laszlo und Dozent einladen, Branch Protection setzen.
2. **Laszlo:** kind, kubectl, make, Docker Desktop installieren; `kind create cluster` testen; Architektur lesen und Rückfragen notieren.
3. **Beide:** Security Requirements durchgehen und abzeichnen; Praxisname bestätigen.
4. **Manuel:** Woche 2 starten mit M2 (Backend-Kern) und M7 (Dockerfile Backend).

## 7. Fortschritt

| Datum | Paket | Stand |
|---|---|---|
| 07.10.2026 | M1 | Repo `Manujpg/SecByDesign` angelegt, Skelett gepusht, Branch Protection auf `main` |
| 19.10.2026 | M2 | Backend-Kern fertig: Konfiguration ohne Default-Secrets, JSON-Logging mit Request-ID, einheitliche Fehlerantworten ohne Informationslecks, Security-Header, Health/Ready, Datenmodell mit DB-Constraints (u. a. Schutz vor Doppelbuchung), Alembic-Migration 0001 mit append-only Audit-Log, Dev-PostgreSQL mit zwei DB-Rollen, 25 Tests grün, Ruff und Bandit ohne Funde |
| 19.10.2026 | M7 (Backend) | Dockerfile Multi-Stage auf `python:3.14-alpine` (Digest gepinnt), Hash-geprüfte Abhängigkeiten, non-root, read-only lauffähig; Trivy: 0 HIGH/CRITICAL; pip-audit: keine bekannten Schwachstellen |
| 19.10.2026 | M3 | Registrierung (ohne Konto-Enumeration), Login mit Argon2id und Dummy-Hash, serverseitige Sitzungen (`__Host-session`, Idle 30 min, absolut 8 h, Rotation, Widerruf), Passwortwechsel mit Abmeldung aller Geräte, Brute-Force-Sperre pro E-Mail-Kennung und IP, CSRF-Schutz per Origin-Prüfung, Audit-Log, Admin-Bootstrap mit Pflicht-Passwortwechsel, Rollen-Gates; 87 Tests grün, Trivy/pip-audit/Bandit ohne Funde |
| 19.10.2026 | M4 | TOTP-MFA: Einrichtung mit otpauth-URI und Bestätigung, AES-GCM-verschlüsselte Secrets (an Nutzer-ID gebunden), Replay-Schutz, ±30 s Toleranz, Sperre nach Fehlversuchen pro Sitzung und Konto, 8 Recovery-Codes (HMAC, einmalig), Pflicht und nicht abschaltbar für STAFF/DOCTOR/ADMIN, Onboarding Passwortwechsel -> MFA -> Zugriff; 113 Tests grün, Scans ohne Funde |
| 19.10.2026 | M8 (Teil 1) | GitHub-Actions-Pipeline: Gitleaks (gesamte Historie), Syft-SBOM (CycloneDX), Semgrep + Bandit, Ruff + pytest, zentrales Quality Gate mit Evidence-Paket je Lauf (19 Tests für das Gate). Offen: SCA-Job (Manuel, Anleitung `docs/anleitungen/m8-pipeline.md`), Actions-Einstellungen, Evidence ins Repo |
