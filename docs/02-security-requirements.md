# Security Requirements – PraxisTermin

> Stand: 02.10.2026 · Version 0.1.0
> Gefordert sind mindestens fünf verpflichtende Security Requirements. Wir definieren
> **zehn verpflichtende (MUST)** und **drei empfohlene (SHOULD)**. Jedes Requirement
> benennt Umsetzungsort und Nachweis, damit die Konsistenz Architektur ↔ Umsetzung
> später prüfbar ist.

Verantwortlich: M = Manuel, L = Laszlo. Bezug: Kapitel in `01-architektur.md`.

| ID | Requirement | Umsetzung (wo) | Nachweis / Test | Verantw. |
|---|---|---|---|---|
| **SR-01** | **Sichere Authentifizierung.** Jede Funktion außer Registrierung, Login, Stammdaten-Lesen und Health-Probes erfordert eine gültige Sitzung. Passwörter werden ausschließlich als Argon2id-Hash gespeichert (min. 12 Zeichen, Prüfung gegen Top-10k-Liste). Login-Fehler sind nicht unterscheidbar (gleiche Meldung, konstante Antwortzeit). | Backend `app/auth/*`, Kap. 6 | pytest: Hash-Format, Fehlertexte identisch, Timing-Test; Semgrep-Regel gegen Klartext-Passwörter | M |
| **SR-02** | **MFA (TOTP) verpflichtend für privilegierte Rollen.** STAFF, DOCTOR und ADMIN müssen beim ersten Login TOTP einrichten; ohne bestätigte MFA sind nur Passwortwechsel und MFA-Setup erreichbar. PATIENT optional. Recovery-Codes gehasht. | Backend `app/auth/mfa.py`, Frontend Setup-Dialog | pytest: Zugriff auf `/staff/*` ohne MFA → 403; TOTP-Fenster ±1 Schritt | M |
| **SR-03** | **Serverseitige Autorisierung (RBAC + Objektbezug).** Jede Route deklariert erlaubte Rollen; zusätzlich wird geprüft, dass Patient:innen nur eigene Termine/Daten und Ärzt:innen nur eigene Termine sehen oder ändern (Schutz vor IDOR). Das Frontend blendet nur aus, entscheidet nie. | Backend Dependencies `require_role`, `require_owner`, Kap. 2 | pytest-Matrix Rolle × Endpunkt; Negativtests mit fremder ID → 404 (nicht 403, kein Existenz-Leak) | M (API), L (Staff-/Doctor-Endpunkte) |
| **SR-04** | **Strikte Eingabevalidierung.** Alle Eingaben (Body, Query, Path, Header) werden gegen Pydantic-Schemas mit Typ, Länge, Format und Allow-Lists geprüft (`extra="forbid"`). Datenbankzugriffe ausschließlich über ORM-Parameterbindung. Freitext ist auf 200 Zeichen begrenzt und wird nur als Text ausgegeben. | Backend Schemas, Frontend zod-Schemas (Spiegel) | pytest: Fuzzing ungültiger Payloads → 422; Semgrep SQL-Injection-Regeln; kein `raw SQL` | M |
| **SR-05** | **Fehlerbehandlung ohne Informationslecks.** Einheitliches Fehlerschema mit `request_id`; keine Stacktraces, Datenbankfehler, Pfade oder Versionsnummern in Antworten. Unerwartete Ausnahmen → generischer 500 mit Log-Eintrag serverseitig. OpenAPI-UI im Cluster deaktiviert. | Backend Exception-Handler, uvicorn-Konfiguration, nginx `server_tokens off` | pytest: provozierter Fehler enthält kein `Traceback`; Header `Server` entfernt | M |
| **SR-06** | **Secret-Hygiene.** Keine Secrets, Zertifikate oder Zugangsdaten im Repository. Alle Secrets werden zur Deploy-Zeit erzeugt (Makefile / Pipeline) und als Kubernetes-Secrets nur den Pods bereitgestellt, die sie brauchen. Secret-Scan bricht die Pipeline bei jedem Fund ab. | `.gitignore`, `scripts/generate-secrets.sh`, Gitleaks-Job, Manifeste | Gitleaks-Report = 0 Findings; `kubectl get secret -n praxis-termine` zeigt nur generierte Secrets | M (Pipeline), L (K8s) |
| **SR-07** | **Sichere Sitzungen und CSRF-Schutz.** Opake 256-Bit-Tokens, in der DB gehasht; Cookie `__Host-session` mit `HttpOnly; Secure; SameSite=Strict`; Idle-Timeout 30 min, absolut 8 h; Rotation nach Login/MFA/Passwortwechsel; Logout invalidiert serverseitig; Origin-Prüfung auf allen zustandsändernden Requests. | Backend `app/auth/session.py`, Middleware | pytest: Cookie-Flags, Ablauf, Reuse nach Logout → 401; Request ohne/mit fremdem Origin → 403 | M |
| **SR-08** | **Brute-Force- und Missbrauchsschutz.** Fehlversuche pro Konto und pro IP werden gezählt; nach 10 Fehlversuchen 15 min Sperre; Rate-Limit am Gateway auf `/api/v1/auth/*` (lokales Envoy-Rate-Limit, ohne Redis); Registrierung und Buchung limitiert. Sperren werden auditiert. Die Client-IP kommt per `X-Forwarded-For` von Envoy, das Backend vertraut nur dem Proxy (`FORWARDED_ALLOW_IPS`). | Backend Login-Service, `infrastructure/k8s/base/routes.yaml` (`BackendTrafficPolicy`), `gateway.yaml` (`ClientTrafficPolicy`) | pytest: 11. Versuch → 423/429; Smoke-Test: Burst auf `/api/v1/auth/login` → 429 mit `x-envoy-ratelimited` | M (App), L (Gateway) |
| **SR-09** | **Transportsicherheit und Browser-Härtung.** TLS ≥ 1.2 am Gateway-Listener (HTTP → HTTPS per HTTPRoute-Redirect), HSTS per `ResponseHeaderModifier`, CSP ohne `unsafe-inline`/`unsafe-eval`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` minimal. | nginx-Konfiguration Frontend, Backend-Middleware, `infrastructure/k8s/base/gateway.yaml` + `routes.yaml` | Smoke-Test prüft Header und `http://` → 301; Mozilla-Observatory-ähnliche Checkliste in Doku | M (nginx/Backend), L (Gateway/TLS) |
| **SR-10** | **Least Privilege in Kubernetes.** Eigener Namespace mit Pod Security Admission `restricted`, ResourceQuota und LimitRange; je Komponente ein ServiceAccount ohne Rechte und ohne Token-Automount; `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`; NetworkPolicy default-deny für Ingress und Egress mit expliziten Allow-Regeln; DB-Laufzeitkonto nur mit DML-Rechten. | `infrastructure/k8s/**`, DB-Init-Skript | kube-linter / Trivy config in Pipeline; `make check-k8s` (`kubectl auth can-i --as=system:serviceaccount:...` = no, Token-Automount aus, PSA aktiv); Connectivity-Test Frontend → DB schlägt fehl | L |
| SR-11 (SHOULD) | **Audit-Logging.** Sicherheitsrelevante Ereignisse werden append-only mit Zeit, Akteur, Aktion, Ziel, Request-ID, IP protokolliert, ohne Passwörter oder Gesundheitsdaten; Admin kann das Log einsehen. | Backend `app/audit.py`, Tabelle `audit_log` | pytest: Login-Fehlversuch erzeugt Eintrag; Laufzeitkonto kann nicht `DELETE` | M |
| SR-12 (SHOULD) | **Supply-Chain-Integrität.** SBOM (CycloneDX) je Image; Basis-Images und GitHub-Actions per Digest/SHA gepinnt; Images werden per Digest deployt; optional cosign-Signatur. | Dockerfiles, Workflow, Kustomize-Overlays | SBOM-Dateien in `/evidence`; `image-ref.txt` mit Digest; `cosign verify` | M (Pipeline), L (Deploy per Digest) |
| SR-13 (SHOULD) | **Datensparsamkeit.** Es werden nur die für die Terminvergabe nötigen Daten erhoben (Name, Geburtsdatum, Kontakt, Versicherungsart, Besuchsgrund als Kategorie). Patient:innen können ihr Konto selbst deaktivieren; Termine werden nach 12 Monaten anonymisiert (Job später). | Datenmodell Kap. 7 | Review des Datenmodells; keine Freitext-Diagnosefelder | M |

## Zuordnung zur Bewertungsmatrix

| Bewertungskriterium | Abgedeckt durch |
|---|---|
| Security Requirements (5 P.) | diese Tabelle |
| Secure Coding (5 P.) | SR-04, SR-05, SR-07 |
| Berechtigungskonzept (5 P.) | SR-01, SR-03, SR-10 |
| Secret-Hygiene (5 P.) | SR-06 |
| MFA (+10 P.) | SR-02 |
| Security Kontext / Namespace + SA / Network Policy (15 P.) | SR-10 |
| SBOM / SAST-SCA-Secrets / Quality Gate (20 P.) | SR-06, SR-12, Pipeline-Kapitel |

## Umgang mit STRIDE (Vorgriff auf Threat Modeling)

Von den sechs STRIDE-Kategorien müssen drei (teilweise) umgesetzt werden. Geplante Zuordnung,
wird im Threat Model verfeinert:

| STRIDE | Umsetzung | Requirement |
|---|---|---|
| Spoofing | **umgesetzt** (Argon2id, MFA, Sessions, Brute-Force-Schutz) | SR-01, SR-02, SR-07, SR-08 |
| Tampering | **umgesetzt** (Validierung, ORM, CSRF, Digest-gepinnte Images, read-only FS) | SR-04, SR-07, SR-10, SR-12 |
| Elevation of Privilege | **umgesetzt** (RBAC, IDOR-Schutz, K8s Least Privilege, DB-Rollen) | SR-03, SR-10 |
| Information Disclosure | teilweise (Fehlerbehandlung, TLS, Header); Verschlüsselung at rest bewusst nicht | SR-05, SR-09 |
| Repudiation | teilweise (Audit-Log als SHOULD); keine signierten Logs, kein externes SIEM | SR-11 |
| Denial of Service | nur Basis (Rate-Limit, Ressourcenlimits); kein WAF/Autoscaling – begründet: lokales Cluster, kein Internet-Exposure | SR-08 |
