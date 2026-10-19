# PraxisTermin – Backend

FastAPI (Python 3.14), SQLAlchemy 2, Alembic, PostgreSQL 16.
Architektur und Sicherheitsanforderungen: [`docs/01-architektur.md`](../docs/01-architektur.md),
[`docs/02-security-requirements.md`](../docs/02-security-requirements.md).

## Struktur

```
backend/
├── app/
│   ├── main.py            App-Factory, Middleware, Router
│   ├── core/              Konfiguration, Logging, Fehlerbehandlung, Middleware
│   ├── api/               Health-Endpunkte, versionierte API unter /api/v1
│   ├── models/            SQLAlchemy-Modelle (Datenmodell aus Architektur Kap. 7)
│   ├── schemas/           Pydantic-Schemas (StrictModel: extra="forbid")
│   └── db.py              Engine, Session-Dependency
├── migrations/            Alembic (0001: Schema + Rechte der Laufzeit-Rolle)
├── tests/                 pytest (SQLite in-memory, ohne Docker lauffähig)
├── dev/                   Lokale PostgreSQL per Docker Compose + Rollen-Init-Skript
├── Dockerfile             Multi-Stage, Alpine, non-root, Digest-gepinnt
├── pyproject.toml         Abhängigkeiten + Ruff/Bandit/pytest-Konfiguration
├── requirements.lock      Gepinnte Laufzeit-Abhängigkeiten mit SHA-256-Hashes
└── requirements-dev.lock  Dasselbe inkl. Test- und Scan-Werkzeuge
```

## Lokale Entwicklung (Git Bash)

```bash
cd backend
py -3.14 -m venv .venv
.venv/Scripts/python.exe -m pip install uv
# SQLAlchemy ohne C-Erweiterung, weil die Windows-"Intelligente App-Steuerung"
# unsignierte DLLs aus dem venv blockiert (betrifft nur Windows, nicht Docker/CI):
DISABLE_SQLALCHEMY_CEXT=1 .venv/Scripts/python.exe -m uv pip install --python .venv/Scripts/python.exe \
  --no-binary sqlalchemy --require-hashes -r requirements-dev.lock
.venv/Scripts/python.exe -m uv pip install --python .venv/Scripts/python.exe --no-deps -e .

cp .env.example .env          # danach Passwörter eintragen (openssl rand -hex 24)
docker compose -f dev/compose.yaml --env-file .env up -d --wait
make -C .. backend-migrate     # Schema als praxis_migrate anlegen
make -C .. backend-run         # API auf http://127.0.0.1:8000, Swagger unter /docs
```

Die Entwicklungsdatenbank lauscht auf `127.0.0.1:55432`, damit eine lokal installierte
PostgreSQL auf 5432 nicht stört.

Unter Windows mit aktiver „Intelligenter App-Steuerung“ ist `make.exe` blockiert. Dann die
Befehle aus dem jeweiligen Makefile-Ziel direkt in der Git Bash ausführen (`make -n <ziel>`
in WSL zeigt sie an), zum Beispiel für die Tests:

```bash
cd backend
.venv/Scripts/python.exe -m ruff check . && .venv/Scripts/python.exe -m pytest
```

## Tests und Prüfungen

```bash
make -C .. backend-test       # Ruff, pytest, Bandit
make -C .. backend-image      # Docker-Image bauen und mit Trivy (HIGH/CRITICAL) prüfen
```

## Abhängigkeiten ändern

Abhängigkeiten stehen in `pyproject.toml`. Danach die Lockfiles neu erzeugen:

```bash
make -C .. backend-lock
```

Die Lockfiles enthalten Hashes für alle Plattformen (`--universal`) und werden im
Docker-Build mit `pip install --require-hashes` geprüft.

## Wichtige Umgebungsvariablen

| Variable | Bedeutung | Default |
|---|---|---|
| `APP_ENV` | `prod`, `test` oder `dev`; nur `dev` aktiviert `/docs` | `prod` |
| `DB_HOST`, `DB_PORT`, `DB_NAME` | Datenbankadresse | `localhost`, `5432`, `praxistermin` |
| `DB_USER`, `DB_PASSWORD` | Laufzeitkonto (`praxis_app`) bzw. im Init-Container `praxis_migrate` | Passwort ohne Default, in `prod` Pflicht |
| `DB_SSLMODE` | `disable`, `prefer`, `require`, `verify-full` | `prefer` |
| `DB_APP_ROLE` | Rolle, der die Migration Rechte auf `audit_log` entzieht | `praxis_app` |
| `FORWARDED_ALLOW_IPS` | IPs, deren `X-Forwarded-For` uvicorn vertraut (Ingress) | `127.0.0.1` |

## Hinweise für Kubernetes (Paket L3/L5)

- Init-Container: dasselbe Image, `command: ["alembic", "upgrade", "head"]`, mit
  `DB_USER=praxis_migrate` und dessen Passwort aus einem eigenen Secret.
- App-Container: `DB_USER=praxis_app`, Port 8000, Probes `GET /healthz` (liveness)
  und `GET /readyz` (readiness).
- `readOnlyRootFilesystem: true` funktioniert ohne zusätzliche Volumes; ein
  `emptyDir` auf `/tmp` schadet nicht.
- Das Rollen-Skript `dev/initdb/01-roles.sh` kann für das PostgreSQL-StatefulSet übernommen werden.
