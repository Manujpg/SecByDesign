# syntax=docker/dockerfile:1.7
# =============================================================================
# PraxisTermin Backend – Multi-Stage-Build
#
# Sicherheitsmerkmale (SR-06, SR-10, SR-12):
# - Basis-Image per Digest gepinnt (reproduzierbar, keine stillen Tag-Wechsel)
# - Abhängigkeiten nur mit geprüften Hashes aus requirements.lock (--require-hashes)
# - Laufzeit-Image ohne pip/Build-Werkzeuge im venv, ohne Tests und Dev-Dateien
# - Läuft als unprivilegierter Nutzer 10001, kompatibel mit readOnlyRootFilesystem
# =============================================================================

# python:3.14-alpine, Stand 19.10.2026 (Python 3.14.8).
# Alpine statt Debian-slim: slim brachte 44 HIGH-CVEs in Systempaketen (util-linux, ncurses,
# perl) ohne verfügbaren Fix mit, die das Quality Gate (CVSS >= 7) blockieren würden.
ARG PYTHON_IMAGE=python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# -----------------------------------------------------------------------------
# Stage 1: Abhängigkeiten in ein isoliertes venv installieren
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock
# pip/setuptools werden im fertigen venv nicht gebraucht (kleinere Angriffsfläche).
RUN pip uninstall -y pip setuptools

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
# Bytecode vorab erzeugen: zur Laufzeit ist das Dateisystem schreibgeschützt.
RUN python -m compileall -q /opt/venv /build/app /build/migrations

# -----------------------------------------------------------------------------
# Stage 2: Laufzeit-Image
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ARG APP_VERSION=0.0.0
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.title="praxistermin-backend" \
      org.opencontainers.image.description="PraxisTermin REST-API (Ärztehaus Lindle)" \
      org.opencontainers.image.source="https://github.com/Manujpg/SecByDesign" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=prod \
    # Konfiguration nur aus Umgebungsvariablen, nie aus einer .env-Datei im Image.
    SETTINGS_ENV_FILE="" \
    # Proxy-Header (X-Forwarded-For) nur vom Ingress übernehmen; im Cluster per Env setzen.
    FORWARDED_ALLOW_IPS=127.0.0.1

# pip aus dem Basis-Image entfernen (wird zur Laufzeit nicht gebraucht, kleinere Angriffsfläche)
# und unprivilegierten Nutzer ohne Login-Shell anlegen.
RUN python -m pip uninstall -y pip setuptools wheel 2>/dev/null || true \
 && addgroup -S -g 10001 app \
 && adduser -S -D -H -u 10001 -G app -s /sbin/nologin app

COPY --from=build --chown=root:root /opt/venv /opt/venv
WORKDIR /app
COPY --from=build --chown=root:root /build/app ./app
COPY --from=build --chown=root:root /build/migrations ./migrations
COPY --from=build --chown=root:root /build/alembic.ini ./

# Code gehört root und ist für den App-Nutzer nur lesbar.
USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

# Im Cluster läuft "alembic upgrade head" als Init-Container mit demselben Image:
#   command: ["alembic", "upgrade", "head"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--no-server-header", "--proxy-headers", "--no-access-log"]
