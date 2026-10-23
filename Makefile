# =============================================================================
# PraxisTermin – Makefile (Blaupause für reproduzierbares Deployment)
#
#   make up      Cluster hochfahren, Gateway installieren, Namespace anlegen,
#                Images laden, Manifeste anwenden, auf Health warten, "Ready"
#   make infra   Nur Plattform (L1/L2): Cluster, Gateway, Namespace, TLS, Prüfungen
#   make down    Cluster löschen
#   make smoke   Health-/Header-Checks über das Gateway
#   make build   Images lokal bauen
#   make scan    SBOM, SAST, SCA, Secret-Scan lokal (Docker-basiert)
#   make bundle  Abgabe-Zip erzeugen
#
# Ausführung unter Linux/macOS bzw. Windows in WSL2 (ADR A14). Entwurf Woche 1 – Ziele, die noch
# auf fehlende Dateien verweisen, sind mit TODO markiert (Paket L6 im Projektplan).
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# ----- Konfiguration ----------------------------------------------------------
CLUSTER        ?= praxis-termine
NAMESPACE      ?= praxis-termine
TEAM_NR        ?= 00
VERSION        := $(shell cat VERSION.txt)
GIT_SHA        := $(shell git rev-parse --short HEAD 2>/dev/null || echo local)
REGISTRY       ?= ghcr.io/manujpg
BACKEND_IMAGE  ?= $(REGISTRY)/praxis-backend
FRONTEND_IMAGE ?= $(REGISTRY)/praxis-frontend
IMAGE_TAG      ?= $(VERSION)
# TODO(M6/M7): Platzhalter, solange es kein frontend/Dockerfile gibt. Unverändertes Basis-Image
# (nginx 1.30.6, Stand 22.10.2026), per Digest gepinnt; der Node zieht es selbst.
FRONTEND_PLACEHOLDER ?= nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03
HAS_FRONTEND   := $(wildcard frontend/Dockerfile)
# Wenn gesetzt, werden Images per Digest aus der Registry gezogen statt lokal gebaut.
BACKEND_DIGEST  ?=
FRONTEND_DIGEST ?=
KIND_CONFIG    ?= infrastructure/kind/cluster.yaml
OVERLAY        ?= infrastructure/k8s/overlays/local
# Envoy Gateway (Gateway API) als Eintrittspunkt, Installation ohne Helm (ADR A26).
GATEWAY_VERSION ?= v1.9.2
GATEWAY_INSTALL ?= https://github.com/envoyproxy/gateway/releases/download/$(GATEWAY_VERSION)/install.yaml
# SHA-256 der install.yaml (v1.9.2, ermittelt 22.10.2026). "make gateway" bricht bei Abweichung ab
# (Supply Chain). Bei einem Versionswechsel neuen Hash eintragen; leer wird er nur ausgegeben.
GATEWAY_INSTALL_SHA256 ?= 0412a72907e57ff9b73c56a7bf6df5190bf0f6e4f8bb4bba34e38630bbab5778
GATEWAY_NAME   ?= praxis-gateway
CACHE_DIR      ?= .cache
WAIT_TIMEOUT   ?= 300s
BUNDLE_DIR     ?= submission

# ----- Hilfe ------------------------------------------------------------------
.PHONY: help
help: ## Zeigt diese Hilfe
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ----- Hauptziel --------------------------------------------------------------
.PHONY: up
up: check-tools cluster gateway namespace tls secrets images deploy wait smoke ## Kompletter Aufbau bis "Ready"
	@echo ""
	@echo "Ready"
	@echo "  App:   https://localhost  (selbstsigniertes Zertifikat einmalig akzeptieren)"
	@echo "  Admin: Initialpasswort siehe Ausgabe von 'make secrets' bzw. Secret admin-bootstrap"

.PHONY: infra
infra: check-tools cluster gateway namespace tls platform gateway-wait check-k8s ## Nur Plattform (L1/L2) aufbauen und prüfen
	@echo ""
	@echo "Plattform bereit: https://localhost läuft über das Gateway (ohne Workloads: 500)"

.PHONY: check-tools
check-tools: ## Prüft, ob docker, kind, kubectl, curl, openssl vorhanden sind
	@for t in docker kind kubectl curl openssl; do \
	  command -v $$t >/dev/null 2>&1 || { echo "Fehlt: $$t (siehe README Setup-Guide)"; exit 1; }; \
	done
	@docker info >/dev/null 2>&1 || { echo "Docker läuft nicht"; exit 1; }

.PHONY: cluster
cluster: ## kind-Cluster erstellen (idempotent)
	@if kind get clusters 2>/dev/null | grep -qx "$(CLUSTER)"; then \
	  echo "Cluster $(CLUSTER) existiert bereits"; \
	else \
	  kind create cluster --name "$(CLUSTER)" --config "$(KIND_CONFIG)"; \
	fi
	@kubectl cluster-info --context "kind-$(CLUSTER)" >/dev/null

.PHONY: gateway
gateway: ## Envoy Gateway installieren (Hash-geprüft), GatewayClass/EnvoyProxy anwenden
	@mkdir -p "$(CACHE_DIR)"
	@f="$(CACHE_DIR)/envoy-gateway-$(GATEWAY_VERSION).yaml"; \
	if [ ! -s "$$f" ]; then \
	  curl -fsSL --proto '=https' --tlsv1.2 -o "$$f.tmp" "$(GATEWAY_INSTALL)" && mv "$$f.tmp" "$$f"; \
	fi; \
	actual="$$(sha256sum "$$f" | cut -d' ' -f1)"; \
	if [ -z "$(GATEWAY_INSTALL_SHA256)" ]; then \
	  echo "WARNUNG: GATEWAY_INSTALL_SHA256 nicht gesetzt, SHA-256 von install.yaml $(GATEWAY_VERSION): $$actual"; \
	elif [ "$$actual" != "$(GATEWAY_INSTALL_SHA256)" ]; then \
	  echo "FEHLER: SHA-256 von $$f weicht ab ($$actual)"; rm -f "$$f"; exit 1; \
	fi; \
	kubectl apply --server-side -f "$$f" >/dev/null
	kubectl -n envoy-gateway-system wait --for=condition=Available deployment/envoy-gateway --timeout=$(WAIT_TIMEOUT)
	kubectl apply -k infrastructure/gateway

.PHONY: tls
tls: ## Selbstsigniertes TLS-Zertifikat als Secret tls-cert erzeugen (nie im Repo)
	./scripts/generate-tls.sh "$(NAMESPACE)"

.PHONY: gateway-wait
gateway-wait: ## Warten, bis der Envoy-Proxy des Gateways läuft
	@sel="gateway.envoyproxy.io/owning-gateway-name=$(GATEWAY_NAME),gateway.envoyproxy.io/owning-gateway-namespace=$(NAMESPACE)"; \
	for i in $$(seq 1 60); do \
	  [ -n "$$(kubectl -n envoy-gateway-system get pods -l "$$sel" -o name 2>/dev/null)" ] && break; \
	  sleep 2; \
	done; \
	kubectl -n envoy-gateway-system wait --for=condition=Ready pod -l "$$sel" --timeout=$(WAIT_TIMEOUT)

.PHONY: check-k8s
check-k8s: ## Least Privilege im Namespace prüfen (PSA, ServiceAccounts, RBAC, Quota)
	./scripts/check-k8s.sh "$(NAMESPACE)"

.PHONY: namespace
namespace: ## Namespace anlegen
	kubectl apply -f infrastructure/k8s/base/namespace.yaml

.PHONY: secrets
secrets: ## Secrets zur Laufzeit erzeugen (nie im Repo), Admin-Initialpasswort einmalig ausgeben
	./scripts/generate-secrets.sh "$(NAMESPACE)"

# Images, die "make images" in den Cluster lädt (ohne frontend/Dockerfile nur das Backend).
LOCAL_IMAGES := $(BACKEND_IMAGE):$(IMAGE_TAG) $(if $(HAS_FRONTEND),$(FRONTEND_IMAGE):$(IMAGE_TAG))

.PHONY: images
images: ## Images bereitstellen: Pull per Digest aus GHCR oder lokaler Build, dann kind load
	@if [ -n "$(BACKEND_DIGEST)" ]; then \
	  docker pull "$(BACKEND_IMAGE)@$(BACKEND_DIGEST)"; \
	  docker tag "$(BACKEND_IMAGE)@$(BACKEND_DIGEST)" "$(BACKEND_IMAGE):$(IMAGE_TAG)"; \
	  if [ -n "$(HAS_FRONTEND)" ]; then \
	    [ -n "$(FRONTEND_DIGEST)" ] || { echo "FRONTEND_DIGEST fehlt"; exit 1; }; \
	    docker pull "$(FRONTEND_IMAGE)@$(FRONTEND_DIGEST)"; \
	    docker tag "$(FRONTEND_IMAGE)@$(FRONTEND_DIGEST)" "$(FRONTEND_IMAGE):$(IMAGE_TAG)"; \
	  fi; \
	else \
	  echo "Kein Digest gesetzt – baue Images lokal"; \
	  $(MAKE) build; \
	fi
	kind load docker-image --name "$(CLUSTER)" $(LOCAL_IMAGES)

.PHONY: build
build: ## Images lokal bauen (Frontend erst, wenn frontend/Dockerfile existiert)
	docker build -t "$(BACKEND_IMAGE):$(IMAGE_TAG)" \
	  --build-arg APP_VERSION="$(VERSION)" --build-arg GIT_SHA="$(GIT_SHA)" ./backend
ifneq ($(HAS_FRONTEND),)
	docker build -t "$(FRONTEND_IMAGE):$(IMAGE_TAG)" \
	  --build-arg APP_VERSION="$(VERSION)" --build-arg GIT_SHA="$(GIT_SHA)" ./frontend
else
	@echo "TODO(M6/M7): kein frontend/Dockerfile – Frontend läuft mit Platzhalter $(FRONTEND_PLACEHOLDER)"
endif

.PHONY: platform
platform: ## Nur Plattform-Manifeste anwenden (Namespace, Identitäten, Kontingente, Gateway, Routen)
	kubectl apply -k infrastructure/k8s/base

# Die Manifeste nennen die Images nur logisch (praxis-backend, praxis-frontend). deploy legt
# in $(CACHE_DIR)/deploy eine Kustomization über das Overlay, die Registry und Tag einsetzt;
# das Overlay selbst bleibt unverändert.
FRONTEND_REF := $(if $(HAS_FRONTEND),$(FRONTEND_IMAGE):$(IMAGE_TAG),$(FRONTEND_PLACEHOLDER))

.PHONY: deploy
deploy: ## Manifeste anwenden (Kustomize-Overlay mit Images aus images/build)
	@d="$(CACHE_DIR)/deploy"; mkdir -p "$$d"; \
	ref="$(FRONTEND_REF)"; \
	if [[ "$$ref" == *@* ]]; then fe="    newName: $${ref%@*}"$$'\n'"    digest: $${ref#*@}"; \
	else fe="    newName: $${ref%:*}"$$'\n'"    newTag: $${ref##*:}"; fi; \
	printf '%s\n' \
	  "# Erzeugt von make deploy – nicht bearbeiten" \
	  "apiVersion: kustomize.config.k8s.io/v1beta1" \
	  "kind: Kustomization" \
	  "resources:" \
	  "  - $$(realpath --relative-to="$$d" "$(OVERLAY)")" \
	  "images:" \
	  "  - name: praxis-backend" \
	  "    newName: $(BACKEND_IMAGE)" \
	  "    newTag: \"$(IMAGE_TAG)\"" \
	  "  - name: praxis-frontend" \
	  "$$fe" > "$$d/kustomization.yaml"; \
	kubectl apply -k "$$d"

.PHONY: wait
wait: gateway-wait ## Warten, bis Gateway und alle Workloads bereit sind
	kubectl -n "$(NAMESPACE)" rollout status statefulset/praxis-postgres --timeout=$(WAIT_TIMEOUT)
	kubectl -n "$(NAMESPACE)" rollout status deployment/praxis-backend  --timeout=$(WAIT_TIMEOUT)
	kubectl -n "$(NAMESPACE)" rollout status deployment/praxis-frontend --timeout=$(WAIT_TIMEOUT)

.PHONY: smoke
smoke: ## Smoke-Test über das Gateway  TODO L6: scripts/smoke.sh
	@if [ -x scripts/smoke.sh ]; then \
	  ./scripts/smoke.sh https://localhost; \
	else \
	  echo "TODO(L6): scripts/smoke.sh fehlt – Minimalprüfung von Health/Ready über das Gateway"; \
	  for p in /api/v1/healthz /api/v1/readyz /; do \
	    code="$$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost$$p")"; \
	    echo "  GET $$p -> $$code"; [ "$$code" = 200 ] || exit 1; \
	  done; \
	fi

.PHONY: down
down: ## Cluster löschen
	kind delete cluster --name "$(CLUSTER)"

.PHONY: logs
logs: ## Logs aller Pods im Namespace
	kubectl -n "$(NAMESPACE)" logs -l app.kubernetes.io/part-of=praxis-termine --all-containers --tail=200

# ----- Backend-Entwicklung (Paket M2) -----------------------------------------
BACKEND_DIR := backend
# Python im venv, relativ zu backend/ (Windows: Scripts/python.exe, Linux/WSL: bin/python)
BACKEND_PY  := .venv/Scripts/python.exe
ifeq ($(wildcard $(BACKEND_DIR)/$(BACKEND_PY)),)
BACKEND_PY  := .venv/bin/python
endif
DEV_COMPOSE := docker compose -f $(BACKEND_DIR)/dev/compose.yaml --env-file $(BACKEND_DIR)/.env

.PHONY: backend-lock
backend-lock: ## Lockfiles mit Hashes neu erzeugen (nach Änderung in pyproject.toml)
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m uv pip compile pyproject.toml --universal --python-version 3.14 --generate-hashes --no-header -q -o requirements.txt
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m uv pip compile pyproject.toml --extra dev --universal --python-version 3.14 --generate-hashes --no-header -q -o requirements-dev.txt

.PHONY: backend-test
backend-test: ## Ruff, pytest und Bandit für das Backend
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m ruff check . && $(BACKEND_PY) -m ruff format --check .
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m pytest
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m bandit -q -c pyproject.toml -r app migrations

.PHONY: backend-db-up
backend-db-up: ## Lokale Entwicklungs-PostgreSQL starten (Port 55432)
	$(DEV_COMPOSE) up -d --wait

.PHONY: backend-db-down
backend-db-down: ## Lokale Entwicklungs-PostgreSQL stoppen (Daten bleiben erhalten)
	$(DEV_COMPOSE) down

.PHONY: backend-migrate
backend-migrate: ## Migrationen als praxis_migrate auf die Entwicklungs-DB anwenden
	cd $(BACKEND_DIR) && DB_USER=praxis_migrate DB_PASSWORD="$$(grep '^DB_MIGRATE_PASSWORD=' .env | cut -d= -f2)" $(BACKEND_PY) -m alembic upgrade head

.PHONY: backend-run
backend-run: ## API lokal mit Auto-Reload starten (APP_ENV aus backend/.env)
	cd $(BACKEND_DIR) && $(BACKEND_PY) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --no-server-header

.PHONY: backend-image
backend-image: ## Backend-Image bauen und mit Trivy gegen das Quality Gate prüfen
	docker build -t "$(BACKEND_IMAGE):$(IMAGE_TAG)" --build-arg APP_VERSION="$(VERSION)" --build-arg GIT_SHA="$(GIT_SHA)" ./$(BACKEND_DIR)
	trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --exit-code 1 "$(BACKEND_IMAGE):$(IMAGE_TAG)"

# ----- Lokale Sicherheitsprüfungen (Spiegel der Pipeline) --------------------
.PHONY: scan
scan: sbom sast sca secrets-scan ## Alle Scans lokal ausführen

.PHONY: sbom
sbom: ## SBOM (CycloneDX) für beide Komponenten
	docker run --rm -v "$$PWD:/src" anchore/syft:latest dir:/src/backend  -o cyclonedx-json > evidence/backend/sbom/local-$(GIT_SHA).cdx.json
	docker run --rm -v "$$PWD:/src" anchore/syft:latest dir:/src/frontend -o cyclonedx-json > evidence/frontend/sbom/local-$(GIT_SHA).cdx.json

.PHONY: sast
sast: ## SAST mit Semgrep und Bandit
	docker run --rm -v "$$PWD:/src" semgrep/semgrep semgrep scan --config p/owasp-top-ten --config p/python --config p/typescript --sarif --output /src/evidence/backend/sast/local-$(GIT_SHA)-semgrep.sarif /src
	docker run --rm -v "$$PWD:/src" python:3.14-alpine sh -c "pip install -q 'bandit[toml]' && bandit -c /src/backend/pyproject.toml -r /src/backend/app /src/backend/migrations -f json -o /src/evidence/backend/sast/local-$(GIT_SHA)-bandit.json || true"

.PHONY: sca
sca: ## SCA mit Trivy (Dateisystem)
	docker run --rm -v "$$PWD:/src" aquasec/trivy:latest fs --scanners vuln --severity HIGH,CRITICAL --format json --output /src/evidence/backend/sca/local-$(GIT_SHA)-trivy.json /src

.PHONY: secrets-scan
secrets-scan: ## Secret-Scan mit Gitleaks (gesamte Historie)
	docker run --rm -v "$$PWD:/src" zricethezav/gitleaks:latest detect --source /src --report-format json --report-path /src/evidence/backend/secrets/local-$(GIT_SHA)-gitleaks.json

# ----- Abgabe ------------------------------------------------------------------
.PHONY: bundle
bundle: ## Abgabe-Zip team-<nr>.zip erzeugen  TODO L6: Reports und Doku einsammeln
	rm -rf "$(BUNDLE_DIR)" && mkdir -p "$(BUNDLE_DIR)/Image" "$(BUNDLE_DIR)/Dokumentation" "$(BUNDLE_DIR)/ThreatModelling"
	docker save "$(BACKEND_IMAGE):$(IMAGE_TAG)"  -o "$(BUNDLE_DIR)/Image/praxis-backend-$(VERSION).tar"
	docker save "$(FRONTEND_IMAGE):$(IMAGE_TAG)" -o "$(BUNDLE_DIR)/Image/praxis-frontend-$(VERSION).tar"
	docker image inspect --format '{{index .RepoDigests 0}}' "$(BACKEND_IMAGE):$(IMAGE_TAG)"  >  "$(BUNDLE_DIR)/Image/image-ref.txt" || true
	docker image inspect --format '{{index .RepoDigests 0}}' "$(FRONTEND_IMAGE):$(IMAGE_TAG)" >> "$(BUNDLE_DIR)/Image/image-ref.txt" || true
	sha256sum "$(BUNDLE_DIR)"/Image/*.tar > "$(BUNDLE_DIR)/Image/digest.txt"
	cp -r docs/threat-model/. "$(BUNDLE_DIR)/ThreatModelling/"
	git archive --format=zip --output "$(BUNDLE_DIR)/repository.zip" HEAD
	cd "$(BUNDLE_DIR)" && zip -r "../team-$(TEAM_NR).zip" .
	@echo "Abgabe erstellt: team-$(TEAM_NR).zip"
