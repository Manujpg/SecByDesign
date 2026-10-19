# =============================================================================
# PraxisTermin – Makefile (Blaupause für reproduzierbares Deployment)
#
#   make up      Cluster hochfahren, Namespace anlegen, Ingress ausrollen,
#                Images laden, Manifeste anwenden, auf Health warten, "Ready"
#   make down    Cluster löschen
#   make smoke   Health-/Header-Checks über den Ingress
#   make build   Images lokal bauen
#   make scan    SBOM, SAST, SCA, Secret-Scan lokal (Docker-basiert)
#   make bundle  Abgabe-Zip erzeugen
#
# Ausführung unter Windows aus der Git Bash. Entwurf Woche 1 – Ziele, die noch
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
# Wenn gesetzt, werden Images per Digest aus der Registry gezogen statt lokal gebaut.
BACKEND_DIGEST  ?=
FRONTEND_DIGEST ?=
KIND_CONFIG    ?= infrastructure/kind/cluster.yaml
OVERLAY        ?= infrastructure/k8s/overlays/local
INGRESS_NGINX  ?= https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.12.1/deploy/static/provider/kind/deploy.yaml
WAIT_TIMEOUT   ?= 300s
BUNDLE_DIR     ?= submission

# ----- Hilfe ------------------------------------------------------------------
.PHONY: help
help: ## Zeigt diese Hilfe
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ----- Hauptziel --------------------------------------------------------------
.PHONY: up
up: check-tools cluster ingress namespace secrets images deploy wait smoke ## Kompletter Aufbau bis "Ready"
	@echo ""
	@echo "Ready"
	@echo "  App:   https://localhost  (selbstsigniertes Zertifikat einmalig akzeptieren)"
	@echo "  Admin: Initialpasswort siehe Ausgabe von 'make secrets' bzw. Secret admin-bootstrap"

.PHONY: check-tools
check-tools: ## Prüft, ob docker, kind, kubectl vorhanden sind
	@for t in docker kind kubectl; do \
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

.PHONY: ingress
ingress: ## ingress-nginx installieren und auf Bereitschaft warten
	kubectl apply -f "$(INGRESS_NGINX)"
	kubectl -n ingress-nginx wait --for=condition=Ready pod \
	  -l app.kubernetes.io/component=controller --timeout=$(WAIT_TIMEOUT)

.PHONY: namespace
namespace: ## Namespace anlegen
	kubectl apply -f infrastructure/k8s/base/namespace.yaml

.PHONY: secrets
secrets: ## Secrets zur Laufzeit erzeugen (nie im Repo)  TODO L5: scripts/generate-secrets.sh
	./scripts/generate-secrets.sh "$(NAMESPACE)"

.PHONY: images
images: ## Images bereitstellen: Pull per Digest aus GHCR oder lokaler Build, dann kind load
	@if [ -n "$(BACKEND_DIGEST)" ] && [ -n "$(FRONTEND_DIGEST)" ]; then \
	  docker pull "$(BACKEND_IMAGE)@$(BACKEND_DIGEST)"; \
	  docker pull "$(FRONTEND_IMAGE)@$(FRONTEND_DIGEST)"; \
	  docker tag "$(BACKEND_IMAGE)@$(BACKEND_DIGEST)" "$(BACKEND_IMAGE):$(IMAGE_TAG)"; \
	  docker tag "$(FRONTEND_IMAGE)@$(FRONTEND_DIGEST)" "$(FRONTEND_IMAGE):$(IMAGE_TAG)"; \
	else \
	  echo "Kein Digest gesetzt – baue Images lokal"; \
	  $(MAKE) build; \
	fi
	kind load docker-image --name "$(CLUSTER)" "$(BACKEND_IMAGE):$(IMAGE_TAG)" "$(FRONTEND_IMAGE):$(IMAGE_TAG)"

.PHONY: build
build: ## Beide Images lokal bauen
	docker build -t "$(BACKEND_IMAGE):$(IMAGE_TAG)" \
	  --build-arg APP_VERSION="$(VERSION)" --build-arg GIT_SHA="$(GIT_SHA)" ./backend
	docker build -t "$(FRONTEND_IMAGE):$(IMAGE_TAG)" \
	  --build-arg APP_VERSION="$(VERSION)" --build-arg GIT_SHA="$(GIT_SHA)" ./frontend

.PHONY: deploy
deploy: ## Manifeste anwenden (Kustomize-Overlay)
	kubectl apply -k "$(OVERLAY)"

.PHONY: wait
wait: ## Warten, bis alle Workloads bereit sind
	kubectl -n "$(NAMESPACE)" rollout status statefulset/praxis-postgres --timeout=$(WAIT_TIMEOUT)
	kubectl -n "$(NAMESPACE)" rollout status deployment/praxis-backend  --timeout=$(WAIT_TIMEOUT)
	kubectl -n "$(NAMESPACE)" rollout status deployment/praxis-frontend --timeout=$(WAIT_TIMEOUT)

.PHONY: smoke
smoke: ## Smoke-Test über den Ingress  TODO L6: scripts/smoke.sh
	./scripts/smoke.sh https://localhost

.PHONY: down
down: ## Cluster löschen
	kind delete cluster --name "$(CLUSTER)"

.PHONY: logs
logs: ## Logs aller Pods im Namespace
	kubectl -n "$(NAMESPACE)" logs -l app.kubernetes.io/part-of=praxis-termine --all-containers --tail=200

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
	docker run --rm -v "$$PWD:/src" python:3.12-slim sh -c "pip install -q bandit && bandit -r /src/backend -f json -o /src/evidence/backend/sast/local-$(GIT_SHA)-bandit.json || true"

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
