#!/usr/bin/env bash
# Erzeugt ein selbstsigniertes TLS-Zertifikat für https://localhost und legt es als
# Kubernetes-Secret "tls-cert" im Namespace der Anwendung ab (Paket L1, SR-06, SR-09).
#
#   scripts/generate-tls.sh [namespace]      (Standard: praxis-termine)
#   FORCE=1 scripts/generate-tls.sh          neues Zertifikat erzwingen
#
# Schlüssel und Zertifikat entstehen nur in einem temporären Verzeichnis und werden
# danach gelöscht; sie gelangen nie ins Repository. Ein vorhandenes Secret bleibt
# erhalten, damit das im Browser akzeptierte Zertifikat gültig bleibt.
set -euo pipefail

NAMESPACE="${1:-praxis-termine}"
SECRET_NAME="tls-cert"
DAYS="${TLS_DAYS:-90}"

for tool in kubectl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Fehlt: $tool" >&2; exit 1; }
done

if [[ "${FORCE:-0}" != "1" ]] && kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1; then
  echo "Secret $NAMESPACE/$SECRET_NAME existiert bereits (FORCE=1 erzeugt ein neues)"
  exit 0
fi

umask 077
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# ECDSA P-256; SAN für Hostname und Loopback-Adresse. MSYS_NO_PATHCONV verhindert, dass
# Git Bash "/CN=..." in einen Windows-Pfad umschreibt.
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout "$workdir/tls.key" -out "$workdir/tls.crt" -days "$DAYS" \
  -subj "/CN=localhost/O=PraxisTermin (lokal)" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null

kubectl -n "$NAMESPACE" create secret tls "$SECRET_NAME" \
  --cert="$workdir/tls.crt" --key="$workdir/tls.key" \
  --dry-run=client -o yaml \
  | kubectl label --local -f - -o yaml app.kubernetes.io/part-of=praxis-termine \
  | kubectl apply -f -

echo "TLS-Zertifikat erstellt (gültig $DAYS Tage):"
openssl x509 -in "$workdir/tls.crt" -noout -subject -enddate -fingerprint -sha256
