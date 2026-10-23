#!/usr/bin/env bash
# Erzeugt die Anwendungs-Secrets zur Deploy-Zeit im Namespace der Anwendung
# (Paket L5, SR-06). Gegenstück zu scripts/generate-tls.sh.
#
#   scripts/generate-secrets.sh [namespace]      (Standard: praxis-termine)
#   FORCE=1 scripts/generate-secrets.sh          alle Secrets neu erzeugen (siehe unten)
#   ADMIN_EMAIL=... scripts/generate-secrets.sh  andere Adresse für das erste Admin-Konto
#
#   db-credentials    POSTGRES_PASSWORD  Superuser "postgres"      -> nur praxis-postgres
#                     MIGRATE_PASSWORD   praxis_migrate (DDL)       -> postgres, Init-Container migrate
#                     APP_PASSWORD       praxis_app (nur DML)       -> postgres, Backend
#   app-session-key   APP_SECRET_KEY     Server-Schlüssel, 64 Zeichen -> Backend
#   admin-bootstrap   ADMIN_BOOTSTRAP_EMAIL / ADMIN_BOOTSTRAP_PASSWORD -> Backend
#
# Werte entstehen nur in einer temporären Datei (umask 077) und werden per --from-env-file
# übergeben, damit sie weder im Repository noch in der Prozessliste (argv) auftauchen.
# Ausgegeben wird nur das Admin-Initialpasswort, und zwar einmalig beim Anlegen; es muss
# beim ersten Login geändert werden. Vorhandene Secrets bleiben unverändert: PostgreSQL
# übernimmt die Passwörter nur bei der Erstinitialisierung des Volumes. Nach FORCE=1
# passen sie daher nicht mehr zur bestehenden Datenbank (Cluster neu aufbauen: make down up).
set -euo pipefail

NAMESPACE="${1:-praxis-termine}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@aerztehaus-lindle.de}"

for tool in kubectl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Fehlt: $tool" >&2; exit 1; }
done

umask 077
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Zufallswert aus dem CSPRNG von OpenSSL, URL-sicheres Alphabet ohne Füllzeichen
# (unkritisch in Verbindungs-URLs, psql-Variablen und Shells).
random() {
  openssl rand -base64 48 | tr -d '\n=' | tr '+/' '-_' | cut -c "1-$1"
}

exists() {
  kubectl -n "$NAMESPACE" get secret "$1" >/dev/null 2>&1
}

# Legt ein generisches Secret aus der env-Datei $workdir/$1.env an (bzw. ersetzt es).
apply_secret() {
  kubectl -n "$NAMESPACE" create secret generic "$1" \
    --from-env-file="$workdir/$1.env" --dry-run=client -o yaml \
    | kubectl label --local -f - -o yaml app.kubernetes.io/part-of=praxis-termine \
    | kubectl apply -f - >/dev/null
  rm -f "$workdir/$1.env"
  echo "Secret $NAMESPACE/$1 erstellt"
}

# Gibt 0 zurück, wenn das Secret (neu) erzeugt werden soll.
needed() {
  if exists "$1" && [[ "${FORCE:-0}" != "1" ]]; then
    echo "Secret $NAMESPACE/$1 existiert bereits (FORCE=1 erzeugt ein neues)"
    return 1
  fi
  return 0
}

kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 \
  || { echo "Namespace $NAMESPACE fehlt (zuerst: make namespace)" >&2; exit 1; }

if needed db-credentials; then
  if exists db-credentials; then
    echo "WARNUNG: neue DB-Passwörter passen nicht zu einem bereits initialisierten Volume" >&2
  fi
  {
    echo "POSTGRES_PASSWORD=$(random 40)"
    echo "MIGRATE_PASSWORD=$(random 40)"
    echo "APP_PASSWORD=$(random 40)"
  } > "$workdir/db-credentials.env"
  apply_secret db-credentials
fi

if needed app-session-key; then
  # 256 Bit als Hex (64 Zeichen); config.py verlangt mindestens 32 Zeichen.
  echo "APP_SECRET_KEY=$(openssl rand -hex 32)" > "$workdir/app-session-key.env"
  apply_secret app-session-key
fi

if needed admin-bootstrap; then
  admin_password="$(random 24)"
  {
    echo "ADMIN_BOOTSTRAP_EMAIL=$ADMIN_EMAIL"
    echo "ADMIN_BOOTSTRAP_PASSWORD=$admin_password"
  } > "$workdir/admin-bootstrap.env"
  apply_secret admin-bootstrap
  echo ""
  echo "Erstes Admin-Konto (wird nur angelegt, solange es noch keine Nutzer:innen gibt):"
  echo "  E-Mail:          $ADMIN_EMAIL"
  echo "  Initialpasswort: $admin_password"
  echo "  Wird nur jetzt angezeigt; beim ersten Login ändern und MFA einrichten."
  unset admin_password
fi
