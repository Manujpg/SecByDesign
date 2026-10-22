#!/bin/sh
# Legt die Datenbank und zwei Rollen nach dem Least-Privilege-Prinzip an (Paket L5, SR-10).
#
#   praxis_migrate  Eigentümer der Datenbank, darf Tabellen anlegen/ändern (nur Init-Container)
#   praxis_app      Laufzeitkonto der API, nur SELECT/INSERT/UPDATE/DELETE, kein DDL
#
# Übernommen aus backend/dev/initdb/01-roles.sh (Entwicklungs-DB); beide Fassungen müssen
# inhaltlich gleich bleiben. Das postgres-Image führt das Skript nur bei der
# Erstinitialisierung des Volumes aus (ConfigMap praxis-postgres-initdb). Die Passwörter
# kommen aus dem Secret db-credentials (scripts/generate-secrets.sh).
set -eu

: "${PRAXIS_DB_NAME:?fehlt}"
: "${PRAXIS_MIGRATE_PASSWORD:?fehlt}"
: "${PRAXIS_APP_PASSWORD:?fehlt}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v db="$PRAXIS_DB_NAME" \
  -v migrate_pw="$PRAXIS_MIGRATE_PASSWORD" \
  -v app_pw="$PRAXIS_APP_PASSWORD" <<'SQL'
CREATE ROLE praxis_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'migrate_pw';
CREATE ROLE praxis_app     LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_pw';
CREATE DATABASE :"db" OWNER praxis_migrate;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO praxis_app;
\connect :"db"
-- Schema gehört dem Migrationskonto; niemand sonst darf darin Objekte anlegen.
ALTER SCHEMA public OWNER TO praxis_migrate;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO praxis_app;
-- Alle künftig von praxis_migrate angelegten Tabellen: nur DML für die App.
ALTER DEFAULT PRIVILEGES FOR ROLE praxis_migrate IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO praxis_app;
ALTER DEFAULT PRIVILEGES FOR ROLE praxis_migrate IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO praxis_app;
SQL
