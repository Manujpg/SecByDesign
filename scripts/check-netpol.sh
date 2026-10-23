#!/usr/bin/env bash
# Verbindungstest für die NetworkPolicies gegen den laufenden Cluster (Paket L4,
# Nachweis SR-10 d). Prüft erlaubte und verbotene Flüsse aus Sicht der echten Pods.
# Exit-Code 1, sobald ein Fluss anders ist als erwartet.
#
#   scripts/check-netpol.sh [namespace]      (Standard: praxis-termine)
#   PROBE_IMAGE=...                          Image für die fremden Test-Pods (braucht nc)
#
# Ziele werden über Pod-IPs angesprochen, nicht über DNS-Namen: Sonst würde ein gesperrter
# DNS-Zugriff eine gesperrte Verbindung nur vortäuschen. Zusätzlich starten zwei kurzlebige
# Test-Pods ohne Freigabe-Labels (im Namespace und in "default"), die einen eingeschleusten
# bzw. fremden Pod darstellen.
set -euo pipefail

NAMESPACE="${1:-praxis-termine}"
PROBE_IMAGE="${PROBE_IMAGE:-nginxinc/nginx-unprivileged:1.30-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03}"
GATEWAY_URL="${GATEWAY_URL:-https://localhost}"
INTERNET_IP="1.1.1.1"
PROBE_NAME="netpol-probe"
failures=0

pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  FEHLER %s\n' "$1"; failures=$((failures + 1)); }

# expect <allow|deny> <Beschreibung> <Befehl...>: Befehl liefert 0 bei bestehender Verbindung.
expect() {
  local want="$1" what="$2"; shift 2
  if "$@" >/dev/null 2>&1; then got=allow; else got=deny; fi
  if [[ "$got" == "$want" ]]; then
    pass "$what: $([[ $want == allow ]] && echo erlaubt || echo gesperrt)"
  else
    fail "$what: erwartet $want, tatsächlich $got"
  fi
}

# TCP-Verbindung aus einem Pod mit BusyBox-nc (Frontend-Platzhalter, PostgreSQL, Test-Pods)
nc_from() {  # <ns> <pod|deploy/..> <ip> <port>
  kubectl -n "$1" exec "$2" -- timeout 6 nc -w 3 "$3" "$4" </dev/null
}
# TCP-Verbindung aus dem Backend (Python-Image ohne nc)
py_from_backend() {  # <ip> <port>
  kubectl -n "$NAMESPACE" exec deploy/praxis-backend -c api -- python -c \
    "import socket,sys; s=socket.socket(); s.settimeout(3); sys.exit(s.connect_ex(('$1',$2)))"
}
dns_from_backend() {
  kubectl -n "$NAMESPACE" exec deploy/praxis-backend -c api -- python -c \
    "import socket; socket.getaddrinfo('praxis-postgres', 5432)"
}
dns_from() {  # <pod|deploy/..>
  # Voller Name: BusyBox-nslookup wertet die Suchdomänen aus resolv.conf nicht aus, mit
  # dem Kurznamen schlüge die Abfrage auch ohne Policy fehl.
  kubectl -n "$NAMESPACE" exec "$1" -- timeout 6 nslookup "praxis-postgres.$NAMESPACE.svc.cluster.local"
}
http_via_gateway() {  # <pfad>
  [[ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$GATEWAY_URL$1")" == 200 ]]
}
has_nc() {  # <ns> <pod|deploy/..>
  kubectl -n "$1" exec "$2" -- sh -c 'command -v nc && command -v timeout' >/dev/null 2>&1
}
pod_ip() {  # <label-wert app.kubernetes.io/name>
  kubectl -n "$NAMESPACE" get pods -l "app.kubernetes.io/name=$1" \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].status.podIP}'
}

# Test-Pod, der die Pod Security "restricted" erfüllt, ohne Freigabe-Labels
start_probe() {  # <ns>
  kubectl -n "$1" delete pod "$PROBE_NAME" --ignore-not-found --wait=true >/dev/null
  kubectl -n "$1" run "$PROBE_NAME" --image="$PROBE_IMAGE" --restart=Never \
    --labels="app.kubernetes.io/name=$PROBE_NAME" --overrides='{
      "apiVersion": "v1",
      "spec": {
        "automountServiceAccountToken": false,
        "securityContext": {"runAsNonRoot": true, "runAsUser": 101, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
          "name": "probe", "image": "'"$PROBE_IMAGE"'", "command": ["sleep", "120"],
          "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}},
          "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}}
        }]
      }}' >/dev/null
  kubectl -n "$1" wait --for=condition=Ready "pod/$PROBE_NAME" --timeout=90s >/dev/null
}
cleanup() {
  for ns in "$NAMESPACE" default; do
    kubectl -n "$ns" delete pod "$PROBE_NAME" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

echo "NetworkPolicies im Namespace $NAMESPACE"
policies="$(kubectl -n "$NAMESPACE" get networkpolicies -o name | wc -l | tr -d ' ')"
kubectl -n "$NAMESPACE" get networkpolicy default-deny-all >/dev/null 2>&1 \
  && pass "default-deny-all vorhanden ($policies Policies)" || fail "default-deny-all fehlt"

fe="$(pod_ip praxis-frontend)"; be="$(pod_ip praxis-backend)"; pg="$(pod_ip praxis-postgres)"
api="$(kubectl -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')"
if [[ -z "$fe" || -z "$be" || -z "$pg" ]]; then
  echo "Workloads laufen nicht (zuerst: make deploy wait)" >&2
  exit 1
fi

echo "Erlaubte Flüsse"
expect allow "Browser -> Gateway -> praxis-frontend:8080" http_via_gateway /
expect allow "Browser -> Gateway -> praxis-backend:8000 -> praxis-postgres:5432 (/readyz)" http_via_gateway /api/v1/readyz
expect allow "praxis-backend -> praxis-postgres:5432" py_from_backend "$pg" 5432
expect allow "praxis-backend -> kube-dns (praxis-postgres auflösen)" dns_from_backend

echo "Gesperrte Flüsse aus kompromittierten Pods"
expect deny "praxis-backend -> praxis-frontend:8080" py_from_backend "$fe" 8080
expect deny "praxis-backend -> Kubernetes-API $api:443" py_from_backend "$api" 443
expect deny "praxis-backend -> Internet $INTERNET_IP:443" py_from_backend "$INTERNET_IP" 443
if has_nc "$NAMESPACE" deploy/praxis-frontend; then
  expect deny "praxis-frontend -> praxis-postgres:5432" nc_from "$NAMESPACE" deploy/praxis-frontend "$pg" 5432
  expect deny "praxis-frontend -> praxis-backend:8000 (am Gateway vorbei)" nc_from "$NAMESPACE" deploy/praxis-frontend "$be" 8000
  expect deny "praxis-frontend -> kube-dns" dns_from deploy/praxis-frontend
  expect deny "praxis-frontend -> Internet $INTERNET_IP:443" nc_from "$NAMESPACE" deploy/praxis-frontend "$INTERNET_IP" 443
else
  echo "  -     praxis-frontend: kein nc/timeout im Image, Prüfung übersprungen (Test-Pods unten decken den Fall ab)"
fi
expect deny "praxis-postgres -> praxis-backend:8000" nc_from "$NAMESPACE" praxis-postgres-0 "$be" 8000
expect deny "praxis-postgres -> kube-dns" dns_from praxis-postgres-0
expect deny "praxis-postgres -> Internet $INTERNET_IP:443" nc_from "$NAMESPACE" praxis-postgres-0 "$INTERNET_IP" 443

echo "Gesperrte Flüsse aus fremden Pods (Test-Pod ohne Freigabe-Labels)"
for ns in "$NAMESPACE" default; do
  start_probe "$ns"
  expect deny "Pod in $ns -> praxis-postgres:5432" nc_from "$ns" "$PROBE_NAME" "$pg" 5432
  expect deny "Pod in $ns -> praxis-backend:8000" nc_from "$ns" "$PROBE_NAME" "$be" 8000
  expect deny "Pod in $ns -> praxis-frontend:8080" nc_from "$ns" "$PROBE_NAME" "$fe" 8080
  kubectl -n "$ns" delete pod "$PROBE_NAME" --wait=false >/dev/null
done

echo ""
if (( failures > 0 )); then
  echo "$failures Prüfung(en) fehlgeschlagen"
  exit 1
fi
echo "Alle Prüfungen bestanden"
