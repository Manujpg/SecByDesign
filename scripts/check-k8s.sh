#!/usr/bin/env bash
# Prüft die Least-Privilege-Eigenschaften des Namespaces gegen den laufenden Cluster
# (Pakete L2/L3/L5, Nachweis SR-10 a/b/c und SR-06). Exit-Code 1, sobald eine Prüfung
# fehlschlägt.
#
#   scripts/check-k8s.sh [namespace]      (Standard: praxis-termine)
set -euo pipefail

NAMESPACE="${1:-praxis-termine}"
SERVICE_ACCOUNTS=(frontend-sa backend-sa postgres-sa default)
failures=0

pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  FEHLER %s\n' "$1"; failures=$((failures + 1)); }

echo "Namespace $NAMESPACE"
enforce="$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
[[ "$enforce" == "restricted" ]] && pass "Pod Security Admission enforce=restricted" \
  || fail "Pod Security Admission enforce='$enforce' (erwartet: restricted)"

echo "ServiceAccounts"
for sa in "${SERVICE_ACCOUNTS[@]}"; do
  automount="$(kubectl -n "$NAMESPACE" get serviceaccount "$sa" -o jsonpath='{.automountServiceAccountToken}')"
  [[ "$automount" == "false" ]] && pass "$sa: automountServiceAccountToken=false" \
    || fail "$sa: automountServiceAccountToken='$automount' (erwartet: false)"
done

echo "RBAC (jede Abfrage muss 'no' liefern)"
# Typische Ziele nach einer Container-Übernahme: Secrets lesen, Pods starten/betreten,
# Rechte ausweiten.
checks=(
  "get secrets" "list secrets" "list pods" "create pods" "create pods/exec"
  "create deployments.apps" "create rolebindings.rbac.authorization.k8s.io"
  "list configmaps" "list namespaces" "create serviceaccounts/token"
)
for sa in "${SERVICE_ACCOUNTS[@]}"; do
  subject="system:serviceaccount:$NAMESPACE:$sa"
  for check in "${checks[@]}"; do
    # shellcheck disable=SC2086  # "verb resource" bewusst in zwei Argumente teilen
    answer="$(kubectl auth can-i $check -n "$NAMESPACE" --as="$subject" 2>/dev/null || true)"
    [[ "$answer" == "no" ]] && pass "$sa: can-i $check = no" \
      || fail "$sa: can-i $check = '$answer'"
  done
done
bindings="$(kubectl -n "$NAMESPACE" get rolebindings -o name 2>/dev/null | wc -l | tr -d ' ')"
[[ "$bindings" == "0" ]] && pass "keine RoleBindings im Namespace" \
  || fail "$bindings RoleBinding(s) im Namespace"

echo "Kontingente"
kubectl -n "$NAMESPACE" get resourcequota praxis-quota >/dev/null 2>&1 && pass "ResourceQuota praxis-quota vorhanden" \
  || fail "ResourceQuota praxis-quota fehlt"
kubectl -n "$NAMESPACE" get limitrange praxis-limits >/dev/null 2>&1 && pass "LimitRange praxis-limits vorhanden" \
  || fail "LimitRange praxis-limits fehlt"

echo "Workloads (SR-10 c; übersprungen, solange nur die Plattform läuft)"
workloads="$(kubectl -n "$NAMESPACE" get deployments,statefulsets -o name 2>/dev/null || true)"
[[ -z "$workloads" ]] && echo "  -     keine Deployments/StatefulSets"
for w in $workloads; do
  spec='.spec.template.spec'
  pod="$(kubectl -n "$NAMESPACE" get "$w" -o jsonpath="{$spec.securityContext.runAsNonRoot} {$spec.securityContext.seccompProfile.type} {$spec.automountServiceAccountToken}")"
  [[ "$pod" == "true RuntimeDefault false" ]] && pass "$w: runAsNonRoot, seccomp RuntimeDefault, kein SA-Token" \
    || fail "$w: Pod-SecurityContext '$pod' (erwartet: true RuntimeDefault false)"
  fields='{.name} {.securityContext.readOnlyRootFilesystem} {.securityContext.allowPrivilegeEscalation} {.securityContext.capabilities.drop} {.resources.requests.cpu} {.resources.limits.cpu} {.resources.limits.memory}{"\n"}'
  while read -r name ro ape drop req_cpu lim_cpu lim_mem; do
    [[ -z "$name" ]] && continue
    [[ "$ro $ape $drop" == 'true false ["ALL"]' && -n "$req_cpu" && -n "$lim_cpu" && -n "$lim_mem" ]] \
      && pass "$w/$name: read-only, keine Eskalation, drop ALL, Requests/Limits" \
      || fail "$w/$name: readOnly=$ro escalation=$ape drop=$drop requests.cpu=$req_cpu limits=$lim_cpu/$lim_mem"
  done < <(kubectl -n "$NAMESPACE" get "$w" -o jsonpath="{range $spec.initContainers[*]}$fields{end}{range $spec.containers[*]}$fields{end}")
done

echo "Secret-Verteilung (SR-06: nur an die Pods, die sie brauchen)"
secret_refs() {  # $1 Workload, $2 Teilbaum der Pod-Spec
  kubectl -n "$NAMESPACE" get "$1" -o jsonpath="{.spec.template.spec.$2..secretKeyRef.key} {.spec.template.spec.$2..secretRef.name} {.spec.template.spec.volumes[*].secret.secretName}" 2>/dev/null | xargs
}
if kubectl -n "$NAMESPACE" get deployment/praxis-frontend >/dev/null 2>&1; then
  refs="$(secret_refs deployment/praxis-frontend containers)"
  [[ -z "$refs" ]] && pass "praxis-frontend: keine Secrets" || fail "praxis-frontend: Secrets '$refs'"
fi
if kubectl -n "$NAMESPACE" get deployment/praxis-backend >/dev/null 2>&1; then
  refs="$(secret_refs deployment/praxis-backend containers)"
  [[ " $refs " != *" POSTGRES_PASSWORD "* && " $refs " != *" MIGRATE_PASSWORD "* ]] \
    && pass "praxis-backend/api: kein Superuser- und kein Migrationspasswort ($refs)" \
    || fail "praxis-backend/api: zu viele Secrets ($refs)"
  refs="$(secret_refs deployment/praxis-backend initContainers)"
  [[ " $refs " != *" POSTGRES_PASSWORD "* && " $refs " != *" APP_PASSWORD "* && " $refs " != *" ADMIN_BOOTSTRAP_PASSWORD "* ]] \
    && pass "praxis-backend/migrate: kein Superuser-, App- oder Admin-Passwort ($refs)" \
    || fail "praxis-backend/migrate: zu viele Secrets ($refs)"
fi

echo ""
if (( failures > 0 )); then
  echo "$failures Prüfung(en) fehlgeschlagen"
  exit 1
fi
echo "Alle Prüfungen bestanden"
