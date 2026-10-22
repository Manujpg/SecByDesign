#!/usr/bin/env bash
# Prüft die Least-Privilege-Eigenschaften des Namespaces gegen den laufenden Cluster
# (Paket L2, Nachweis SR-10 a/b). Exit-Code 1, sobald eine Prüfung fehlschlägt.
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

echo ""
if (( failures > 0 )); then
  echo "$failures Prüfung(en) fehlgeschlagen"
  exit 1
fi
echo "Alle Prüfungen bestanden"
