#!/usr/bin/env bash
# Create the complete KubeShield laboratory on a local kind cluster.
# Idempotent: re-running upgrades components in place.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER=kubeshield-lab
CTX="kind-${CLUSTER}"
IMAGE="kubeshield:0.1.0"
CILIUM_VERSION=1.20.4
FALCO_CHART_VERSION=9.2.2
KYVERNO_CHART_VERSION=3.9.2
K="kubectl --context ${CTX}"
H="helm --kube-context ${CTX}"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing required tool: $1" >&2; exit 1; }; }
for t in docker kind kubectl helm openssl; do need "$t"; done

log "Helm repositories"
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
helm repo update >/dev/null

if ! kind get clusters | grep -qx "${CLUSTER}"; then
  log "Creating kind cluster ${CLUSTER} (API and UI bound to 127.0.0.1 only)"
  kind create cluster --config "${ROOT}/deploy/kind/cluster.yaml"
fi

log "Cilium ${CILIUM_VERSION} + Hubble Relay"
$H upgrade --install cilium cilium/cilium --version "${CILIUM_VERSION}" -n kube-system \
  -f "${ROOT}/deploy/cilium/values.yaml" --wait --timeout 10m

log "Kyverno and KubeShield guardrail policies"
$H upgrade --install kyverno kyverno/kyverno --version "${KYVERNO_CHART_VERSION}" -n kyverno --create-namespace \
  -f "${ROOT}/deploy/kyverno/values.yaml" --wait --timeout 10m
$H upgrade --install kubeshield-policies "${ROOT}/deploy/helm/kubeshield-policies" -n kyverno --wait

log "Laboratory namespaces and workloads"
$K apply -f "${ROOT}/deploy/lab/"
$K create namespace kubeshield-system --dry-run=client -o yaml | $K apply -f -
$K label namespace kubeshield-system kubeshield.io/policy-mode=enforce --overwrite >/dev/null

log "Secrets (generated once, stored only in the cluster)"
if ! $K -n kubeshield-system get secret kubeshield-secrets >/dev/null 2>&1; then
  ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
  $K -n kubeshield-system create secret generic kubeshield-secrets \
    --from-literal=jwt-secret="$(openssl rand -hex 32)" \
    --from-literal=ingest-token="$(openssl rand -hex 32)" \
    --from-literal=postgres-password="$(openssl rand -hex 24)" \
    --from-literal=admin-password="${ADMIN_PASSWORD}" >/dev/null
fi
INGEST_TOKEN="$($K -n kubeshield-system get secret kubeshield-secrets -o jsonpath='{.data.ingest-token}' | base64 -d)"
$K create namespace falco --dry-run=client -o yaml | $K apply -f - >/dev/null
$K -n falco create secret generic falcosidekick-kubeshield \
  --from-literal=WEBHOOK_ADDRESS="http://kubeshield-api.kubeshield-system.svc:8000/api/v1/ingest/falco" \
  --from-literal=WEBHOOK_CUSTOMHEADERS="Authorization:Bearer ${INGEST_TOKEN}" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
unset INGEST_TOKEN

log "Falco ${FALCO_CHART_VERSION} with KubeShield rules"
$H upgrade --install falco falcosecurity/falco --version "${FALCO_CHART_VERSION}" -n falco \
  -f "${ROOT}/deploy/falco/values.yaml" \
  --set-file 'customRules.kubeshield_rules\.yaml='"${ROOT}/deploy/falco/kubeshield_rules.yaml" --wait --timeout 10m
$K -n falco rollout restart deployment/falco-falcosidekick >/dev/null

log "Building ${IMAGE}"
docker build -t "${IMAGE}" "${ROOT}"
kind load docker-image "${IMAGE}" --name "${CLUSTER}"

log "KubeShield"
$H upgrade --install kubeshield "${ROOT}/deploy/helm/kubeshield" -n kubeshield-system --wait --timeout 10m
$K -n kubeshield-system rollout restart deployment/kubeshield-api >/dev/null
$K -n kubeshield-system rollout status deployment/kubeshield-api --timeout 5m

cat <<MSG

KubeShield is running at http://127.0.0.1:8080 (bound to loopback only).
Username: admin
Password: run
  kubectl --context ${CTX} -n kubeshield-system get secret kubeshield-secrets -o jsonpath='{.data.admin-password}' | base64 -d; echo
MSG
