# Installation

KubeShield runs entirely on your machine: a single-node kind cluster, no cloud resources, no paid services.

## Requirements

| Tool | Tested version | Notes |
|---|---|---|
| Docker-compatible runtime | Colima 0.10.3 (Docker 29.5) on macOS 15 arm64 | Docker Desktop or Docker Engine on Linux also work |
| kind | 0.33.0 (Kubernetes 1.37.0 node image) | |
| kubectl | 1.37 | |
| Helm | 4.3.1 | |
| openssl | any | secret generation |
| Python | 3.12+ | only for running tests / the E2E harness from the host |
| Node.js | 24 | only for frontend development |

Resources: plan for at least **15 GB of free disk** (VM disk, images, Trivy DB). The full lab (Cilium, Falco, Kyverno, KubeShield, PostgreSQL, lab workloads) ran in a VM with
**4 CPUs and 3.5 GB RAM**. On an 8 GB Mac, giving the VM 6 GB caused
heavy host swapping, so 3.5 GB is the recommended size.

The kernel must support eBPF with BTF (Linux ≥ 5.8). Colima's Ubuntu 24.04 VM (kernel 6.8) works with
Falco's `modern_ebpf` driver.

### macOS with Colima

```bash
brew install colima docker docker-buildx kind kubectl helm
colima start --cpu 4 --memory 3.5 --disk 40 --vm-type vz --mount-type virtiofs
```

## Bring up the lab

```bash
git clone https://github.com/ahmedhany-cys/kubeshield.git
cd kubeshield
./scripts/lab-up.sh
```

The script is idempotent and performs, in order:

1. creates the kind cluster `kubeshield-lab` without the default CNI, API server on `127.0.0.1`;
2. installs Cilium 1.20.4 with Hubble Relay (`deploy/cilium/values.yaml`);
3. installs Kyverno 1.19.2 and the KubeShield guardrail policies (`deploy/helm/kubeshield-policies`);
4. applies the lab namespaces and workloads (`deploy/lab/`);
5. generates secrets (JWT, ingest token, admin and database passwords) into the `kubeshield-secrets` Secret;
6. installs Falco 0.45.2 (chart 9.2.2) with the KubeShield rules and Falcosidekick pointed at KubeShield;
7. builds the `kubeshield:0.1.0` image, loads it into kind and installs `deploy/helm/kubeshield`.

Open <http://127.0.0.1:8080> and sign in as `admin`. Retrieve the generated password with:

```bash
kubectl --context kind-kubeshield-lab -n kubeshield-system get secret kubeshield-secrets \
  -o jsonpath='{.data.admin-password}' | base64 -d; echo
```

## Verify

```bash
kubectl --context kind-kubeshield-lab get pods -A
python3 -m pip install httpx
python3 e2e/run_e2e.py            # runs all scenarios + the response flow, writes docs/validation/
```

In the UI, Settings → System status should list Falco, Falcosidekick, Kyverno, Cilium and Hubble Relay as
healthy (Tetragon is reported as not installed by design).

## Tear down

```bash
./scripts/lab-down.sh
colima stop
```

## Development without the cluster

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest                 # unit tests use SQLite and fake Kubernetes clients

cd ../frontend
npm ci
npm run dev                      # proxies /api to http://127.0.0.1:8000
```

To run the API on the host against the lab cluster, copy `.env.example` to `.env`, fill in the values,
port-forward Hubble Relay and start `uvicorn kubeshield.main:create_app --factory --port 8000`
(Falco alerts only reach the in-cluster API).
