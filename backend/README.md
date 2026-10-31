# KubeShield backend

FastAPI service that ingests Falco, Kyverno and Cilium Hubble telemetry, correlates incidents,
runs the response engine and serves the dashboard. See the repository README and `docs/` for details.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest
```
