# Contributing to KubeShield

Thanks for your interest. Issues and pull requests are welcome.

## Development setup

```bash
# backend
cd backend && python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
python -m pytest && ruff check .

# frontend
cd frontend && npm ci && npm run build

# full lab (Docker, kind, kubectl, helm)
./scripts/lab-up.sh && python3 e2e/run_e2e.py
```

## Guidelines

- **Evidence over claims.** A new detection needs a Falco rule (or other source), a catalog entry in
  `backend/kubeshield/catalog.py`, a simulation scenario that triggers it, and a passing run of
  `e2e/run_e2e.py`. Do not mark anything as working without a recorded result.
- **Safe defaults.** Response actions must re-check the lab label, record their outcome and verify the
  resulting cluster state. Destructive actions must never run automatically by default.
- **Least privilege.** If a change needs a new Kubernetes permission, add it to the narrowest Role and
  document it in `docs/security-model.md`.
- **No secrets** in code, manifests, fixtures or screenshots.
- Keep the code style consistent: `ruff check .` for Python, strict TypeScript for the frontend.
- Use clear, conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
