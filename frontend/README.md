# KubeShield web dashboard

React + TypeScript single-page app for the KubeShield API. It is built into
`frontend/dist` and served by the FastAPI backend at `/` (with history
fallback), so all API calls use relative `/api/v1/...` URLs.

## Requirements

- Node.js 20+ and npm

## Development

```bash
cd frontend
npm ci
npm run dev
```

The Vite dev server runs on http://localhost:5173 and proxies `/api` to the
backend at `http://127.0.0.1:8000`. Start the backend separately, then sign in
with a KubeShield account.

## Production build

```bash
cd frontend
npm ci
npm run build      # tsc -b && vite build -> frontend/dist
```

Set `KUBESHIELD_STATIC_DIR` to the `frontend/dist` path to serve the
dashboard. `npm run typecheck` runs the TypeScript checks only, and
`npm run preview` serves the built bundle locally (API calls still need the
backend behind the same origin).

## Notes

- Authentication uses the backend's HttpOnly session cookie; nothing is stored
  in `localStorage`. State-changing requests send `X-Requested-With: kubeshield`.
- The bundle contains no inline scripts and no external fonts or CDNs, so it
  works under the backend's Content-Security-Policy.
- Project: https://github.com/ahmedhany-cys/kubeshield
