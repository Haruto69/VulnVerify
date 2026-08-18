# VulnVerify Frontend

React + Vite frontend for VulnVerify. Talks to the FastAPI backend in
`../backend` over its `/api/v1` REST API — no other backend is
supported.

## Prerequisites

- Node.js 18+
- The backend running locally (see `../backend`), by default at
  `http://127.0.0.1:8000`

## Setup

```bash
npm install
npm run dev
```

The dev server runs at `http://localhost:5173` by default, which
matches the backend's CORS allowlist (`backend/main.py`). If you
change the Vite port, add it to that allowlist too — the backend
does not accept requests from arbitrary origins.

## Configuring the API URL

The app reads `VITE_API_URL` at build/dev time. If unset, it falls
back to `http://127.0.0.1:8000/api/v1`.

To override it, copy the example env file and edit it:

```bash
cp .env.example .env
```

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Start the Vite dev server |
| `npm run build` | Production build to `dist/` |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | Run ESLint |

## What's wired up

- Scan upload (`POST /scans`) — ZAP JSON / Burp XML
- Findings (`GET /scans/{id}/findings`)
- Per-finding verification (`POST /scans/{id}/findings/{id}/verify`)
  for CSRF, SQLi (TIME_BASED), and reflected XSS — the only families
  the backend currently supports
- Verified findings, deduplication, enrichment, and risk-priority
  results, each from their respective backend endpoint

Verification runs a real HTTP replay on the backend and can take up
to a minute or more; the UI reflects this with an explicit "Verifying…"
state rather than a fixed timer.

## Known gaps

- The "Verification Performance" panel (Precision/Recall/F1,
  confusion matrix) has no backing endpoint yet and is intentionally
  left as labeled demo data — do not remove that label without adding
  a real endpoint.
- "Generate Report" has no backend endpoint yet; it's a placeholder.
- Only SQLI, CSRF, and reflected-XSS findings can be verified; other
  categories (CORS, Information Disclosure, etc.) are shown but not
  verifiable, matching the backend's current scope.
