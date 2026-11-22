# Sentinel Advisory

Enterprise vulnerability intelligence and advisory automation for Node.js, PostgreSQL, CrowdStrike Falcon, CISA KEV, FIRST EPSS, NVD, and CVE List V5.

## What is implemented

- Incremental CVE List V5 ingestion from a local Git checkout
- CVSS 4.0-first selection with vendor/CNA, NVD, then CISA precedence
- CISA KEV synchronization every 20 minutes
- Daily EPSS history and freshness dates
- Targeted CrowdStrike US-2 application searches—never a full inventory export
- `host.id` resolution through the Falcon Hosts API
- Tri-state internet exposure without unsafe IP-based inference
- PostgreSQL audit, intelligence, match, alert, delivery, and feed-run tables
- KEV-first executive summaries and HTML host tables
- Lease-based claim/ack delivery API for Fusion or Power Automate
- Responsive enterprise dashboard
- PM2 configuration for a continuously running Windows service

The detailed design and acceptance criteria remain in [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).

## Requirements

- Node.js 22+
- PostgreSQL 15+
- Git
- A local checkout of `CVEProject/cvelistV5`
- CrowdStrike US-2 OAuth credentials with read access to Falcon Discover and Hosts

## Local setup

```powershell
Copy-Item .env.example .env
npm install --legacy-peer-deps
npm run db:migrate
npm run dev
```

Environment values are read from the process environment. Load `.env` through your Windows service/secret-management mechanism; the application deliberately does not commit or print secrets.

The dashboard is served by Vite at `http://127.0.0.1:5173` during development. Add `?demo=1` to preview the interface without a database. The API listens on `http://127.0.0.1:4100`.

## CVE List checkout

Clone the upstream repository outside this project and set `CVE_REPO_PATH` to its absolute path:

```powershell
git clone --filter=blob:none https://github.com/CVEProject/cvelistV5.git C:\SecurityData\cvelistV5
```

The first scheduled run records the current commit as a baseline and sends no historical alert flood. Later runs fetch and fast-forward `main`, process only added/modified files under `cves/`, and advance the cursor after successful processing.

## Production build

```powershell
npm run typecheck
npm test
npm run build
npm run db:migrate
pm2 start ecosystem.config.cjs
pm2 save
```

Configure PM2 boot persistence using the organization's approved Windows service wrapper or Task Scheduler. Run under a restricted service identity and inject secrets at runtime.

## Main API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Database-backed health check |
| `GET` | `/api/v1/dashboard/overview` | Dashboard summary and priority queue |
| `GET` | `/api/v1/connectors` | Connector readiness without secrets |
| `POST` | `/api/v1/crowdstrike/applications/search` | Targeted application and host lookup |
| `POST` | `/api/v1/feeds/cve-list/sync` | Incremental CVE repository sync |
| `POST` | `/api/v1/feeds/cisa-kev/sync` | CISA KEV sync and new-KEV re-evaluation |
| `POST` | `/api/v1/feeds/epss/refresh` | Refresh current EPSS for relevant CVEs |
| `POST` | `/api/v1/alert-deliveries/claim` | Lease queued messages to a workflow consumer |
| `POST` | `/api/v1/alert-deliveries/:id/ack` | Acknowledge successful mail delivery |

## Verification

```powershell
npm run typecheck
npm test
npm run build
npm audit --omit=dev
```

No CrowdStrike client ID or secret is required for compilation or unit tests.

"# Advisory" 
