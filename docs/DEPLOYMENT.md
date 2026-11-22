# Windows and PostgreSQL deployment

## Database

Create a dedicated database and least-privilege application role, then provide the connection through `DATABASE_URL`. The migration requires permission to create tables, indexes, and the `pgcrypto` extension. After migrations, the runtime role needs normal read/write access to the application schema but does not need PostgreSQL superuser privileges.

Run migrations once per release before starting the new application build:

```powershell
npm run db:migrate
```

## Secrets

Required production secrets:

- `DATABASE_URL`
- `CROWDSTRIKE_CLIENT_ID`
- `CROWDSTRIKE_CLIENT_SECRET`
- `NVD_API_KEY` (recommended)

Do not store them in `.env` inside the Git checkout. Inject them through the Windows service identity, an approved secret manager, or protected machine-level environment variables.

## CrowdStrike

The connector is fixed to the confirmed US-2 origin by default. It performs:

1. filtered `GET /discover/queries/applications/v1` requests;
2. batched `GET /discover/entities/applications/v1` requests;
3. `host.id` deduplication;
4. batched `POST /devices/entities/devices/v2` host resolution.

It never downloads the entire application inventory. Authentication failures cause one token refresh and retry. Other errors remain failures/unknown states and cannot be interpreted as “not affected.”

## Process supervision

Build with `npm run build`, then start `ecosystem.config.cjs` through PM2. Use one application process because scheduled work currently runs in-process. Horizontal scaling requires a PostgreSQL advisory-lock leader before enabling schedulers on more than one instance.

Use the Windows service wrapper or Task Scheduler approved by the organization to restore PM2 after reboot. Set the working directory to the release directory and run the process as a restricted service account.

## Workflow polling

Configure Fusion or Power Automate to POST to `/api/v1/alert-deliveries/claim` with its stable consumer ID. After the email succeeds, POST the returned `leaseToken` to the acknowledgement endpoint. An unacknowledged lease becomes available again, preventing message loss.

Protect all non-health endpoints behind the enterprise reverse proxy/SSO layer before production use. Network-restrict the claim/ack endpoints to workflow runners and use TLS end to end.
