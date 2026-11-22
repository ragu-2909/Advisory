# Cybersecurity Advisory Automation — Phase 1 Implementation Plan

Status: design baseline  
Runtime constraint: Node.js/TypeScript only; no Python; no Docker  
Target host: continuously running Windows server/EC2 instance

## 1. Objective

Continuously identify newly published or materially changed vulnerabilities, determine whether affected products exist in the organization's inventories, enrich them with current exploitation and severity intelligence, and produce actionable alerts without hiding high-risk findings because enrichment is incomplete.

The system will:

1. ingest changed CVE records from the CVE List V5 repository;
2. ingest CISA's KEV catalog independently;
3. refresh all relevant EPSS values every day;
4. enrich records with NVD metrics while retaining vendor/CNA and CISA attribution;
5. correlate affected products and versions with CrowdStrike and uploaded inventory files;
6. incorporate asset exposure and confidence into prioritization;
7. queue alert payloads for Fusion Workflow, Power Automate, or another mail sender;
8. provide a dashboard and an auditable explanation for every decision.

## 2. Authoritative inputs and refresh policy

| Input | Purpose | Refresh | Failure behavior |
|---|---|---:|---|
| CVE List V5 (`CVEProject/cvelistV5`) | Primary CVE record, CNA/vendor descriptions, affected versions, metrics and references | Incremental poll every 10 minutes | Retry with backoff; retain cursor; never advance cursor on partial failure |
| FIRST EPSS API/daily file | Latest probability of exploitation in the next 30 days and percentile | Daily after 14:00 UTC, plus retry until the feed date advances | Retain last value with `observedAt` and `scoreDate`; mark stale after 36 hours; missing/stale EPSS never suppresses a candidate |
| CISA KEV JSON | Evidence of known exploitation, required action, due date and ransomware metadata | Every 20 minutes using ETag/Last-Modified where available | Retain last valid catalog and show feed-health warning |
| NVD CVE API 2.0 | NVD CVSS enrichment and CPE/configuration data | On new/changed CVE, then retry incomplete records | Keep vendor data; label NVD enrichment pending; respect API-key rate limits |
| CrowdStrike Discover + Hosts APIs | On-demand application lookup and host-ID resolution | Per qualifying CVE/product; cache only results and host details | Retry with backoff; an API failure is `UNKNOWN`, never “application absent” |
| Uploaded CSV/XLSX inventory | Additional sources of truth | On upload and scheduled file replacement | Validate into staging; reject the batch atomically with row-level errors |
| Vendor RSS/advisories | Patch and mitigation context | Default hourly per feed | Do not use unverified prose to manufacture a CVSS value |

The CVE Git repository is processed incrementally. The service stores the last successfully processed commit SHA, fetches updates, obtains changed paths under `cves/`, validates each JSON record, and only then moves the cursor. An initial bootstrap is a separate controlled job so it cannot flood the alert queue.

## 3. CVSS selection and attribution

### 3.1 Deterministic precedence

CVSS version precedence is evaluated first, then publisher precedence within that version:

1. vendor/CNA CVSS 4.0;
2. NVD CVSS 4.0;
3. CISA-published CVSS 4.0, only when an explicit attributable metric exists;
4. vendor/CNA CVSS 3.1;
5. NVD CVSS 3.1;
6. CISA-published CVSS 3.1, only when an explicit attributable metric exists.

CVSS 3.0 or 2.0 is retained for display/history but is not selected for the phase-1 decision score. A missing score is represented as unknown, never as zero.

This ordering implements both requirements: CVSS 4.0 takes priority over 3.1, while vendor/CNA takes priority over NVD and CISA when comparing the same CVSS version.

### 3.2 What “vendor score” means

In CVE List V5, the CNA container is the primary published record. It is treated as vendor-originated only when the CNA/provider is the affected vendor or the metric has explicit vendor attribution. A coordinator or third-party CNA score remains a CNA score and its actual provider is displayed; it must not be mislabeled as vendor-authored.

All discovered metrics are stored, not just the selected metric. Each metric stores:

- CVSS version, base score, severity and vector;
- publisher/provider name and organization ID where present;
- source class (`VENDOR_CNA`, `NVD`, `CISA`, `OTHER_ADP`);
- source URL, publication/update time, and ingestion time;
- whether and why it was selected.

The dashboard and alerts display, for example: `9.8 CVSS 4.0 — Vendor/CNA`, rather than an unattributed number.

### 3.3 CISA clarification

CISA KEV is not a CVSS scoring feed. KEV membership is a strong, separate signal that exploitation has been observed. CISA ADP enrichment (for example SSVC) is also stored independently. The service will use a CISA CVSS value only if the source explicitly supplies a valid CVSS metric; it will not derive a “CISA score” from KEV fields.

## 4. EPSS lifecycle

EPSS changes daily, so it is modeled as time-series enrichment rather than a fixed property of a CVE.

- Fetch the current daily dataset after FIRST's normal daily publication time.
- Upsert `cveId + scoreDate`, retaining `epss`, `percentile`, `scoreDate`, `fetchedAt`, and model metadata when available.
- Refresh EPSS for every open/matched vulnerability, not only on first ingestion.
- Recalculate prioritization whenever the score date or value changes materially.
- Show both score and percentile as percentages and show “as of YYYY-MM-DD”.
- Keep at least 90 days of history to explain priority changes.
- Batch CVE API queries within documented limits or ingest the signed/daily CSV once at scale.
- If today's value is unavailable, use the latest retained value with a stale badge. No EPSS value means `unknown`, not `0%`.

EPSS estimates exploitation probability; it does not know whether an organizational asset is internet-facing or vulnerable. Exposure, authentication, asset criticality, and compensating controls are separate organizational inputs.

## 5. KEV and executive summary behavior

KEV is never rendered as a detached appendix or separate alert section. It appears at the start of the executive summary and affects the subject, priority, and recommended action.

Example executive-summary opening:

> **KNOWN EXPLOITED (CISA KEV): YES.** CVE-YYYY-NNNN affects 14 confirmed hosts, including 3 internet-facing systems. CISA requires action by YYYY-MM-DD. The selected severity is 9.8 (CVSS 4.0, Vendor/CNA); current EPSS is 94.2% (98th percentile, as of YYYY-MM-DD).

The email subject begins with `[KEV]` whenever true. The executive summary includes `dateAdded`, `dueDate`, required action, ransomware-campaign use, and the source link when supplied.

## 6. Correlation and matching

### 6.1 Inventory normalization

Normalize every source to a common asset/software model:

- source and source record ID;
- host/device ID, hostname, IP addresses and architecture;
- product, vendor, installed version, package identifier/CPE/PURL when available;
- operating system and architecture (`x64`, `x86`, `arm64`, etc.);
- internet exposure, listening service, authentication requirement and network zone;
- business owner, asset criticality and environment;
- last seen and source freshness.

CrowdStrike host IDs are resolved to host details before alert output. Architecture is a matching dimension, not a global filter: filtering only to `x64` would silently miss other affected systems.

### 6.2 CrowdStrike on-demand lookup flow

The service will not download or maintain the tenant's complete Falcon application inventory. It queries only products implicated by a qualifying CVE/KEV candidate.

The connector uses CrowdStrike OAuth2 client credentials and direct REST calls from Node.js. It does not use FalconPy or any Python component. The tenant is in CrowdStrike US-2, so the configured API origin is `https://api.us-2.crowdstrike.com`. The existing API client has read access across modules; the connector itself uses only the read operations it needs. Credentials are intentionally left unconfigured in source control and will be supplied during connector setup after deployment.

For each distinct normalized affected product/version range:

1. Build one or more escaped Falcon Query Language (FQL) filters from the CVE vendor/product, known aliases, affected versions, supported architectures and platform where available. Raw CVE or user-provided values are never concatenated into FQL without escaping and validation.
2. Call `GET /discover/queries/applications/v1` (`query_applications`) to search only for matching application IDs. Follow pagination until the match set is complete, subject to a configured safety ceiling.
3. Resolve returned application IDs in batches of at most 100 through `GET /discover/entities/applications/v1` (`get_applications`). Persist the application evidence returned by Falcon, including name, vendor, version, architecture, installation path, timestamps and the associated `host.id`. The tenant contract confirms that `host.id` is returned and is the canonical join identifier.
4. Deduplicate the Falcon `host.id` values across all matched application records.
5. Resolve host details using the Hosts service. Prefer `POST /devices/entities/devices/v2` (`GetDeviceDetails`/`PostDeviceDetailsV2`) so up to 5,000 IDs can be resolved per request; use the documented `GET /devices/entities/devices/v2` operation in batches of at most 100 only as a compatibility fallback.
6. Join host responses back to every application match by agent ID and store the correlation evidence. Mail output then includes hostname, local/external IP, OS/platform, architecture, last seen, tags/groups and other approved host fields.
7. Cache successful host detail responses for a short configurable TTL (default 15 minutes) so several CVEs affecting the same hosts do not repeat identical API calls. Cache keys include Falcon cloud/tenant plus host ID.

Internet exposure is tri-state: `TRUE`, `FALSE`, or `UNKNOWN`. If an explicit CrowdStrike `internet_exposure` value is returned by an approved application or host response, it is used with source and observation time. If it is absent, exposure remains `UNKNOWN`; the connector does not classify a host as internet-facing merely because `external_ip` is populated. A future authoritative network/cloud source can supplement this field without changing the CrowdStrike correlation contract. `UNKNOWN` exposure cannot reduce alert priority.

The connector records request operation, page/batch number, result count, duration, Falcon trace/request ID where available, and retry outcome, but never logs OAuth tokens or secrets.

The combined Discover endpoint (`GET /discover/combined/applications/v1`) is not used for the primary workflow because the requirement is to retrieve matching application records first and explicitly resolve their host IDs through the Hosts API. It may be enabled later only as an administrator-approved optimization with equivalent response-contract tests.

Result semantics are deliberately distinct:

- a successful, fully paged query with no application records means `NOT_FOUND_IN_CROWDSTRIKE`;
- a matched application outside the affected version/architecture means `PRESENT_NOT_AFFECTED`;
- a matched affected application with a resolved host means `CONFIRMED`;
- a matched application whose host cannot be resolved means `MATCHED_HOST_UNRESOLVED` and remains reviewable/alertable;
- authentication, authorization, timeout, rate-limit or partial-pagination failures mean `CROWDSTRIKE_LOOKUP_UNKNOWN`, never “not affected.”

The database stores only the targeted evidence returned for relevant products and the minimal cached host projection; it does not become a shadow copy of the complete CrowdStrike inventory.

### 6.3 Match confidence

Matches are evidence-based and retain their explanation:

- `CONFIRMED`: exact product identifier and affected version/range;
- `PROBABLE`: normalized vendor/product match with compatible but incomplete version data;
- `POSSIBLE`: fuzzy alias/product match or version unknown;
- `NOT_AFFECTED`: an explicit unaffected version/range or reviewed exclusion.

Only `CONFIRMED` and `PROBABLE` matches create automatic mail candidates by default. `POSSIBLE` matches enter a review queue and remain visible. Match rules support vendor/product aliases and must be testable; an LLM is not required for phase 1.

## 7. Risk and alert policy

Severity, exploitation likelihood, observed exploitation, exposure, impact and match confidence remain distinct fields. The engine emits both a priority and a plain-language rationale.

Default policy (configuration, not hard-coded constants):

| Condition on an affected organizational asset | Result |
|---|---|
| CISA KEV = true | Always alert; `P1` if internet-facing, critical asset, ransomware use is known, or selected CVSS >= 8.0; otherwise `P2` |
| Not KEV and selected CVSS >= 9.0 | Alert; `P1` for internet-facing/unauthenticated network path, otherwise `P2` |
| CVSS below threshold but EPSS/exposure indicates exceptional risk | Review candidate with explicit policy reason; no silent promotion |
| Score missing but KEV or credible active exploitation is present | Alert; do not wait for CVSS or EPSS |
| Inventory match is possible/ambiguous | Review queue; show potential host count |

This preserves the requested thresholds (`>= 9.0` normally and `>= 8.0` for urgent KEV handling) while ensuring a KEV affecting the organization is never hidden merely because its selected CVSS is 7.9 or unavailable.

Exposure is not inferred from EPSS. An internet-facing, unauthenticated network path increases urgency. A non-internet-facing asset can reduce priority, but it does not erase the finding because lateral access and internal threat paths remain possible.

Every decision stores a rule version and a trace such as:

```json
{
  "decision": "ALERT_P1",
  "reasons": [
    "CISA_KEV_TRUE",
    "INVENTORY_MATCH_CONFIRMED",
    "INTERNET_FACING_TRUE",
    "CVSS_4_SELECTED_VENDOR_CNA_9_8"
  ],
  "policyVersion": "1.0.0"
}
```

## 8. Alert queue and polling API

The producer creates an immutable alert event and a mail-ready projection. Consumers poll every 20 minutes; the server does not rely on a moving “last 20 minutes” query, which can lose messages during outages.

Recommended endpoint:

`POST /api/v1/alert-deliveries/claim`

Request:

```json
{
  "consumerId": "fusion-prod",
  "maxItems": 50,
  "leaseSeconds": 300
}
```

Response shape:

```json
{
  "generatedAt": "2026-11-22T07:00:00.000Z",
  "items": [
    {
      "deliveryId": "01...",
      "alertId": "01...",
      "subject": "[P1][KEV] CVE-YYYY-NNNN affects 14 hosts — action due YYYY-MM-DD",
      "body": {
        "contentType": "html",
        "executiveSummary": "KNOWN EXPLOITED (CISA KEV): YES...",
        "html": "<p>...</p><table>...</table>",
        "affectedHosts": [
          {
            "hostId": "...",
            "hostname": "host01",
            "ipAddresses": ["10.0.0.10"],
            "architecture": "x64",
            "installedProduct": "...",
            "installedVersion": "...",
            "internetFacing": true,
            "matchConfidence": "CONFIRMED"
          }
        ]
      },
      "facts": {
        "cveId": "CVE-YYYY-NNNN",
        "kev": true,
        "cvss": {"version": "4.0", "score": 9.8, "source": "VENDOR_CNA"},
        "epss": {"score": 0.942, "percentile": 0.98, "scoreDate": "2026-11-22"}
      }
    }
  ]
}
```

The consumer acknowledges successful sends with `POST /api/v1/alert-deliveries/{deliveryId}/ack`. Unacknowledged leases become available again. `alertId + consumerId` is the idempotency key, preventing both loss and duplicate mail. A compatibility `GET` endpoint can be added only if the chosen workflow cannot issue POST requests.

## 9. Dashboard

The authenticated web dashboard provides:

- executive overview: P1/P2 counts, affected hosts, KEV count, due/overdue action and feed health;
- active findings with CVSS version/source, current EPSS/date, KEV status embedded prominently, exposure and match confidence;
- CVE detail with all competing scores and the selection explanation;
- affected-host table with hostname, IP, architecture, installed/affected versions and freshness;
- ingestion, enrichment, correlation and delivery audit logs;
- review workflow for possible matches and false positives;
- configuration for thresholds, schedules, aliases, inventory uploads and RSS feeds;
- test-alert and feed-health views without exposing secrets.

## 10. Proposed Node.js architecture

Use a TypeScript monorepo with one deployable service initially:

```text
apps/
  api-worker/       Fastify API, schedulers and background jobs
  web/              React dashboard built to static assets
packages/
  domain/           CVE, score, inventory and decision models
  connectors/       CVE Git, FIRST, CISA, NVD, CrowdStrike, RSS, file upload
  correlation/      product/version normalization and evidence
  policy/           versioned deterministic alert rules
  notifications/    queue projection and HTML generation
  persistence/      migrations and repositories
```

Recommended components:

- Node.js current LTS and TypeScript;
- Fastify with JSON Schema/OpenAPI validation;
- React/Vite for the dashboard;
- PostgreSQL as the required production database for auditability, leases, concurrent jobs and retained intelligence history;
- a database-backed job/alert queue to avoid requiring Redis in phase 1;
- structured JSON logging with secret redaction;
- Zod or JSON Schema validation at every external boundary;
- Vitest plus fixture-based contract tests.

No AI/LLM is needed in phase 1. Deterministic rules are safer and auditable. A later optional AI layer may summarize vendor advisories or propose aliases, but it must cite its input and cannot decide affectedness or suppress alerts.

## 11. Windows operation

Build to versioned release directories and run the Node service under PM2 with an ecosystem configuration. Configure boot persistence through a managed Windows mechanism (for example a Windows service wrapper or Task Scheduler), use a restricted service account, and keep secrets in the Windows credential/secret facility or injected environment—not in Git.

Operational controls:

- health, readiness and dependency-health endpoints;
- PM2 restart limits and memory ceiling;
- daily database backup and tested restore;
- log rotation and retention;
- graceful shutdown so cursors and delivery leases remain consistent;
- outbound TLS verification and API timeouts;
- NVD/CrowdStrike rate-limit handling with jittered backoff;
- encrypted credentials and automatic token renewal.

## 12. Security controls

- OIDC/enterprise SSO for dashboard and APIs, with admin/analyst/consumer roles;
- CrowdStrike OAuth credentials supplied through deployment configuration, an NVD API key, and runtime enforcement of read-only connector operations;
- upload size/type limits, formula-injection neutralization, malware scanning hook and atomic import;
- SSRF protection for configurable RSS URLs;
- HTML escaping and a strict allow-list for advisory content;
- signed audit trail for configuration, review and delivery changes;
- webhook/polling consumer authentication and IP/network restrictions where appropriate;
- dependency lockfile, automated dependency scanning and reproducible builds.

## 13. Delivery milestones

1. **Foundation:** schemas, database migrations, configuration, structured logs, health endpoints and fixtures.
2. **Intelligence ingestion:** incremental CVE Git sync, CISA KEV sync, NVD enrichment, CVSS selector and daily EPSS history.
3. **Inventory:** targeted CrowdStrike OAuth/application search/host-ID resolution, normalized evidence and safe CSV/XLSX import.
4. **Correlation and policy:** version-range matching, aliases, exposure fields, decision traces and review queue.
5. **Notifications:** durable claim/ack API, HTML/JSON mail contract, deduplication and escalation updates.
6. **Dashboard:** executive view, finding/host detail, score provenance, logs, review and settings.
7. **Hardening/deployment:** SSO, Windows service/PM2 setup, backups, monitoring, load/failure tests and runbooks.

## 14. Acceptance tests for the clarified requirements

The implementation is not accepted until automated tests demonstrate:

1. vendor CVSS 4.0 beats NVD and CISA CVSS 4.0;
2. NVD CVSS 4.0 beats vendor CVSS 3.1 because version precedence is first;
3. vendor CVSS 3.1 wins when no valid CVSS 4.0 exists;
4. invalid or missing metrics do not become zero and do not block KEV alerts;
5. every selected score exposes version, provider and selection reason;
6. EPSS is updated on a later score date and the previous daily value remains queryable;
7. stale/missing EPSS cannot suppress an otherwise qualifying alert;
8. an affected KEV appears in the first sentence of the executive summary and prefixes the subject;
9. an affected KEV below CVSS 8.0 still generates an alert under the safety rule;
10. a non-KEV CVE at CVSS 9.0 qualifies, while 8.9 follows the configured non-KEV path;
11. x86/arm64 inventory is not lost through an x64-only CrowdStrike query;
12. CrowdStrike host IDs resolve to hostname and IP fields in the mail JSON;
13. a crashed poll consumer can reclaim an unacknowledged delivery without duplicate acknowledgement;
14. a changed CVE record is re-evaluated without generating a duplicate alert unless material facts changed;
15. CISA KEV metadata is never described as a CISA CVSS score.
16. a CVE product lookup issues a filtered Discover application query and never starts a full inventory export;
17. all pages of matching application IDs are resolved to application entities in batches of at most 100;
18. deduplicated host IDs are resolved with the Hosts API and joined back to the correct application evidence;
19. CrowdStrike API errors and partial pagination produce `CROWDSTRIKE_LOOKUP_UNKNOWN`, not an empty/not-affected result;
20. repeated CVEs for a cached host avoid an unnecessary host-detail request while preserving fresh application evidence.

## 15. Decisions needed before implementation

The design can proceed with the confirmed US-2 region, read-enabled API client and `host.id` join contract. These deployment facts remain to be supplied before the corresponding feature is enabled:

- CrowdStrike client ID and client secret through connector/deployment configuration after the project is ready (never committed to Git);
- optional redacted application and host responses for final contract-fixture validation; implementation will use the confirmed `host.id` field;
- an additional authoritative exposure source if CrowdStrike does not return an explicit `internet_exposure` value;
- enterprise SSO/OIDC issuer and expected roles;
- the first uploaded inventory column mapping and authoritative-source conflict rule;
- the final workflow's support for POST plus acknowledgement;
- alert recipients/routing ownership and remediation SLA by priority.

## 16. Primary references

- CVE List V5: <https://github.com/CVEProject/cvelistV5/tree/main/cves>
- CVE Record Format: <https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json>
- FIRST EPSS API: <https://api.first.org/epss/>
- FIRST EPSS FAQ: <https://www.first.org/epss/faq>
- CISA KEV catalog: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CISA KEV JSON: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- NVD CVE API: <https://nvd.nist.gov/developers/vulnerabilities>
- NVD CVSS guidance: <https://nvd.nist.gov/vuln-metrics/cvss>
- CrowdStrike FalconPy Discover service definitions (authoritative operation mapping used only as REST documentation): <https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/discover.py>
- CrowdStrike Discover endpoint definitions: <https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_discover.py>
- CrowdStrike Hosts endpoint definitions: <https://github.com/CrowdStrike/falconpy/blob/main/src/falconpy/_endpoint/_hosts.py>

