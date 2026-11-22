CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE vulnerabilities (
  cve_id text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  title text,
  description text,
  state text NOT NULL DEFAULT 'PUBLISHED',
  published_at timestamptz,
  updated_at timestamptz,
  selected_cvss_version text,
  selected_cvss_score numeric(3,1),
  selected_cvss_severity text,
  selected_cvss_vector text,
  selected_cvss_source text,
  selected_cvss_provider text,
  raw_record jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  ingested_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cvss_metrics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id text NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
  version text NOT NULL,
  base_score numeric(3,1) NOT NULL,
  severity text,
  vector text,
  source_class text NOT NULL,
  provider text,
  provider_org_id text,
  source_url text,
  published_at timestamptz,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cve_id, version, vector, source_class, provider)
);

CREATE TABLE epss_history (
  cve_id text NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
  score_date date NOT NULL,
  epss numeric(12,9) NOT NULL CHECK (epss BETWEEN 0 AND 1),
  percentile numeric(12,9) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, score_date)
);

CREATE TABLE kev_entries (
  cve_id text PRIMARY KEY REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
  vendor_project text,
  product text,
  vulnerability_name text,
  date_added date NOT NULL,
  short_description text,
  required_action text,
  due_date date,
  known_ransomware_campaign_use text,
  notes text,
  raw_record jsonb NOT NULL,
  fetched_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE application_matches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id text NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
  source text NOT NULL,
  external_application_id text,
  host_id text NOT NULL,
  application_name text NOT NULL,
  vendor text,
  installed_version text,
  architecture text,
  installation_paths jsonb NOT NULL DEFAULT '[]',
  match_confidence text NOT NULL,
  match_state text NOT NULL,
  evidence jsonb NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cve_id, source, external_application_id, host_id)
);

CREATE TABLE hosts (
  source text NOT NULL,
  host_id text NOT NULL,
  hostname text,
  local_ip text,
  external_ip text,
  platform_name text,
  os_version text,
  architecture text,
  internet_exposure boolean,
  exposure_source text,
  last_seen_at timestamptz,
  details jsonb NOT NULL,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (source, host_id)
);

CREATE TABLE alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id text NOT NULL REFERENCES vulnerabilities(cve_id),
  priority text NOT NULL,
  state text NOT NULL DEFAULT 'OPEN',
  subject text NOT NULL,
  executive_summary text NOT NULL,
  mail_body jsonb NOT NULL,
  decision_trace jsonb NOT NULL,
  policy_version text NOT NULL,
  fingerprint text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alert_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  consumer_id text NOT NULL,
  status text NOT NULL DEFAULT 'AVAILABLE',
  lease_token uuid,
  leased_until timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  acknowledged_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (alert_id, consumer_id)
);

CREATE TABLE feed_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  feed text NOT NULL,
  status text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  records_processed integer NOT NULL DEFAULT 0,
  cursor text,
  error_summary text,
  metadata jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_vulnerabilities_score ON vulnerabilities(selected_cvss_score DESC);
CREATE INDEX idx_epss_latest ON epss_history(cve_id, score_date DESC);
CREATE INDEX idx_matches_cve ON application_matches(cve_id);
CREATE INDEX idx_alerts_state_priority ON alerts(state, priority, created_at DESC);
CREATE INDEX idx_deliveries_claim ON alert_deliveries(consumer_id, status, leased_until);
