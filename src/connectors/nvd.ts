import type { AppConfig } from '../config.js';
import type { CvssMetric } from '../domain/types.js';
import { fetchJson } from './http.js';

interface NvdResponse { vulnerabilities?: Array<{ cve?: Record<string, unknown> }> }

export class NvdConnector {
  constructor(private readonly config: AppConfig) {}

  async getCve(cveId: string): Promise<{ raw?: Record<string, unknown>; metrics: CvssMetric[] }> {
    const query = new URLSearchParams({ cveId });
    const headers = this.config.NVD_API_KEY ? { apiKey: this.config.NVD_API_KEY } : undefined;
    const response = await fetchJson<NvdResponse>(`https://services.nvd.nist.gov/rest/json/cves/2.0?${query}`, { headers });
    const cve = response.vulnerabilities?.[0]?.cve;
    return { raw: cve, metrics: extractNvdMetrics(cve) };
  }
}

export function extractNvdMetrics(cve?: Record<string, unknown>): CvssMetric[] {
  if (!cve || !isRecord(cve.metrics)) return [];
  const output: CvssMetric[] = [];
  const mappings = [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1']] as const;
  for (const [field, version] of mappings) {
    const entries = cve.metrics[field];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!isRecord(entry) || !isRecord(entry.cvssData) || typeof entry.cvssData.baseScore !== 'number') continue;
      output.push({
        version,
        source: 'NVD',
        baseScore: entry.cvssData.baseScore,
        severity: stringValue(entry.cvssData.baseSeverity),
        vector: stringValue(entry.cvssData.vectorString),
        provider: stringValue(entry.source) ?? 'NVD'
      });
    }
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function stringValue(value: unknown): string | undefined { return typeof value === 'string' ? value : undefined; }
