import { describe, expect, it } from 'vitest';
import { evaluateRisk } from './risk-policy.js';

describe('evaluateRisk', () => {
  it('alerts on affected KEV even below CVSS 8', () => {
    const result = evaluateRisk({
      cveId: 'CVE-2026-1000', kev: true, confirmedAffectedAssets: 1, internetExposure: false,
      selectedCvss: { version: '3.1', source: 'VENDOR_CNA', baseScore: 7.5 }
    });
    expect(result.decision).toBe('ALERT_P2');
  });

  it('makes unknown exposure urgent for KEV to avoid false reassurance', () => {
    const result = evaluateRisk({ cveId: 'CVE-2026-1001', kev: true, confirmedAffectedAssets: 1, internetExposure: null });
    expect(result.decision).toBe('ALERT_P1');
  });

  it('alerts for a non-KEV CVSS 9 finding', () => {
    const result = evaluateRisk({
      cveId: 'CVE-2026-1002', kev: false, confirmedAffectedAssets: 2, internetExposure: false,
      selectedCvss: { version: '4.0', source: 'NVD', baseScore: 9 }
    });
    expect(result.decision).toBe('ALERT_P2');
  });

  it('never alerts without an affected asset match', () => {
    const result = evaluateRisk({ cveId: 'CVE-2026-1003', kev: true, confirmedAffectedAssets: 0, internetExposure: true });
    expect(result.decision).toBe('NO_ALERT');
  });
});
