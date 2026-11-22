import { describe, expect, it } from 'vitest';
import { selectCvss } from './cvss-selector.js';
import type { CvssMetric } from './types.js';

const metric = (version: CvssMetric['version'], source: CvssMetric['source'], baseScore: number): CvssMetric => ({ version, source, baseScore });

describe('selectCvss', () => {
  it('prefers vendor CVSS 4.0 within the same version', () => {
    expect(selectCvss([metric('4.0', 'NVD', 10), metric('4.0', 'VENDOR_CNA', 9.3)]))
      .toEqual(metric('4.0', 'VENDOR_CNA', 9.3));
  });

  it('prefers NVD 4.0 over vendor 3.1 because version precedence is first', () => {
    expect(selectCvss([metric('3.1', 'VENDOR_CNA', 10), metric('4.0', 'NVD', 8.8)]))
      .toEqual(metric('4.0', 'NVD', 8.8));
  });

  it('falls back to vendor 3.1 when no 4.0 metric exists', () => {
    expect(selectCvss([metric('3.1', 'NVD', 9.9), metric('3.1', 'VENDOR_CNA', 9.1)]))
      .toEqual(metric('3.1', 'VENDOR_CNA', 9.1));
  });

  it('does not select legacy metrics or invalid scores', () => {
    expect(selectCvss([metric('3.0', 'VENDOR_CNA', 10), metric('4.0', 'NVD', 11)])).toBeUndefined();
  });
});
