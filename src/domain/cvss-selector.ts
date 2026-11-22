import type { CvssMetric, CvssSource, CvssVersion } from './types.js';

const versionRank: Record<CvssVersion, number> = {
  '4.0': 0,
  '3.1': 1,
  '3.0': 20,
  '2.0': 30
};

const sourceRank: Record<CvssSource, number> = {
  VENDOR_CNA: 0,
  NVD: 1,
  CISA: 2,
  OTHER_ADP: 3
};

export function selectCvss(metrics: CvssMetric[]): CvssMetric | undefined {
  return metrics
    .filter((metric) => (metric.version === '4.0' || metric.version === '3.1') && isValidScore(metric.baseScore))
    .toSorted((left, right) => {
      const versionDifference = versionRank[left.version] - versionRank[right.version];
      if (versionDifference !== 0) return versionDifference;
      const sourceDifference = sourceRank[left.source] - sourceRank[right.source];
      if (sourceDifference !== 0) return sourceDifference;
      return right.baseScore - left.baseScore;
    })[0];
}

function isValidScore(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= 10;
}
