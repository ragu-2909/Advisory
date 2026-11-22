export type CvssVersion = '4.0' | '3.1' | '3.0' | '2.0';
export type CvssSource = 'VENDOR_CNA' | 'NVD' | 'CISA' | 'OTHER_ADP';

export interface CvssMetric {
  version: CvssVersion;
  baseScore: number;
  severity?: string;
  vector?: string;
  source: CvssSource;
  provider?: string;
  providerOrgId?: string;
}

export interface EpssScore {
  cve: string;
  epss: number;
  percentile: number;
  scoreDate: string;
}

export interface RiskInput {
  cveId: string;
  selectedCvss?: CvssMetric;
  epss?: EpssScore;
  kev: boolean;
  ransomwareUseKnown?: boolean;
  confirmedAffectedAssets: number;
  internetExposure: true | false | null;
  unauthenticatedNetworkPath?: boolean;
  criticalAsset?: boolean;
}

export interface RiskDecision {
  decision: 'NO_ALERT' | 'REVIEW' | 'ALERT_P1' | 'ALERT_P2';
  priority: 'P1' | 'P2' | 'REVIEW' | 'NONE';
  reasons: string[];
  policyVersion: string;
}
