import type { RiskDecision, RiskInput } from './types.js';

export const POLICY_VERSION = '1.0.0';

export function evaluateRisk(input: RiskInput): RiskDecision {
  const reasons: string[] = [];
  if (input.confirmedAffectedAssets <= 0) {
    return { decision: 'NO_ALERT', priority: 'NONE', reasons: ['NO_CONFIRMED_AFFECTED_ASSETS'], policyVersion: POLICY_VERSION };
  }

  reasons.push('INVENTORY_MATCH_CONFIRMED');
  if (input.kev) reasons.push('CISA_KEV_TRUE');
  if (input.internetExposure === true) reasons.push('INTERNET_FACING_TRUE');
  if (input.internetExposure === null) reasons.push('INTERNET_EXPOSURE_UNKNOWN');
  if (input.unauthenticatedNetworkPath) reasons.push('UNAUTHENTICATED_NETWORK_PATH');
  if (input.criticalAsset) reasons.push('CRITICAL_ASSET');
  if (input.ransomwareUseKnown) reasons.push('KNOWN_RANSOMWARE_USE');
  if (input.selectedCvss) {
    reasons.push(`CVSS_${input.selectedCvss.version.replace('.', '_')}_${input.selectedCvss.source}_${input.selectedCvss.baseScore}`);
  } else {
    reasons.push('CVSS_UNKNOWN');
  }

  if (input.kev) {
    const urgent = input.internetExposure !== false || input.criticalAsset || input.ransomwareUseKnown || (input.selectedCvss?.baseScore ?? 0) >= 8;
    return { decision: urgent ? 'ALERT_P1' : 'ALERT_P2', priority: urgent ? 'P1' : 'P2', reasons, policyVersion: POLICY_VERSION };
  }

  if ((input.selectedCvss?.baseScore ?? 0) >= 9) {
    const urgent = input.internetExposure === true || input.unauthenticatedNetworkPath || input.criticalAsset;
    return { decision: urgent ? 'ALERT_P1' : 'ALERT_P2', priority: urgent ? 'P1' : 'P2', reasons, policyVersion: POLICY_VERSION };
  }

  if ((input.epss?.epss ?? 0) >= 0.7 && input.internetExposure !== false) {
    reasons.push('EPSS_EXCEPTIONAL_REVIEW');
    return { decision: 'REVIEW', priority: 'REVIEW', reasons, policyVersion: POLICY_VERSION };
  }

  return { decision: 'NO_ALERT', priority: 'NONE', reasons, policyVersion: POLICY_VERSION };
}
