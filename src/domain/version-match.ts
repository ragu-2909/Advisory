import type { AffectedProduct } from '../connectors/cve-record.js';

function numericVersion(value: string) {
  return /^\d+(?:\.\d+)*$/.test(value) ? value.split('.').map(BigInt) : undefined;
}

function compare(left: string, right: string) {
  const a = numericVersion(left), b = numericVersion(right);
  if (!a || !b) return undefined;
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const difference = (a[index] ?? 0n) - (b[index] ?? 0n);
    if (difference) return difference > 0n ? 1 : -1;
  }
  return 0;
}

export function matchVersion(product: AffectedProduct, installed?: string) {
  if (!installed || product.platforms.length) return 'REVIEW';
  const statuses = new Set<string>();
  for (const rule of product.versions) {
    const end = rule.lessThan ?? rule.lessThanOrEqual;
    if (rule.hasChanges) { statuses.add('unknown'); continue; }
    if (!end) {
      if (rule.version === installed) statuses.add(rule.status);
      else if (rule.version === '*') statuses.add('unknown');
      continue;
    }
    if (!['semver', 'custom'].includes(rule.versionType ?? '')) { statuses.add('unknown'); continue; }
    const lower = rule.version === '0' ? 0 : compare(installed, rule.version);
    const upper = end === '*' ? -1 : compare(installed, end);
    if (lower === undefined || upper === undefined) statuses.add('unknown');
    else if (lower >= 0 && (upper < 0 || (upper === 0 && !rule.lessThan))) statuses.add(rule.status);
  }
  if (statuses.size === 1 && statuses.has('affected')) return 'AFFECTED';
  if (statuses.size === 1 && statuses.has('unaffected')) return 'UNAFFECTED';
  if (!statuses.size && product.defaultStatus === 'unaffected') return 'UNAFFECTED';
  return 'REVIEW';
}
