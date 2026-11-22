import type { AffectedProduct, ParsedCveRecord } from '../connectors/cve-record.js';
import type { CrowdStrikeApplicationMatch } from '../connectors/crowdstrike.js';
import { matchVersion } from '../domain/version-match.js';

export type ProductTarget = {
  product: AffectedProduct;
  relationship: 'Listed component' | 'Downstream application' | 'NVD inventory candidate';
  source: string;
  searchName: string;
};

export async function discoverProducts(record: ParsedCveRecord, nvd?: Record<string, unknown>) {
  const targets: ProductTarget[] = record.affected.map(product => ({
    product, relationship: 'Listed component', source: `https://www.cve.org/CVERecord?id=${record.cveId}`,
    searchName: product.product
  }));
  const warnings: string[] = [];
  const additionalReferences = Array.isArray(nvd?.references)
    ? nvd.references.flatMap(item => typeof item?.url === 'string' ? [item.url as string] : []) : [];
  const productNames = new Set(targets.map(target => identity(target.product.product)));
  if (Array.isArray(nvd?.configurations)) {
    for (const configuration of nvd.configurations) {
      if (!Array.isArray(configuration?.nodes)) continue;
      for (const node of configuration.nodes) {
        if (!Array.isArray(node?.cpeMatch)) continue;
        for (const match of node.cpeMatch) {
          if (match?.vulnerable !== true || typeof match.criteria !== 'string') continue;
          const [, , part, vendor, name] = match.criteria.split(':');
          if (part !== 'a' || !vendor || !name || !/^[a-z0-9_.-]+$/i.test(name) || productNames.has(identity(name))) continue;
          productNames.add(identity(name));
          const product = name.replaceAll('_', ' ');
          targets.push({
            product: { vendor, product, platforms: [], versions: [] },
            relationship: 'NVD inventory candidate', source: `https://nvd.nist.gov/vuln/detail/${record.cveId}`, searchName: product
          });
        }
      }
    }
  }
  const advisories = new Set([...record.references, ...additionalReferences].flatMap(reference => {
    if (!/^https:\/\/nodejs\.org\/en\/blog\/vulnerability\/[a-z0-9-]+\/?(?:[?#].*)?$/i.test(reference)) return [];
    return [reference.split(/[?#]/)[0]!.replace(/\/$/, '')];
  }));
  if (advisories.size > 3) warnings.push('Some Node.js references exceeded the advisory lookup limit.');
  await Promise.all([...advisories].slice(0, 3).map(async source => {
    try {
      const downstream = await readNodeAdvisory(source, record.cveId);
      if (downstream) targets.push(downstream);
    } catch {
      warnings.push(`Could not verify downstream versions from ${source}.`);
      targets.push(nodeTarget(source, []));
    }
  }));
  const unique = [...new Map(targets.map(target => [JSON.stringify(target), target])).values()];
  const order = { 'Downstream application': 0, 'Listed component': 1, 'NVD inventory candidate': 2 };
  return { targets: unique.sort((a, b) => order[a.relationship] - order[b.relationship]), warnings };
}

async function readNodeAdvisory(source: string, cveId: string) {
  const html = await readVendorPage(source);
  const headings = [...html.matchAll(/<h[23]\b[^>]*>[\s\S]*?<\/h[23]>/gi)];
  const index = headings.findIndex(heading => plainText(heading[0]).includes(`(${cveId})`));
  if (index < 0) return undefined;
  const section = plainText(html.slice(headings[index]!.index, headings[index + 1]?.index));
  const affectedStatement = /This vulnerability affects Node\.js\s+([^.!?]+(?:\.x[^.!?]*)*\.x)/i.exec(section)?.[1] ?? '';
  const branches = new Set([...affectedStatement.matchAll(/\b(\d+)\.x\b/g)].map(item => item[1]));
  const releases = [...new Set([...html.matchAll(/href="(?:https:\/\/nodejs\.org)?\/en\/blog\/release\/v(\d+\.\d+\.\d+)\/?"/g)]
    .map(item => item[1]!).filter(version => branches.has(version.split('.')[0])))];
  const byBranch = await Promise.all([...branches].map(async major => {
    const candidates = releases.filter(version => version.startsWith(`${major}.`));
    if (candidates.length !== 1) return undefined;
    const fixed = candidates[0]!;
    const release = plainText(await readVendorPage(`https://nodejs.org/en/blog/release/v${fixed}/`));
    if (!release.includes(cveId)) return undefined;
    return [
      { version: `${major}.0.0`, status: 'affected', lessThan: fixed, versionType: 'semver' },
      { version: fixed, status: 'unaffected', lessThan: `${Number(major) + 1}.0.0`, versionType: 'semver' }
    ];
  }));
  return nodeTarget(source, byBranch.flatMap(rules => rules ?? []));
}

function nodeTarget(source: string, versions: AffectedProduct['versions']): ProductTarget {
  return { product: { product: 'Node.js', vendor: 'Node.js project', platforms: [], versions }, relationship: 'Downstream application', source, searchName: 'Node.js' };
}

async function readVendorPage(url: string) {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: 'error' });
  if (!response.ok || !response.body) throw new Error('Vendor advisory unavailable');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let html = '';
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return html + decoder.decode();
      size += value.byteLength;
      if (size > 3_000_000) throw new Error('Vendor page exceeded the size limit');
      html += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

function plainText(html: string) {
  return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
}

export function matchTarget(target: ProductTarget, application: CrowdStrikeApplicationMatch) {
  const { product, relationship } = target;
  if (relationship === 'NVD inventory candidate') return 'REVIEW';
  const exactName = identity(application.name) === identity(product.product);
  const vendor = product.vendor?.trim().toLowerCase();
  const exactVendor = !vendor || vendor === 'n/a' || application.vendor?.trim().toLowerCase() === vendor;
  return exactName && (exactVendor || relationship === 'Downstream application')
    ? matchVersion(product, application.version?.replace(/^v(?=\d)/i, '')) : 'REVIEW';
}

function identity(name: string) { return name.trim().toLowerCase().replace(/[._ -]/g, ''); }
