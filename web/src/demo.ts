import type { Overview } from './types';

export const demoOverview: Overview = {
  counts: { open: 24, p1: 6, p2: 18, cves: 11 },
  findings: [
    { id: '1', cveId: 'CVE-2026-129448', priority: 'P1', subject: 'Apache Roller remote code execution', createdAt: new Date().toISOString(), cvssScore: 9.8, cvssVersion: '4.0', cvssSource: 'VENDOR_CNA', kev: true, dueDate: '2026-11-23', epss: 0.941, percentile: 0.989, epssDate: '2026-11-21', affectedHosts: 14 },
    { id: '2', cveId: 'CVE-2026-107155', priority: 'P1', subject: 'SonicOS security control bypass', createdAt: new Date().toISOString(), cvssScore: 8.8, cvssVersion: '4.0', cvssSource: 'VENDOR_CNA', kev: true, dueDate: '2026-11-27', epss: 0.781, percentile: 0.963, epssDate: '2026-11-21', affectedHosts: 6 },
    { id: '3', cveId: 'CVE-2026-88321', priority: 'P2', subject: 'Node.js permission model bypass', createdAt: new Date().toISOString(), cvssScore: 9.1, cvssVersion: '3.1', cvssSource: 'NVD', kev: false, epss: 0.434, percentile: 0.872, epssDate: '2026-11-21', affectedHosts: 19 },
    { id: '4', cveId: 'CVE-2026-72418', priority: 'P2', subject: 'VMware management interface flaw', createdAt: new Date().toISOString(), cvssScore: 9.3, cvssVersion: '4.0', cvssSource: 'VENDOR_CNA', kev: false, epss: 0.287, percentile: 0.811, epssDate: '2026-11-21', affectedHosts: 3 }
  ],
  feeds: [
    { feed: 'CVE List V5', status: 'SUCCESS', completedAt: new Date(Date.now() - 4 * 60_000).toISOString(), recordsProcessed: 28 },
    { feed: 'CISA KEV', status: 'SUCCESS', completedAt: new Date(Date.now() - 11 * 60_000).toISOString(), recordsProcessed: 1462 },
    { feed: 'FIRST EPSS', status: 'SUCCESS', completedAt: new Date(Date.now() - 5 * 60 * 60_000).toISOString(), recordsProcessed: 312 },
    { feed: 'CrowdStrike US-2', status: 'SUCCESS', completedAt: new Date(Date.now() - 18 * 60_000).toISOString(), recordsProcessed: 42 }
  ]
};
