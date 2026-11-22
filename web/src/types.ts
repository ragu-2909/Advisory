export interface Finding {
  id: string; cveId: string; priority: string; subject: string; createdAt: string;
  cvssScore?: number; cvssVersion?: string; cvssSource?: string; kev: boolean;
  dueDate?: string; epss?: number; percentile?: number; epssDate?: string; affectedHosts: number;
}
export interface Feed { feed: string; status: string; completedAt?: string; recordsProcessed: number; errorSummary?: string }
export interface Overview {
  counts: { open: number; p1: number; p2: number; cves: number };
  findings: Finding[];
  feeds: Feed[];
}
