import { z } from 'zod';
import type { EpssScore } from '../domain/types.js';
import { fetchJson } from './http.js';

const responseSchema = z.object({
  data: z.array(z.object({ cve: z.string(), epss: z.string(), percentile: z.string(), date: z.string() }))
});

export class EpssConnector {
  async getScores(cveIds: string[]): Promise<EpssScore[]> {
    const scores: EpssScore[] = [];
    for (const batch of chunks(cveIds, 80)) {
      const query = new URLSearchParams({ cve: batch.join(',') });
      const response = responseSchema.parse(await fetchJson(`https://api.first.org/data/v1/epss?${query}`));
      scores.push(...response.data.map((item) => ({
        cve: item.cve,
        epss: Number(item.epss),
        percentile: Number(item.percentile),
        scoreDate: item.date
      })));
    }
    return scores;
  }
}

function chunks<T>(values: T[], size: number): T[][] {
  return Array.from({ length: Math.ceil(values.length / size) }, (_, index) => values.slice(index * size, (index + 1) * size));
}
