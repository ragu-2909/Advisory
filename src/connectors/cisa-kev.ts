import { z } from 'zod';
import { fetchJson } from './http.js';

export const kevEntrySchema = z.object({
  cveID: z.string(),
  vendorProject: z.string(),
  product: z.string(),
  vulnerabilityName: z.string(),
  dateAdded: z.string(),
  shortDescription: z.string(),
  requiredAction: z.string(),
  dueDate: z.string(),
  knownRansomwareCampaignUse: z.string(),
  notes: z.string().default('')
}).passthrough();

const catalogSchema = z.object({
  catalogVersion: z.string(),
  dateReleased: z.string(),
  vulnerabilities: z.array(kevEntrySchema)
});

export type KevEntry = z.infer<typeof kevEntrySchema>;

export class CisaKevConnector {
  async fetchCatalog() {
    return catalogSchema.parse(await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'));
  }
}
