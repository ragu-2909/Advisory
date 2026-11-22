import { z } from 'zod';
import type { AppConfig } from '../config.js';
import { fetchJson, HttpError } from './http.js';

const falconEnvelope = z.object({
  meta: z.record(z.string(), z.unknown()).optional(),
  resources: z.array(z.unknown()).default([]),
  errors: z.array(z.unknown()).optional()
}).passthrough();

export interface ApplicationSearch {
  name: string;
  vendor?: string;
  versions?: string[];
  architectures?: string[];
  limit?: number;
}

export interface CrowdStrikeApplicationMatch {
  applicationId: string;
  hostId: string;
  name: string;
  vendor?: string;
  version?: string;
  architecture?: string;
  installationPaths: string[];
  application: Record<string, unknown>;
  host?: Record<string, unknown>;
  exposure: true | false | null;
}

interface TokenResponse { access_token: string; expires_in: number; token_type: string }

export class CrowdStrikeConnector {
  private token?: { value: string; expiresAt: number };

  constructor(private readonly config: AppConfig) {}

  get configured(): boolean {
    return Boolean(this.config.CROWDSTRIKE_CLIENT_ID?.trim() && this.config.CROWDSTRIKE_CLIENT_SECRET?.trim());
  }

  get baseUrl() { return this.config.CROWDSTRIKE_BASE_URL.replace(/\/+$/, ''); }

  async checkAuthentication() {
    await this.getToken(true);
    return { status: 'Authenticated', baseUrl: this.baseUrl };
  }

  async searchApplications(input: ApplicationSearch): Promise<CrowdStrikeApplicationMatch[]> {
    if (!this.configured) throw new Error('CrowdStrike connector is not configured');
    const filter = buildApplicationFilter(input);
    const applicationIds = await this.queryAllApplicationIds(filter, input.limit ?? 5_000);
    if (applicationIds.length === 0) return [];

    const applications = await this.getApplicationEntities(applicationIds);
    if (applications.length !== applicationIds.length || applications.some(app => !getHostId(app))) {
      throw new Error('Falcon returned incomplete application or host identifiers.');
    }
    const hostIds = [...new Set(applications.map(getHostId).filter((id): id is string => Boolean(id)))];
    const hosts = await this.getHostEntities(hostIds);
    const hostById = new Map(hosts.map((host) => [String(host.device_id ?? host.id ?? ''), host]));

    return applications.flatMap((application) => {
      const hostId = getHostId(application);
      if (!hostId) return [];
      const host = hostById.get(hostId);
      return [{
        applicationId: String(application.id ?? ''),
        hostId,
        name: String(application.name ?? input.name),
        vendor: optionalString(application.vendor),
        version: optionalString(application.version),
        architecture: firstString(application.architectures) ?? optionalString(application.architecture),
        installationPaths: stringArray(application.installation_paths),
        application,
        host,
        exposure: explicitExposure(application, host)
      }];
    });
  }

  private async getToken(force = false): Promise<string> {
    if (!this.configured) throw new Error('Set both CrowdStrike credential fields and restart the API.');
    if (!force && this.token && this.token.expiresAt > Date.now() + 60_000) return this.token.value;
    const body = new URLSearchParams({
      client_id: this.config.CROWDSTRIKE_CLIENT_ID!.trim(),
      client_secret: this.config.CROWDSTRIKE_CLIENT_SECRET!.trim()
    });
    const token = await fetchJson<TokenResponse>(`${this.baseUrl}/oauth2/token`, {
      method: 'POST',
      redirect: 'error',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    }).catch(error => {
      if (!(error instanceof HttpError)) throw new Error(`Falcon OAuth connection failed at ${this.baseUrl}. Check DNS, TLS and outbound access.`);
      const hint = [400, 401, 403].includes(error.status)
        ? ' Check that this active API client ID and secret are from the same Falcon cloud and that the service loaded the current values.'
        : '';
      throw new Error(`Falcon OAuth token request returned HTTP ${error.status} at ${this.baseUrl}.${hint}`);
    });
    if (!token.access_token || !Number.isFinite(token.expires_in)) throw new Error('Falcon OAuth did not return a usable access token.');
    this.token = { value: token.access_token, expiresAt: Date.now() + token.expires_in * 1_000 };
    return token.access_token;
  }

  private async request(path: string, init: RequestInit = {}): Promise<z.infer<typeof falconEnvelope>> {
    const execute = async () => {
      const token = await this.getToken();
      return falconEnvelope.parse(await fetchJson<unknown>(`${this.baseUrl}${path}`, {
        ...init, redirect: 'error',
        headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) }
      }));
    };
    try {
      try { return await execute(); }
      catch (error) {
        if (!(error instanceof HttpError) || error.status !== 401) throw error;
        this.token = undefined;
        return await execute();
      }
    } catch (error) {
      if (error instanceof HttpError) {
        const scope = path.startsWith('/discover/') ? 'Falcon Discover: Read' : 'Hosts: Read';
        throw new Error(`Falcon ${path.split('?')[0]} returned HTTP ${error.status} after authentication. Check ${scope} and tenant access.`);
      }
      throw error;
    }
  }

  private async queryAllApplicationIds(filter: string, safetyLimit: number): Promise<string[]> {
    const ids: string[] = [];
    let offset = 0;
    const pageSize = 100;
    while (ids.length < safetyLimit) {
      const query = new URLSearchParams({ filter, limit: String(pageSize), offset: String(offset) });
      const envelope = await this.request(`/discover/queries/applications/v1?${query}`);
      if (envelope.errors?.length) throw new Error('Falcon Discover returned application search errors.');
      const page = envelope.resources.map(String);
      ids.push(...page);
      if (page.length < pageSize) break;
      offset += page.length;
    }
    if (ids.length >= safetyLimit) throw new Error('Falcon result limit reached. Application coverage is incomplete.');
    return ids;
  }

  private async getApplicationEntities(ids: string[]): Promise<Record<string, unknown>[]> {
    const entities: Record<string, unknown>[] = [];
    for (const batch of chunks(ids, 100)) {
      const query = new URLSearchParams();
      for (const id of batch) query.append('ids', id);
      const envelope = await this.request(`/discover/entities/applications/v1?${query}`);
      entities.push(...envelope.resources.filter(isRecord));
    }
    return entities;
  }

  private async getHostEntities(ids: string[]): Promise<Record<string, unknown>[]> {
    const entities: Record<string, unknown>[] = [];
    for (const batch of chunks(ids, 5_000)) {
      const envelope = await this.request('/devices/entities/devices/v2', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ids: batch })
      });
      entities.push(...envelope.resources.filter(isRecord));
    }
    return entities;
  }
}

export function buildApplicationFilter(input: ApplicationSearch): string {
  const clauses = [`name:*'*${escapeFql(input.name)}*'`];
  if (input.vendor) clauses.push(`vendor:*'*${escapeFql(input.vendor)}*'`);
  if (input.architectures?.length) {
    clauses.push(`architectures:[${input.architectures.map((value) => `'${escapeFql(value)}'`).join(',')}]`);
  }
  return clauses.join('+');
}

function escapeFql(value: string): string {
  return value.replace(/[\\'*]/g, (character) => `\\${character}`).replace(/[\r\n]/g, ' ').trim();
}

function getHostId(application: Record<string, unknown>): string | undefined {
  const host = isRecord(application.host) ? application.host : undefined;
  return host ? optionalString(host.id) : undefined;
}

function explicitExposure(application: Record<string, unknown>, host?: Record<string, unknown>): true | false | null {
  const applicationHost = isRecord(application.host) ? application.host : undefined;
  const raw = applicationHost?.internet_exposure ?? host?.internet_exposure;
  if (raw === true || raw === 'Yes' || raw === 'yes') return true;
  if (raw === false || raw === 'No' || raw === 'no') return false;
  return null;
}

function chunks<T>(values: T[], size: number): T[][] {
  return Array.from({ length: Math.ceil(values.length / size) }, (_, index) => values.slice(index * size, (index + 1) * size));
}
function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value); }
function optionalString(value: unknown): string | undefined { return typeof value === 'string' && value ? value : undefined; }
function firstString(value: unknown): string | undefined { return Array.isArray(value) ? value.find((item): item is string => typeof item === 'string') : undefined; }
function stringArray(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []; }
