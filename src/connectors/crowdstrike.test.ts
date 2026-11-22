import { describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../config.js';
import { buildApplicationFilter, CrowdStrikeConnector } from './crowdstrike.js';

describe('buildApplicationFilter', () => {
  it('targets the requested product and vendor', () => {
    expect(buildApplicationFilter({ name: 'Node.js', vendor: 'OpenJS', architectures: ['x64', 'arm64'] }))
      .toBe("name:*'*Node.js*'+vendor:*'*OpenJS*'+architectures:['x64','arm64']");
  });

  it('escapes FQL control quotes', () => {
    expect(buildApplicationFilter({ name: "Acme's Tool" })).toContain("Acme\\'s Tool");
  });
});

describe('Falcon host resolution', () => {
  it.each([200, 400])('preserves inventory and routes IDs correctly when Hosts returns HTTP %i', async status => {
    const a = 'a'.repeat(32), b = 'b'.repeat(32);
    const requests: Array<{ url: URL; body?: string }> = [];
    vi.stubGlobal('fetch', async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      requests.push({ url, body: typeof init?.body === 'string' ? init.body : undefined });
      const resources = (items: unknown[]) => Response.json({ resources: items });
      switch (url.pathname) {
        case '/oauth2/token': return Response.json({ access_token: 'fixture', expires_in: 1800 });
        case '/discover/queries/applications/v1': return resources(['one', 'two', 'three', 'four']);
        case '/discover/entities/applications/v1': return resources([
          { id: 'one', name: 'Node.js', version: '24.22.0', host: { id: 'asset-one', aid: a } },
          { id: 'two', name: 'Node.js', version: '24.22.1', host: { id: 'asset-two' } },
          { id: 'three', name: 'Node.js', version: '22.23.3', host: { id: 'asset-three', aid: b } },
          { id: 'four', name: 'Node.js', version: '26.12.0', host: { id: 'asset-four' } }
        ]);
        case '/devices/entities/devices/v2': return status === 400
          ? Response.json({ errors: [{ code: 400 }] }, { status })
          : resources([{ device_id: a, hostname: 'sensor-one' }]);
        case '/discover/entities/hosts/v1': return resources([
          { id: 'asset-one', hostname: 'discover-one' },
          { id: 'asset-two', hostname: 'discover-two', current_local_ip: '10.0.0.2' },
          { id: 'asset-three', hostname: 'discover-three' }
        ]);
        default: throw new Error('Unexpected route');
      }
    });
    try {
      const connector = new CrowdStrikeConnector(loadConfig({ CROWDSTRIKE_CLIENT_ID: 'fixture', CROWDSTRIKE_CLIENT_SECRET: 'fixture' }));
      const matches = await connector.searchApplications({ name: 'Node.js' });
      expect(requests.find(request => request.url.pathname === '/devices/entities/devices/v2')?.body)
        .toBe(JSON.stringify({ ids: [a, b] }));
      expect(requests.find(request => request.url.pathname === '/discover/entities/hosts/v1')?.url.searchParams.getAll('ids'))
        .toEqual([...(status === 400 ? ['asset-one'] : []), 'asset-two', 'asset-three', 'asset-four']);
      expect(matches.map(match => match.host?.hostname))
        .toEqual([status === 400 ? 'discover-one' : 'sensor-one', 'discover-two', 'discover-three', undefined]);
      expect(matches[1]?.host?.local_ip).toBe('10.0.0.2');
      expect(matches[3]).toMatchObject({ version: '26.12.0', hostResolutionIssue: expect.stringContaining('no matching host details') });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
