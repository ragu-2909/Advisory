import { describe, expect, it } from 'vitest';
import { buildApplicationFilter } from './crowdstrike.js';

describe('buildApplicationFilter', () => {
  it('targets the requested product and vendor', () => {
    expect(buildApplicationFilter({ name: 'Node.js', vendor: 'OpenJS', architectures: ['x64', 'arm64'] }))
      .toBe("name:*'*Node.js*'+vendor:*'*OpenJS*'+architectures:['x64','arm64']");
  });

  it('escapes FQL control quotes', () => {
    expect(buildApplicationFilter({ name: "Acme's Tool" })).toContain("Acme\\'s Tool");
  });
});
