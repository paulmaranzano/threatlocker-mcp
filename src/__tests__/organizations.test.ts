import { describe, it, expect, vi, beforeEach } from 'vitest';
import { organizationsHandler } from '../domains/organizations.js';
import { getClient } from '../utils/client.js';

vi.mock('../utils/client.js', () => ({
  getClient: vi.fn(),
}));

function mockClient(overrides: Record<string, unknown>) {
  const client = { organizations: overrides };
  (getClient as ReturnType<typeof vi.fn>).mockResolvedValue(client);
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('organizationsHandler.getTools', () => {
  it('exposes exactly the two organization tools (get_auth_key removed)', () => {
    const names = organizationsHandler.getTools().map((t) => t.name);
    expect(names).toEqual([
      'threatlocker_organizations_list_children',
      'threatlocker_organizations_for_move_computers',
    ]);
  });
});

describe('threatlocker_organizations_list_children', () => {
  it('forwards filters to organizations.listChildren and returns the mapped response', async () => {
    const listChildren = vi.fn().mockResolvedValue({ organizations: [{ id: 'org-child-1' }] });
    mockClient({ listChildren });

    const result = await organizationsHandler.handleCall('threatlocker_organizations_list_children', {
      searchText: 'Acme',
      pageNumber: 1,
      pageSize: 50,
    });

    expect(listChildren).toHaveBeenCalledWith({
      searchText: 'Acme',
      pageNumber: 1,
      pageSize: 50,
    });
    expect(result.content[0].text).toBe(
      JSON.stringify({ organizations: [{ id: 'org-child-1' }] }, null, 2),
    );
  });
});

describe('threatlocker_organizations_for_move_computers', () => {
  it('calls listForMoveComputers (the method that actually exists on the SDK) with no arguments', async () => {
    const listForMoveComputers = vi.fn().mockResolvedValue([{ id: 'org-1' }, { id: 'org-2' }]);
    mockClient({ listForMoveComputers });

    const result = await organizationsHandler.handleCall(
      'threatlocker_organizations_for_move_computers',
      {},
    );

    expect(listForMoveComputers).toHaveBeenCalledWith();
    expect(result.content[0].text).toBe(
      JSON.stringify([{ id: 'org-1' }, { id: 'org-2' }], null, 2),
    );
  });
});

describe('unknown tool', () => {
  it('returns an isError result and does not touch the client', async () => {
    const listChildren = vi.fn();
    mockClient({ listChildren });

    const result = await organizationsHandler.handleCall('threatlocker_organizations_bogus', {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe('Unknown tool: threatlocker_organizations_bogus');
    expect(listChildren).not.toHaveBeenCalled();
  });
});
