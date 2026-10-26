import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { DomainHandler, CallToolResult } from '../utils/types.js';
import { getClient } from '../utils/client.js';
import { logger } from '../utils/logger.js';
import { elicitSelection } from '../utils/elicitation.js';

function getTools(): Tool[] {
  return [
    {
      name: 'threatlocker_audit_search',
      description:
        'Search the ThreatLocker unified audit log. Filter by hostname, action (Permit/Deny), actionType and filePath. ' +
        'Set groupBy to get counts per username, processPath, parentProcess or filePath, sorted highest first ' +
        '(e.g. "top 10 denies on BEG-PC28": hostname + action Deny + groupBy processPath). ' +
        'Rows are trimmed to the useful fields. There is no reliable total: hasMore is true when a page comes back full.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          hostname: { type: 'string', description: 'Exact computer hostname, e.g. BEG-PC28' },
          action: { type: 'string', enum: ['Permit', 'Deny'], description: 'Only Permit or only Deny rows' },
          actionType: { type: 'string', description: 'e.g. execute, network, install, read, write' },
          filePath: { type: 'string', description: 'Full file path of the target; * wildcards allowed, e.g. *chrome.exe*' },
          searchText: { type: 'string', description: 'Deprecated alias for filePath' },
          groupBy: {
            type: 'string',
            enum: Object.keys(GROUP_BY_IDS),
            description: 'Return one row per group with a count, sorted by count (highest first)',
          },
          startDate: { type: 'string', description: 'Start date filter (ISO 8601). Defaults to 24h before endDate.' },
          endDate: { type: 'string', description: 'End date filter (ISO 8601). Defaults to now.' },
          pageNumber: { type: 'number', description: 'Page number (default 1)' },
          pageSize: { type: 'number', description: 'Page size (default 50, groups default 500)' },
          childOrganizations: { type: 'boolean', description: 'Include child organizations' },
        },
      },
    },
    {
      name: 'threatlocker_audit_get',
      description:
        'Get one audit log entry by eActionLogId, the string id on a threatlocker_audit_search row. ' +
        'Optional sourceTableId (integer 1-4) selects that row\'s source table. ' +
        'actionLogId is a deprecated alias and is stringified into eActionLogId. A numeric id is rejected before the request.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          eActionLogId: {
            type: 'string',
            description:
              'eActionLogId from a threatlocker_audit_search row. ActionLogGetByIdV2 requires this string; the numeric actionLogId on the same row is a different field and returns HTTP 500.',
          },
          sourceTableId: {
            type: 'integer',
            minimum: 1,
            maximum: 4,
            description:
              'Optional source table of that row. ActionLog = 1, DenyActionLog = 2, BaselineActionLog = 3, EventLogActionLog = 4.',
          },
          actionLogId: {
            type: 'string',
            deprecated: true,
            description:
              'Deprecated alias for eActionLogId. Stringified and sent as eActionLogId when it is not numeric. A numeric actionLogId is rejected; use eActionLogId from the search row.',
          },
        },
        // One id is required. Existing callers send actionLogId; new callers send eActionLogId.
        anyOf: [{ required: ['eActionLogId'] }, { required: ['actionLogId'] }],
      },
    },
    {
      name: 'threatlocker_audit_file_history',
      description:
        'Get audit history for a file on one computer. fullPath is required, plus hostname or computerId (a GUID). The Portal file-history API returns HTTP 417 when only fullPath is sent.',
      inputSchema: {
        type: 'object' as const,
        properties: {
          fullPath: { type: 'string', description: 'Full file path. Required.' },
          hostname: {
            type: 'string',
            description: 'Computer hostname. Required unless computerId is set.',
          },
          computerId: {
            type: 'string',
            description: 'Computer GUID (not a numeric id). Required unless hostname is set.',
          },
          sourceTableId: {
            type: 'number',
            description:
              'Optional source table. ActionLog = 1, DenyActionLog = 2, BaselineActionLog = 3, EventLogActionLog = 4.',
          },
          pageNumber: { type: 'number', description: 'Optional page number.' },
          pageSize: { type: 'number', description: 'Optional page size.' },
        },
        required: ['fullPath'],
        // `required` cannot express "hostname or computerId". anyOf requires
        // at least one identifier; both may be sent together.
        anyOf: [{ required: ['hostname'] }, { required: ['computerId'] }],
      },
    },
  ];
}

async function handleCall(toolName: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const client = await getClient();

  switch (toolName) {
    case 'threatlocker_audit_search': {
      // Elicitation: if no filter AND no date range, elicit date range
      const hasSearchText = !!(args.searchText || args.filePath || args.hostname);
      const hasDateRange = !!(args.startDate || args.endDate);

      let startDate = args.startDate as string | undefined;
      let endDate = args.endDate as string | undefined;

      if (!hasSearchText && !hasDateRange) {
        const dateChoice = await elicitSelection(
          'Select audit log date range:',
          ['Last 24h', 'Last 7d', 'Last 30d', 'Custom'],
          'Last 24h'
        );

        const now = new Date();
        if (dateChoice === 'Last 24h') {
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        } else if (dateChoice === 'Last 7d') {
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        } else if (dateChoice === 'Last 30d') {
          startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
          endDate = now.toISOString();
        }
        // For 'Custom', leave dates undefined to prompt user to specify
      }

      const groupBy = typeof args.groupBy === 'string' ? args.groupBy : undefined;
      if (groupBy && !(groupBy in GROUP_BY_IDS)) {
        return {
          content: [{ type: 'text', text: `Invalid groupBy "${groupBy}". Valid: ${Object.keys(GROUP_BY_IDS).join(', ')}` }],
          isError: true,
        };
      }
      const action = typeof args.action === 'string' ? args.action : undefined;
      if (action && !(action in ACTION_IDS)) {
        return {
          content: [{ type: 'text', text: `Invalid action "${action}". Valid: ${Object.keys(ACTION_IDS).join(', ')}` }],
          isError: true,
        };
      }

      const pageNumber = (args.pageNumber as number | undefined) ?? 1;
      const pageSize = (args.pageSize as number | undefined) ?? (groupBy ? 500 : 50);
      const end = toIsoSeconds(endDate ?? new Date());
      const body: Record<string, unknown> = {
        startDate: toIsoSeconds(startDate ?? new Date(new Date(end).getTime() - DAY_MS)),
        endDate: end,
        pageNumber,
        pageSize,
        paramsFieldsDto: [],
        showChildOrganizations: (args.childOrganizations as boolean | undefined) ?? false,
      };
      const filePath = nonEmptyString(args.filePath) ?? nonEmptyString(args.searchText);
      const hostname = nonEmptyString(args.hostname);
      const actionType = nonEmptyString(args.actionType);
      if (filePath) body.fullPath = filePath;
      if (hostname) body.hostname = hostname;
      if (actionType) body.actionType = actionType;
      if (action) body.actionId = ACTION_IDS[action];
      if (groupBy) body.groupBys = [GROUP_BY_IDS[groupBy]];

      logger.info('API call: ActionLogGetByParametersV2', body);
      // node-threatlocker's auditLog.search() cannot send actionId or groupBys, so post the same
      // request through its HTTP client.
      const { data } = await client.auditLog.http.requestWithMeta('/ActionLog/ActionLogGetByParametersV2', {
        method: 'POST',
        body,
        headers: { usenewsearch: 'true' },
      });
      const rows: Record<string, unknown>[] = Array.isArray(data) ? data : data?.items ?? [];
      const result = groupBy
        ? {
            groupBy,
            groups: rows
              .map(r => ({ count: r.groupByCount, ...slimRow(r, GROUP_FIELDS[groupBy]) }))
              .sort((a, b) => Number(b.count) - Number(a.count)),
          }
        : { items: rows.map(r => slimRow(r)) };
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ ...result, page: pageNumber, pageSize, returned: rows.length, hasMore: rows.length === pageSize }, null, 2),
        }],
      };
    }
    case 'threatlocker_audit_get': {
      // node-threatlocker@3.0.0 (WYREAI-386): get(id: string, { sourceTableId }?)
      // sends eActionLogId. The numeric actionLogId is V1 and HTTP 500s on V2.
      const resolved = auditGetArgs(args);
      if (!resolved.ok) {
        return {
          content: [{ type: 'text', text: resolved.message }],
          isError: true,
        };
      }
      const { eActionLogId, sourceTableId } = resolved;
      logger.info('API call: auditLog.get', { eActionLogId, sourceTableId });
      const auditEntry = await client.auditLog.get(eActionLogId, { sourceTableId });
      return { content: [{ type: 'text', text: JSON.stringify(auditEntry, null, 2) }] };
    }
    case 'threatlocker_audit_file_history': {
      // Object form from node-threatlocker#32 (WYREAI-386), published in
      // @wyre-ai/node-threatlocker@2.0.0. The string call
      // getFileHistory(fullPath) is the HTTP 417.
      const params = fileHistoryParams(args);
      if (!params) {
        return {
          content: [{ type: 'text', text: FILE_HISTORY_ARG_ERROR }],
          isError: true,
        };
      }
      logger.info('API call: auditLog.getFileHistory', params);
      const history = await client.auditLog.getFileHistory(params);
      return { content: [{ type: 'text', text: JSON.stringify(history, null, 2) }] };
    }
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${toolName}` }], isError: true };
  }
}

const AUDIT_GET_ARG_ERROR =
  'threatlocker_audit_get requires eActionLogId, the string id on a threatlocker_audit_search row. ' +
  'actionLogId is accepted as a deprecated alias and is stringified into eActionLogId. ' +
  'The numeric actionLogId is not that id; ActionLogGetByIdV2 returns HTTP 500 for it.';

const SOURCE_TABLE_ID_ERROR =
  'threatlocker_audit_get sourceTableId must be an integer 1 (ActionLog), 2 (DenyActionLog), 3 (BaselineActionLog), or 4 (EventLogActionLog).';

const AUDIT_GET_NUMERIC_ID_ERROR =
  'threatlocker_audit_get got a numeric action log id. actionLogId is a deprecated alias and is stringified, ' +
  'but ActionLogGetByIdV2 does not accept the numeric actionLogId (that request is HTTP 500). ' +
  'Pass eActionLogId, the string id on the threatlocker_audit_search row.';

/** Digit-only ids are V1 actionLogId values. The SDK rejects them before the request. */
const NUMERIC_ACTION_LOG_ID = /^-?\d+$/;

type AuditGetSuccess = {
  ok: true;
  eActionLogId: string;
  sourceTableId?: 1 | 2 | 3 | 4;
};

type AuditGetFailure = { ok: false; message: string };

/**
 * Prefers eActionLogId. actionLogId is the deprecated alias and is stringified
 * (a numeric actionLogId becomes its decimal string) so older callers still reach get().
 */
function auditGetArgs(args: Record<string, unknown>): AuditGetSuccess | AuditGetFailure {
  const eActionLogId = nonEmptyString(args.eActionLogId) ?? stringifiedId(args.actionLogId);
  if (!eActionLogId) return { ok: false, message: AUDIT_GET_ARG_ERROR };
  if (NUMERIC_ACTION_LOG_ID.test(eActionLogId)) return { ok: false, message: AUDIT_GET_NUMERIC_ID_ERROR };

  if (args.sourceTableId == null) return { ok: true, eActionLogId };
  if (!isSourceTableId(args.sourceTableId)) return { ok: false, message: SOURCE_TABLE_ID_ERROR };
  return { ok: true, eActionLogId, sourceTableId: args.sourceTableId };
}

function stringifiedId(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return nonEmptyString(value);
}

function isSourceTableId(value: unknown): value is 1 | 2 | 3 | 4 {
  return value === 1 || value === 2 || value === 3 || value === 4;
}

const FILE_HISTORY_ARG_ERROR =
  'threatlocker_audit_file_history requires fullPath and either hostname or computerId. ' +
  'ActionLogGetAllForFileHistoryV2 returns HTTP 417 "Missing Parameters. Unable to load details." ' +
  'when only fullPath is sent.';

const DAY_MS = 24 * 60 * 60 * 1000;

// actionId values seen in the Portal API: 1 Permit, 3 Deny.
const ACTION_IDS: Record<string, number> = { Permit: 1, Deny: 3 };

// groupBys ids, confirmed against the live API (each grouping's counts sum to the ungrouped total).
const GROUP_BY_IDS: Record<string, number> = { username: 1, processPath: 2, parentProcess: 4, filePath: 10 };

// For a grouped row, the fields that are actually constant across the group.
const GROUP_FIELDS: Record<string, string[]> = {
  username: ['username'],
  processPath: ['processPath'],
  parentProcess: ['createdByProcess'],
  filePath: ['fullPath', 'sha256Hash'],
};

const ROW_FIELDS = [
  'dateTime', 'hostname', 'username', 'action', 'actionType', 'fullPath', 'processPath',
  'createdByProcess', 'policyName', 'applicationName', 'sha256Hash', 'destinationIPAddress',
  'destinationPort', 'eActionLogId', 'computerId', 'organizationId',
];

function slimRow(row: Record<string, unknown>, fields: string[] = ROW_FIELDS): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (row[f] !== null && row[f] !== undefined && row[f] !== '') out[f] = row[f];
  }
  return out;
}

function toIsoSeconds(value: string | Date): string {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`Invalid audit log date "${String(value)}". Use an ISO 8601 timestamp.`);
  }
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function nonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Builds the object `auditLog.getFileHistory` expects.
 * Returns null when fullPath is blank or both computer identifiers are missing.
 */
function fileHistoryParams(args: Record<string, unknown>): Record<string, unknown> | null {
  const fullPath = nonEmptyString(args.fullPath);
  const hostname = nonEmptyString(args.hostname);
  const computerId = nonEmptyString(args.computerId);
  if (!fullPath || (!hostname && !computerId)) return null;

  const params: Record<string, unknown> = { fullPath };
  if (hostname) params.hostname = hostname;
  if (computerId) params.computerId = computerId;
  if (typeof args.sourceTableId === 'number') params.sourceTableId = args.sourceTableId;
  if (typeof args.pageNumber === 'number') params.pageNumber = args.pageNumber;
  if (typeof args.pageSize === 'number') params.pageSize = args.pageSize;
  return params;
}

export const auditLogHandler: DomainHandler = { getTools, handleCall };