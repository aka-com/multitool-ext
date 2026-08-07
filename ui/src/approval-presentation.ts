import type { Approval } from './types';

const KNOWN_NAMES: Readonly<Record<string, string>> = {
  github: 'GitHub',
  postgres: 'PostgreSQL',
  postgresql: 'PostgreSQL',
  ssh: 'SSH',
};

/** A connection name is user-controlled, so only normalize brands whose
 * spelling Multitool actually knows. Everything else stays exactly as named. */
export function approvalToolName(connection: string): string {
  return KNOWN_NAMES[connection.trim().toLowerCase()] ?? connection;
}

/** Agent names are self-reported identifiers. Make their separators readable
 * without pretending they are verified identities. */
export function approvalAgentName(agent: string): string {
  if (agent === 'endpoint') return 'Direct Endpoint Client';
  return agent
    .trim()
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ') || 'Unknown Agent';
}

/** Compatibility for brokers that predate structured operation fields. Only
 * accept the canonical all-caps-method plus absolute-path summary shape; all
 * other agent-authored prose remains opaque. */
function approvalOperation(approval: Approval): { method?: string; path?: string } {
  if (approval.method || approval.path) {
    return { method: approval.method?.toUpperCase(), path: approval.path ?? undefined };
  }
  const legacy = approval.summary.match(/^([A-Z]{3,12})\s+(\/\S+)$/);
  return legacy ? { method: legacy[1], path: legacy[2] } : {};
}

/** The decision fact in Multitool's voice. Prefer structured fields over the
 * agent-authored summary; the narrow GitHub issue shape is the one operation
 * for which the broker gives enough structure to name the result precisely. */
export function approvalActionLabel(approval: Approval): string {
  if (approval.unit === 'host_key') return 'Trust an SSH host key';
  if (approval.unit === 'session' || approval.type === 'pg') {
    return 'Open a database session';
  }
  if (approval.unit === 'login' || approval.type === 'ssh') return 'Sign in over SSH';
  if (approval.unit === 'tool') return `Call ${approval.summary}`;

  const { method, path } = approvalOperation(approval);
  const issue = method === 'POST'
    ? path?.match(/^\/repos\/([^/]+)\/([^/]+)\/issues\/?$/)
    : null;
  if (issue) return `Create an issue in ${issue[1]}/${issue[2]}`;
  if (method && path) {
    const verb = method === 'GET' ? 'Read'
      : method === 'POST' ? 'Post to'
      : method === 'PUT' || method === 'PATCH' ? 'Update'
      : method === 'DELETE' ? 'Delete'
      : method;
    return `${verb} ${path}`;
  }
  return approval.summary;
}

/** The waiting-request banner's one-line ask when a single approval holds
 * the queue: agent, action, and tool in Multitool's voice, so the band can
 * name the decision instead of tallying it. The action label keeps its
 * leading capital when it starts an opaque token (an HTTP method, an
 * agent-authored summary) rather than a sentence of ours. */
export function approvalWantsLine(approval: Approval): string {
  const action = approvalActionLabel(approval);
  const clause = /^[A-Z][a-z]/.test(action)
    ? action.charAt(0).toLowerCase() + action.slice(1)
    : action;
  return `${approvalAgentName(approval.agent)} wants to ${clause} on ${
    approvalToolName(approval.connection)}`;
}

/** Short consequence under the question. Host-key approval is durable rather
 * than windowed, so it gets its own honest sentence. */
export function approvalPermissionSummary(approval: Approval): string {
  const tool = approvalToolName(approval.connection);
  if (approval.unit === 'host_key') {
    return `Approving trusts and pins this host key for ${tool}.`;
  }
  if (approval.unit === 'session' || approval.type === 'pg') {
    return `Approving lets this agent use ${tool} for this database session.`;
  }
  if (approval.unit === 'login' || approval.type === 'ssh') {
    return `Approving lets this agent sign in to ${tool}.`;
  }
  if (approval.unit === 'tool') {
    return `Approving lets this agent call ${tool} until the window expires.`;
  }
  const verb = approvalOperation(approval).method === 'POST' ? 'post to' : 'use';
  return `Approving lets this agent ${verb} ${tool} until the window expires.`;
}
