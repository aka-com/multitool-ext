import type { AgentIdentity, Approval } from './types';

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

/**
 * How to refer to whoever is calling.
 *
 * Multitool only prints a name it can vouch for. A self-reported label is
 * whatever the caller typed, so rendering it puts attacker-chosen text into
 * the sentence a user reads while deciding whether to trust that caller —
 * `agent` is therefore never displayed, only recorded. When the OS proved
 * nothing, the app says "an agent", which is both honest and enough: the user
 * knows what they just asked for.
 *
 * `lead` starts a sentence, `mid` sits inside one. That is the only
 * grammatical wrinkle the three states introduce, and keeping the two forms
 * here is what stops each call site from inventing its own.
 */
export interface AgentNaming {
  /** Sentence-initial: "An agent wants to…". */
  lead: string;
  /** Mid-sentence: "Allow this agent to…". */
  mid: string;
  /** The verified program name, when there is one, for a name + check mark. */
  program?: string;
  /** The verified signing organisation, when the program has no name. */
  signer?: string;
  verified: boolean;
}

/** The one label that is not a self-reported name: the broker sets it on its
 * own direct-endpoint plane, so it is a fact about the transport rather than a
 * claim by the caller, and stays worth showing. */
const ENDPOINT_LABEL = 'endpoint';

export function agentNaming(
  identity?: AgentIdentity | null,
  agent?: string | null,
): AgentNaming {
  if (identity?.kind !== 'verified' && identity?.kind !== 'verified_signer'
      && agent === ENDPOINT_LABEL) {
    return {
      lead: 'A direct endpoint client',
      mid: 'this direct endpoint client',
      verified: false,
    };
  }
  switch (identity?.kind) {
    case 'verified':
      return {
        lead: identity.program,
        mid: identity.program,
        program: identity.program,
        verified: true,
      };
    case 'verified_signer':
      // The signer is an organisation, not the program, so it is never put
      // where a program name would go — deriving "Claude Code" from
      // `com.anthropic.claude-code` would be exactly the guess this design
      // exists to avoid.
      return {
        lead: `An agent from ${identity.signer}`,
        mid: `an agent from ${identity.signer}`,
        signer: identity.signer,
        verified: true,
      };
    default:
      return { lead: 'An agent', mid: 'this agent', verified: false };
  }
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
  return `${agentNaming(approval.identity, approval.agent).lead} wants to ${clause} on ${
    approvalToolName(approval.connection)}`;
}

/** What the approve-for-a-while button promises. A window on an attested
 * caller binds to that one run; on an unattested one it covers whatever next
 * sends the same label, and the button must not imply otherwise. */
export function approvalWindowLabel(approval: Approval, minutes: number): string {
  return approval.run_scoped
    ? `Approve this session for ${minutes} min`
    : `Approve for ${minutes} min`;
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
