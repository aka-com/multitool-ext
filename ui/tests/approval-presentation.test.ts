import assert from 'node:assert/strict';
import test from 'node:test';
import {
  approvalActionLabel,
  approvalAgentName,
  approvalPermissionSummary,
  approvalToolName,
  approvalWantsLine,
} from '../src/approval-presentation';
import type { Approval } from '../src/types';

function approval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: 'approval-1',
    connection_id: 'github-1',
    connection: 'github',
    type: 'api',
    unit: 'request',
    target: 'https://api.github.com',
    agent: 'claude-code',
    summary: 'POST /repos/aka/aka/issues',
    detail: '{"title":"Flaky test"}',
    credential_names: [],
    method: 'POST',
    path: '/repos/aka/aka/issues',
    waiting: 1,
    requested_at: '2026-08-08T12:00:00Z',
    expires_at: '2026-08-08T12:05:00Z',
    window_secs: 900,
    ...overrides,
  };
}

test('approval presentation turns structured GitHub traffic into decision copy', () => {
  const request = approval();
  assert.equal(approvalAgentName(request.agent), 'Claude Code');
  assert.equal(approvalToolName(request.connection), 'GitHub');
  assert.equal(approvalActionLabel(request), 'Create an issue in aka/aka');
  assert.equal(
    approvalPermissionSummary(request),
    'Approving lets this agent post to GitHub until the window expires.',
  );
});

test('legacy canonical request summaries receive the same decision copy', () => {
  const request = approval({ method: undefined, path: undefined });
  assert.equal(approvalActionLabel(request), 'Create an issue in aka/aka');
  assert.equal(
    approvalPermissionSummary(request),
    'Approving lets this agent post to GitHub until the window expires.',
  );
});

test('the banner ask names agent, action, and tool in one line', () => {
  assert.equal(
    approvalWantsLine(approval()),
    'Claude Code wants to create an issue in aka/aka on GitHub',
  );
  assert.equal(
    approvalWantsLine(approval({
      connection: 'prod-db', type: 'pg', unit: 'session', method: null, path: null,
    })),
    'Claude Code wants to open a database session on prod-db',
  );
  // Opaque leading tokens (an unknown HTTP method, agent-authored summaries)
  // keep their capitals: only our own sentence case is folded into the clause.
  assert.equal(
    approvalWantsLine(approval({ method: 'HEAD', path: '/status' })),
    'Claude Code wants to HEAD /status on GitHub',
  );
});

test('approval presentation keeps durable and session decisions honest', () => {
  assert.equal(
    approvalPermissionSummary(approval({
      connection: 'prod-db', type: 'pg', unit: 'session', method: null, path: null,
    })),
    'Approving lets this agent use prod-db for this database session.',
  );
  assert.equal(
    approvalPermissionSummary(approval({
      connection: 'prod-ssh', type: 'ssh', unit: 'host_key', method: null, path: null,
    })),
    'Approving trusts and pins this host key for prod-ssh.',
  );
});
