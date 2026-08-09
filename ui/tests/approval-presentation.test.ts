import assert from 'node:assert/strict';
import test from 'node:test';
import {
  agentNaming,
  approvalActionLabel,
  approvalPermissionSummary,
  approvalToolName,
  approvalWantsLine,
  approvalWindowLabel,
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
    'An agent wants to create an issue in aka/aka on GitHub',
  );
  assert.equal(
    approvalWantsLine(approval({
      connection: 'prod-db', type: 'pg', unit: 'session', method: null, path: null,
    })),
    'An agent wants to open a database session on prod-db',
  );
  // Opaque leading tokens (an unknown HTTP method, agent-authored summaries)
  // keep their capitals: only our own sentence case is folded into the clause.
  assert.equal(
    approvalWantsLine(approval({ method: 'HEAD', path: '/status' })),
    'An agent wants to HEAD /status on GitHub',
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

test('only a verified program is named', () => {
  assert.deepEqual(
    agentNaming({
      kind: 'verified',
      program: 'Claude Desktop',
      signer: 'Anthropic, PBC',
      team_id: 'Q6L2SF6YDW',
      identifier: 'com.anthropic.claude-desktop',
    }),
    { lead: 'Claude Desktop', mid: 'Claude Desktop', program: 'Claude Desktop', verified: true },
  );

  // A signed CLI binary has no bundle to take a name from. The signer is an
  // organisation, so it never sits where a program name would, and a name is
  // never derived from the identifier.
  const signerOnly = agentNaming({
    kind: 'verified_signer',
    signer: 'Anthropic, PBC',
    team_id: 'Q6L2SF6YDW',
    identifier: 'com.anthropic.claude-code',
  });
  assert.equal(signerOnly.lead, 'An agent from Anthropic, PBC');
  assert.equal(signerOnly.mid, 'an agent from Anthropic, PBC');
  assert.equal(signerOnly.program, undefined);

  assert.deepEqual(
    agentNaming({ kind: 'unattested' }),
    { lead: 'An agent', mid: 'this agent', verified: false },
  );
  // An older broker sends no identity at all.
  assert.equal(agentNaming(undefined).lead, 'An agent');
});

test('a self-reported label never reaches the rendered name', () => {
  // The whole point: whatever the caller calls itself, an unattested caller is
  // "an agent". A label crafted to look verified buys nothing, because there
  // is no slot for it to land in.
  for (const label of ['claude-code', 'Claude Code ✓ verified by Anthropic', '']) {
    const naming = agentNaming({ kind: 'unattested' }, label);
    assert.equal(naming.lead, 'An agent');
    assert.equal(naming.verified, false);
  }
  assert.equal(
    approvalWantsLine(approval({ agent: 'Claude Code ✓ verified' })),
    'An agent wants to create an issue in aka/aka on GitHub',
  );
});

test('the broker-set endpoint label is still named, because it is not a claim', () => {
  // `endpoint` is set by the broker on its own direct-endpoint plane, so it
  // reports the transport rather than repeating something a caller chose.
  const naming = agentNaming({ kind: 'unattested' }, 'endpoint');
  assert.equal(naming.lead, 'A direct endpoint client');
  assert.equal(naming.verified, false);
  // A verified identity still wins: the transport is the fallback, not an
  // override.
  assert.equal(
    agentNaming(
      {
        kind: 'verified',
        program: 'Claude Desktop',
        signer: 'Anthropic, PBC',
        team_id: 'T',
        identifier: 'i',
      },
      'endpoint',
    ).lead,
    'Claude Desktop',
  );
});

test('the approve-for-a-while button promises only what it can deliver', () => {
  assert.equal(
    approvalWindowLabel(approval({ run_scoped: true }), 15),
    'Approve this session for 15 min',
  );
  assert.equal(approvalWindowLabel(approval({ run_scoped: false }), 15), 'Approve for 15 min');
  // An older broker omits the flag; the weaker wording is the safe default.
  assert.equal(approvalWindowLabel(approval(), 15), 'Approve for 15 min');
});
