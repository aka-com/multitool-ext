import test from 'node:test';
import assert from 'node:assert/strict';

import {
  COMMANDS,
  brokerCommands,
  commandHost,
  nativeOnlyReason,
  requestFor,
  resolvePath,
} from '../src/commands';
import type { CommandName } from '../src/types';

test('every command is classified, and every native one says why', () => {
  const names = Object.keys(COMMANDS) as CommandName[];
  assert.ok(names.length > 50, 'the table should cover the whole command map');
  for (const name of names) {
    const spec = COMMANDS[name];
    if (spec.host === 'native') {
      // A bare "not supported" is not a reason. Someone reading the web app
      // and wondering where a control went needs the actual answer.
      assert.ok(spec.reason.length > 8, `${name} needs a reason`);
      assert.equal(nativeOnlyReason(name), spec.reason);
    } else {
      assert.match(spec.path, /^\/v1\/manage\//, `${name} must address the manage plane`);
      assert.equal(nativeOnlyReason(name), null);
    }
  }
});

test('nothing that touches this machine is offered over HTTP', () => {
  // The list the split exists for. Each of these needs the OS: the
  // clipboard that keeps a value out of the page, Touch ID, ~/.aws,
  // ~/.ssh, login items, native notifications.
  for (const name of [
    'copy_secret', 'copy_secret_totp', 'copy_endpoint_text', 'copy_key', 'copy_agent_setup',
    'get_lock_state', 'lock_app', 'unlock_app', 'start_embedded_unlock',
    'get_autostart', 'set_autostart',
    'get_notification_settings', 'set_notification_settings',
    'list_aws_profiles', 'inspect_ssh_import', 'check_known_hosts',
    'get_local_username', 'open_url',
    'capture_screen_region', 'open_screen_recording_settings',
  ] as CommandName[]) {
    assert.equal(commandHost(name), 'native', `${name} must stay native`);
  }
});

test('the surfaces the web app is for are all reachable', () => {
  for (const name of [
    'list_connections', 'add_connection', 'delete_connection',
    'list_secrets', 'add_secret', 'reveal_secret',
    'get_settings', 'list_activity', 'clear_activity',
    'list_approvals', 'respond_approval', 'list_requests',
    'list_elicitations', 'respond_elicitation',
    'get_identity', 'list_sessions',
  ] as CommandName[]) {
    assert.equal(commandHost(name), 'broker', `${name} should work in a browser`);
  }
  assert.ok(brokerCommands().length > 30);
});

test('path parameters are filled and encoded', () => {
  assert.equal(
    resolvePath('/v1/manage/secrets/:id/reveal', { id: 'abc-123' }),
    '/v1/manage/secrets/abc-123/reveal',
  );
  // An argument must never be able to add path segments of its own.
  assert.equal(
    resolvePath('/v1/manage/secrets/:id', { id: '../../auth/tokens' }),
    '/v1/manage/secrets/..%2F..%2Fauth%2Ftokens',
  );
  assert.throws(() => resolvePath('/v1/manage/secrets/:id', {}), /id argument is required/);
});

test('a request carries its path values in the path and nothing else', () => {
  const request = requestFor('reveal_secret', { id: 'sec-1' });
  assert.equal(request.method, 'POST');
  assert.equal(request.path, '/v1/manage/secrets/sec-1/reveal');
  // `id` built the path; it must not also be sent as a body field.
  assert.deepEqual(request.body, {});
  assert.equal(request.unwrap?.({ value: 'hunter2' }), 'hunter2');
});

test('an edit sends only the fields it was given, in the broker\'s field names', () => {
  const request = requestFor('edit_secret', { id: 'sec-1', newName: 'renamed' });
  assert.equal(request.path, '/v1/manage/secrets/sec-1');
  assert.equal(request.method, 'PATCH');
  // The webview passes camelCase; the broker's `SecretEditBody` deserializes
  // snake_case, so the body must be translated or the edit silently no-ops.
  // Absent fields stay absent: sending `newValue: undefined` as null would
  // read to the broker as "clear the value".
  assert.deepEqual(request.body, { new_name: 'renamed' });
});

test('mcp_status sends its options as the body, not wrapped in a key', () => {
  const request = requestFor('mcp_status', { id: 'c1', options: { whoami_tool: 'me' } });
  assert.deepEqual(request.body, { whoami_tool: 'me' });
  // Defaults when none are given.
  assert.deepEqual(requestFor('mcp_status', { id: 'c1' }).body, {});
});

test('loopback-catcher sign-in flows are not offered over HTTP', () => {
  // OAuth connect/reconnect and MCP sign-in all redirect to a 127.0.0.1
  // catcher only the desktop shell runs, so a browser cannot complete them.
  for (const name of ['oauth_connect', 'oauth_reconnect', 'start_mcp_auth'] as CommandName[]) {
    assert.equal(commandHost(name), 'native', `${name} needs a loopback catcher`);
  }
});

test('a safe method carries its arguments as a query, never a body', () => {
  const request = requestFor('list_activity', { limit: 50, before: 12 });
  assert.equal(request.method, 'GET');
  assert.equal(request.path, '/v1/manage/activity/page?limit=50&before=12');
  assert.equal(request.body, undefined);

  // An absent optional is omitted rather than sent as the string "null".
  const first = requestFor('list_activity', { limit: 50, before: null });
  assert.equal(first.path, '/v1/manage/activity/page?limit=50');
});

test('a native command refuses before it can reach the network', () => {
  assert.throws(
    () => requestFor('lock_app', undefined),
    /only available in the desktop app/,
  );
});

test('boolean-returning routes are unwrapped from their envelope', () => {
  assert.equal(
    requestFor('respond_approval', { id: 'a', decision: 'approve_window' }).unwrap?.({ answered: true }),
    true,
  );
  assert.equal(
    requestFor('set_tool_access', { connectionId: 'c', enabled: true }).unwrap?.({ changed: false }),
    false,
  );
  assert.equal(
    requestFor('revoke_endpoint', { endpointId: 'e' }).unwrap?.({ revoked: true }),
    true,
  );
});
