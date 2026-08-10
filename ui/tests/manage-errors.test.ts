// Pins the web translation of the broker's ManageError JSON to the same
// {kind, code, field, message} contract the desktop's Rust translation
// (FormError::from_manage) produces. If an arm changes on either side, this
// is the test that says so.

import assert from 'node:assert/strict';
import test from 'node:test';

import { inlineFormError } from '../src/form-errors';
import { manageErrorContext, manageFormError } from '../src/manage-errors';
import type { ManageErrorContext } from '../src/manage-errors';
import type { ConnectionInput } from '../src/types';

const SECRET: ManageErrorContext = {
  form: 'secret', connectionKind: '', includesNewSecret: false,
};
const API_WITH_NEW_SECRET: ManageErrorContext = {
  form: 'connection', connectionKind: 'api', includesNewSecret: true,
};
const PG: ManageErrorContext = {
  form: 'connection', connectionKind: 'pg', includesNewSecret: false,
};

test('a duplicate credential name lands on the form-appropriate field', () => {
  const payload = { code: 'secret_name_taken', name: 'GITHUB_TOKEN' };
  assert.deepEqual(manageFormError(payload, SECRET), {
    kind: 'conflict',
    code: 'secret_name_taken',
    field: 'name',
    message: 'That credential name is already in use',
  });
  // Inside a connection form the duplicate is the new-credential input.
  assert.equal(manageFormError(payload, API_WITH_NEW_SECRET)?.field, 'newSecretName');
});

test('field-routed errors satisfy the inline form-error contract', () => {
  const error = manageFormError({ code: 'connection_name_taken', name: 'x' }, PG);
  assert.deepEqual(inlineFormError(error), {
    field: 'name',
    message: 'That tool name is already in use',
  });
});

test('connection field names translate from wire values to input ids', () => {
  const at = (kind: string, wireField: string) =>
    manageFormError(
      { code: 'invalid_connection_field', field: wireField, message: 'nope' },
      { form: 'connection', connectionKind: kind, includesNewSecret: false },
    )?.field;
  // An API tool renders one origin input covering scheme and host.
  assert.equal(at('api', 'host'), 'origin');
  assert.equal(at('pg', 'host'), 'host');
  assert.equal(at('pg', 'scheme'), 'origin');
  assert.equal(at('pg', 'database'), 'dbname');
  assert.equal(at('ssh', 'host_key_fingerprint'), 'hostKeyFingerprint');
});

test('renamed desktop UI codes are preserved', () => {
  // The desktop renames these wire tags for the UI; app.tsx matches on the
  // renamed codes, so the web translation must emit them identically.
  assert.equal(manageFormError({ code: 'template', message: 'x' }, PG)?.code, 'invalid_template');
  assert.equal(
    manageFormError({ code: 'unknown_template_ref', name: 'x' }, PG)?.code,
    'unknown_template_credential',
  );
  assert.equal(
    manageFormError({ code: 'wrong_secret_count', kind: 'pg' }, PG)?.code,
    'wrong_credential_count',
  );
  // Both change-conflict variants collapse to the one code app.tsx refreshes on.
  assert.equal(
    manageFormError({ code: 'approval_connection_changed' }, PG)?.code,
    'connection_changed',
  );
});

test('an invalid connection config lands where the typed credential went', () => {
  const payload = { code: 'invalid_connection_config', message: 'bad template' };
  assert.equal(manageFormError(payload, API_WITH_NEW_SECRET)?.field, 'template');
  assert.equal(
    manageFormError(payload, { ...PG, includesNewSecret: true })?.field,
    'newSecretValue',
  );
  assert.equal(manageFormError(payload, PG)?.field, undefined);
});

test('unknown codes keep the broker message as detail instead of vanishing', () => {
  const error = manageFormError({ code: 'internal', message: 'disk full' }, SECRET);
  assert.equal(error?.code, 'save_failed');
  assert.equal(error?.message, 'Couldn’t save your changes');
  assert.equal(error?.detail, 'disk full');
  // Not a manage error at all: the caller keeps the original payload.
  assert.equal(manageFormError({ reason: 'no_session' }, SECRET), null);
});

test('the context derives from the command and its input', () => {
  const input = {
    name: 'db', type: 'pg', new_secret_value: 'hunter2',
  } as unknown as ConnectionInput;
  assert.deepEqual(manageErrorContext('add_connection', { input }), {
    form: 'connection', connectionKind: 'pg', includesNewSecret: true,
  });
  assert.deepEqual(manageErrorContext('add_secret', { name: 'x', value: 'y' }), {
    form: 'secret', connectionKind: '', includesNewSecret: false,
  });
});
