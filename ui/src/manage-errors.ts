// Structured broker form errors for the web app.
//
// The desktop shell translates the broker's `ManageError` into
// `{kind, code, field, message, detail}` in Rust (`FormError::from_manage`
// in src-tauri/src/commands.rs) so its forms can mark the offending input
// instead of toasting. The web app receives the broker's JSON directly and
// had no equivalent — a duplicate credential name was a global toast, not a
// marked field. This module is that translation, ported arm for arm: same
// UI codes, same field ids, same copy. If an arm changes on one side it
// must change on the other; `ui/tests/manage-errors.test.ts` pins the
// mapping.
//
// Input is the wire enum (`#[serde(tag = "code", rename_all =
// "snake_case")]`), so `payload.code` is the variant and the variant's
// fields ride alongside. The emitted `code` is the desktop's *UI* code,
// which differs from the wire tag where the desktop renamed one
// (`template` → `invalid_template`, and so on) — app.tsx matches on the UI
// codes, so the web must speak them too.

import type { StructuredFormError } from './form-errors';
import type { CommandArgs, CommandName, ConnectionInput } from './types';

/** What the desktop calls `FormContext`: which form the failed command
 * belongs to, deciding which input a shared code lands on. */
export interface ManageErrorContext {
  form: 'secret' | 'connection';
  /** The connection type ('api', 'pg', …); empty for a secret form. */
  connectionKind: string;
  /** Whether the request carried a newly typed credential value. */
  includesNewSecret: boolean;
}

/** The context a command's failure is translated under. Mirrors which
 * desktop commands pass `FormContext::Connection` vs `FormContext::Secret`;
 * everything else takes the secret default, which only decides the field a
 * shared *credential-name* code lands on. */
export function manageErrorContext<K extends CommandName>(
  command: K,
  args: CommandArgs<K> | undefined,
): ManageErrorContext {
  if (
    command === 'add_connection'
    || command === 'edit_connection'
    || command === 'test_connection_draft'
  ) {
    const input = (args as { input?: ConnectionInput } | undefined)?.input;
    return {
      form: 'connection',
      connectionKind: input?.type ?? '',
      includesNewSecret: input?.new_secret_value != null
        || Boolean(input?.new_secrets?.length),
    };
  }
  return { form: 'secret', connectionKind: '', includesNewSecret: false };
}

/** `ConnectionField` wire values → the form input ids the sheets render.
 * `scheme` reports as the combined origin field; on an API tool `host`
 * does too, because that form has one origin input covering both. */
const CONNECTION_FIELD_IDS: Record<string, string> = {
  host: 'host',
  scheme: 'origin',
  port: 'port',
  database: 'dbname',
  user: 'user',
  url: 'url',
  template: 'template',
  host_key_fingerprint: 'hostKeyFingerprint',
};

function text(payload: Record<string, unknown>, key: string): string {
  const value = payload[key];
  return typeof value === 'string' ? value : '';
}

/**
 * The broker's `ManageError` JSON as a field-routed form error, or null
 * when the payload is not a manage error (no `code`). Unknown codes fall
 * into the same "couldn't save" bucket the desktop uses, keeping the
 * broker's human-readable message as the detail.
 */
export function manageFormError(
  payload: Record<string, unknown>,
  context: ManageErrorContext,
): StructuredFormError | null {
  const wire = typeof payload.code === 'string' ? payload.code : null;
  if (!wire) return null;
  const shaped = (
    kind: string,
    code: string,
    field: string | null,
    message: string,
    detail?: string,
  ): StructuredFormError => ({
    kind,
    code,
    ...(field ? { field } : {}),
    message,
    ...(detail ? { detail } : {}),
  });
  // A credential name belongs to the secret form's own field, or to the
  // new-credential input riding inside a connection form.
  const secretNameField = context.form === 'secret' ? 'name' : 'newSecretName';

  switch (wire) {
    case 'secret_name_taken':
      return shaped('conflict', wire, secretNameField, 'That credential name is already in use');
    case 'connection_name_taken':
      return shaped('conflict', wire, 'name', 'That tool name is already in use');
    case 'connection_target_taken':
      return shaped(
        'conflict', wire, 'name',
        `An equivalent target is already saved as ${text(payload, 'name')}`,
      );
    case 'invalid_secret_name':
      return shaped(
        'validation', wire, secretNameField,
        'Use letters, numbers, and underscores; start with a letter or underscore',
      );
    case 'invalid_connection_name':
      return shaped(
        'validation', wire, 'name',
        'Use 1–64 letters, numbers, spaces, or endpoint punctuation; '
        + 'start with a letter or number and don’t end with a space',
      );
    // The password form's two structured refusals; the desktop reaches
    // these through its own pre-validation, the web through the broker.
    case 'invalid_site':
      return shaped('validation', wire, 'site', text(payload, 'message') || 'Enter a website address');
    case 'invalid_totp_seed':
      return shaped(
        'validation', wire, 'totp',
        text(payload, 'message') || 'That doesn’t look like a 2FA secret or otpauth:// link',
      );
    case 'not_a_password':
      return shaped('validation', wire, null, 'Only passwords carry sign-in fields');
    case 'template':
      return shaped(
        'validation', 'invalid_template', 'template',
        `Invalid template: ${text(payload, 'message')}`,
      );
    case 'unknown_template_ref':
      return shaped(
        'validation', 'unknown_template_credential', 'template',
        `${text(payload, 'name')} is not a saved credential`,
      );
    case 'wrong_secret_count':
      return shaped(
        'validation', 'wrong_credential_count', 'secret',
        `${text(payload, 'kind')} tools require exactly one saved credential`,
      );
    case 'secret_not_found':
      return context.form === 'secret'
        ? shaped('conflict', wire, null, 'This credential was removed elsewhere')
        : shaped('validation', wire, 'secret', 'This credential no longer exists; choose another');
    case 'invalid_connection_field': {
      const wireField = text(payload, 'field');
      const field = wireField === 'host' && context.connectionKind === 'api'
        ? 'origin'
        : CONNECTION_FIELD_IDS[wireField] ?? null;
      return shaped('validation', wire, field, text(payload, 'message'));
    }
    case 'invalid_connection_config': {
      const field = !context.includesNewSecret ? null
        : context.connectionKind === 'api' ? 'template'
        : 'newSecretValue';
      return shaped('validation', 'invalid_connection', field, text(payload, 'message'));
    }
    case 'kind_change':
      return shaped(
        'validation', 'connection_kind_fixed', null,
        'Tool type cannot be changed after creation',
      );
    case 'connection_not_found':
      return shaped('conflict', wire, null, 'This tool was removed elsewhere');
    case 'endpoint_requires_wiring':
      return shaped(
        'conflict', wire, null,
        'Enable this tool for agents before issuing a direct endpoint',
      );
    case 'endpoint_limit':
      return shaped(
        'conflict', wire, null,
        `This broker already has its limit of ${Number(payload.max) || 0} direct endpoints`,
        'Revoke an existing endpoint, then try again.',
      );
    case 'approval_connection_changed':
      return shaped(
        'conflict', 'connection_changed', null,
        'The tool changed while you were confirming. Review it and save again.',
      );
    case 'connection_changed':
      return shaped(
        'conflict', wire, null,
        'This tool changed elsewhere. Review the latest settings and try again.',
      );
    case 'vault':
      return shaped(
        'system', 'keychain_unavailable', null,
        'Couldn’t save to the broker’s vault',
        text(payload, 'message'),
      );
    case 'one_password':
      return shaped(
        'system', 'onepassword', null,
        `1Password: ${text(payload, 'message')}`,
        text(payload, 'provider_code'),
      );
    case 'remote_unsupported':
      return shaped(
        'system', wire, null,
        `${text(payload, 'feature')} isn’t available for a remote broker yet`,
      );
    case 'unreachable':
      return shaped(
        'system', 'broker_unreachable', null,
        'Couldn’t reach the remote broker',
        text(payload, 'message'),
      );
    default:
      return shaped(
        'system', 'save_failed', null,
        'Couldn’t save your changes',
        text(payload, 'message'),
      );
  }
}
