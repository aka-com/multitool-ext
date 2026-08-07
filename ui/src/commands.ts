// Which commands are the broker's and which are this shell's.
//
// The webview has always talked to one thing: a Tauri command surface that
// mixed two unrelated kinds of call. Some are questions for the broker —
// list the connections, reveal a credential, answer an approval — and reach
// it identically whether it is in this process or across the network. The
// rest are the desktop app itself: the dock icon, the OS clipboard, Touch
// ID, `~/.aws` on this disk. Only the first kind can reach a browser.
//
// This table is that split, and it is exhaustive over `CommandMap` — a new
// command does not compile until you classify it. That is the point:
// forgetting to classify one would otherwise mean discovering in production
// that the web app calls something only a Mac can answer.
//
// `native` is not a smaller list of features. It is the list of things a
// browser genuinely cannot do, and each entry says which.

import type { CommandArgs, CommandMap, CommandName } from './types';

/** Where a command can be served from. */
export type CommandHost = 'broker' | 'native';

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/**
 * How a broker command reaches `/v1/manage`.
 *
 * `path` is a template whose `:name` segments are filled from the command's
 * arguments. `body` picks what to send; anything it does not return is not
 * sent, so a value used only to build the path never also lands in the body.
 * `unwrap` pulls the UI's value out of the envelope some routes use.
 */
export interface BrokerRoute {
  method: Method;
  path: string;
  body?: (args: Record<string, unknown>) => unknown;
  unwrap?: (value: unknown) => unknown;
}

/** Why a command cannot be served to a browser. */
export interface NativeOnly {
  reason: string;
}

export type CommandSpec =
  | ({ host: 'broker' } & BrokerRoute)
  | ({ host: 'native' } & NativeOnly);

const pick = (...keys: string[]) =>
  (args: Record<string, unknown>): unknown => {
    const body: Record<string, unknown> = {};
    for (const key of keys) if (args[key] !== undefined) body[key] = args[key];
    return body;
  };

/** The body is one named field the route expects under a different name. */
const rename = (from: string, to: string) =>
  (args: Record<string, unknown>): unknown => ({ [to]: args[from] });

/**
 * Rename several fields at once, keeping `pick`'s omit-if-absent rule.
 *
 * The webview passes arguments in camelCase (Tauri's convention maps them to
 * a Rust command's snake_case parameters), but a broker route deserializes
 * the JSON body by its own snake_case field names — so a straight forward of
 * the camelCase keys deserializes to nothing and the call fails silently. A
 * field whose value is `undefined` is left out, so "send only what changed"
 * still holds.
 */
const remap = (mapping: Record<string, string>) =>
  (args: Record<string, unknown>): unknown => {
    const body: Record<string, unknown> = {};
    for (const [from, to] of Object.entries(mapping)) {
      if (args[from] !== undefined) body[to] = args[from];
    }
    return body;
  };

const field = (name: string) => (value: unknown): unknown =>
  (value as Record<string, unknown>)?.[name];

const broker = (method: Method, path: string, rest: Partial<BrokerRoute> = {}): CommandSpec =>
  ({ host: 'broker', method, path, ...rest });

const native = (reason: string): CommandSpec => ({ host: 'native', reason });

const NO_BODY = () => ({});

/**
 * Every command, classified. Typed as a total map over `CommandMap`, so
 * adding a command without deciding where it belongs is a type error.
 */
export const COMMANDS: { [K in CommandName]: CommandSpec } = {
  /* ------------------------- this shell, only ------------------------- */

  // Which broker the app manages is a property of this installation. A
  // browser is already *at* one broker — the one that served the page.
  get_broker_profile: native('the web app is served by the broker it manages'),
  connect_remote_broker: native('the web app is served by the broker it manages'),
  sign_in_remote_broker: native('the web app signs in on this page, not through a device grant'),
  retry_remote_broker: native('the web app is served by the broker it manages'),
  switch_broker_local: native('there is no local broker to switch to in a browser'),
  default_device_name: native('names this Mac'),

  get_local_username: native('reads this machine’s user account'),

  // The OS clipboard. The browser has its own, and it is materially
  // different: these copies keep the value out of the webview entirely,
  // mark it as transient so clipboard managers skip it, and clear it on a
  // timer. `navigator.clipboard` can do none of that.
  copy_secret: native('copies without the value entering the page'),
  copy_secret_totp: native('copies without the value entering the page'),
  copy_endpoint_text: native('copies without the value entering the page'),
  copy_key: native('copies without the value entering the page'),
  copy_agent_setup: native('copies without the value entering the page'),

  // Native notifications, the dock, and login items.
  get_notification_settings: native('native notifications belong to this app'),
  set_notification_settings: native('native notifications belong to this app'),
  request_notification_permission: native('native notifications belong to this app'),
  open_notification_settings: native('opens System Settings'),
  get_autostart: native('a login item is a property of this Mac'),
  set_autostart: native('a login item is a property of this Mac'),
  open_url: native('opens the system browser'),

  // The app lock gates this shell's own windows. A browser tab has no
  // equivalent, and the broker session's own expiry is the web answer.
  get_lock_state: native('Touch ID gates this app’s windows'),
  set_lock_settings: native('Touch ID gates this app’s windows'),
  lock_app: native('Touch ID gates this app’s windows'),
  unlock_app: native('Touch ID gates this app’s windows'),
  note_activity: native('drives this app’s idle timer'),
  start_embedded_unlock: native('hosts a native control'),
  retry_embedded_unlock: native('hosts a native control'),
  stop_embedded_unlock: native('hosts a native control'),

  // This disk.
  list_aws_profiles: native('reads ~/.aws on this Mac'),
  inspect_ssh_import: native('reads a key file on this Mac'),
  check_known_hosts: native('reads ~/.ssh/known_hosts on this Mac'),

  // Window chrome.
  set_menu_bar_hides_dock: native('a macOS window behaviour'),
  ui_set_mode: native('window chrome'),
  ui_hide_main: native('window chrome'),
  ui_hide_dropdown: native('window chrome'),
  ui_set_dropdown_form_active: native('window chrome'),
  ui_set_request_inbox_visible: native('window chrome'),
  ui_take_open_requests: native('window chrome'),

  /* ------------------------------ the broker -------------------------- */

  list_secrets: broker('GET', '/v1/manage/secrets'),
  add_secret: broker('POST', '/v1/manage/secrets', {
    body: pick('name', 'value', 'kind', 'site', 'username', 'totp'),
  }),
  edit_secret: broker('PATCH', '/v1/manage/secrets/:id', {
    body: remap({
      newName: 'new_name',
      newValue: 'new_value',
      newSite: 'new_site',
      newUsername: 'new_username',
      newTotp: 'new_totp',
    }),
  }),
  delete_secret: broker('DELETE', '/v1/manage/secrets/:id'),
  reveal_secret: broker('POST', '/v1/manage/secrets/:id/reveal', {
    body: NO_BODY,
    unwrap: field('value'),
  }),
  get_secret_totp: broker('POST', '/v1/manage/secrets/:id/totp', { body: NO_BODY }),

  list_onepassword_integrations: broker('GET', '/v1/manage/integrations'),
  add_onepassword_integration: broker('POST', '/v1/manage/integrations', {
    body: pick('label', 'method', 'account', 'connectUrl', 'token'),
  }),
  replace_onepassword_token: broker('PUT', '/v1/manage/integrations/:id/token', {
    body: pick('token'),
  }),
  delete_onepassword_integration: broker('DELETE', '/v1/manage/integrations/:id'),
  onepassword_health: broker('GET', '/v1/manage/integrations/:id/health'),
  list_onepassword_vaults: broker('GET', '/v1/manage/integrations/:id/vaults'),
  list_onepassword_items: broker('GET', '/v1/manage/integrations/:id/vaults/:vaultId/items'),
  list_onepassword_fields: broker(
    'GET',
    '/v1/manage/integrations/:id/vaults/:vaultId/items/:itemId/fields',
  ),
  add_onepassword_secret: broker('POST', '/v1/manage/integrations/onepassword/secrets', {
    body: remap({
      name: 'name',
      integrationId: 'integration_id',
      vaultId: 'vault_id',
      vaultLabel: 'vault_label',
      itemId: 'item_id',
      itemLabel: 'item_label',
      sectionId: 'section_id',
      sectionLabel: 'section_label',
      fieldId: 'field_id',
      fieldLabel: 'field_label',
      fieldType: 'field_type',
    }),
  }),

  list_connections: broker('GET', '/v1/manage/connections'),
  add_connection: broker('POST', '/v1/manage/connections', { body: pick('input') }),
  edit_connection: broker('PUT', '/v1/manage/connections/:id', {
    body: pick('expectedUpdatedAt', 'input'),
  }),
  delete_connection: broker('DELETE', '/v1/manage/connections/:id'),
  reorder_connections: broker('POST', '/v1/manage/connections/reorder', {
    body: rename('orderedIds', 'ordered_ids'),
  }),
  test_connection: broker('POST', '/v1/manage/connections/:id/test', { body: NO_BODY }),
  test_connection_draft: broker('POST', '/v1/manage/connections/test-draft', {
    body: pick('input'),
  }),
  set_tool_access: broker('POST', '/v1/manage/connections/:connectionId/access', {
    body: pick('enabled'),
    unwrap: field('changed'),
  }),
  set_confirm_mode: broker('POST', '/v1/manage/connections/:connectionId/confirm', {
    body: rename('on', 'on'),
    unwrap: field('changed'),
  }),
  set_expose_response_credentials: broker(
    'POST',
    '/v1/manage/connections/:connectionId/response-credentials',
    { body: pick('expose'), unwrap: field('changed') },
  ),
  set_allowed_tools: broker('POST', '/v1/manage/connections/:connectionId/allowed-tools', {
    body: pick('tools'),
    unwrap: field('changed'),
  }),
  set_audit_statements: broker('POST', '/v1/manage/connections/:connectionId/audit-statements', {
    body: rename('auditStatements', 'audit_statements'),
    unwrap: field('changed'),
  }),
  list_mcp_tools: broker('GET', '/v1/manage/connections/:id/mcp-tools'),
  // The handler deserializes `McpCheckOptions` at the top level of the body,
  // so the options object is sent as the body itself, not wrapped in a key.
  mcp_status: broker('POST', '/v1/manage/connections/:id/mcp-status', {
    body: (args) => args.options ?? {},
  }),

  // OAuth and relayed-MCP sign-in both hand their result back to a loopback
  // catcher the desktop shell opens (`http://127.0.0.1:<port>/…`). A browser
  // has no such catcher and cannot originate that redirect, so the flow
  // cannot complete in the web app — offering it would strand the user
  // mid-sign-in rather than fail honestly here.
  start_mcp_auth: native('MCP sign-in returns to a loopback catcher only the desktop app runs'),
  get_mcp_auth: broker('GET', '/v1/manage/mcp-auth/:id'),
  cancel_mcp_auth: broker('DELETE', '/v1/manage/mcp-auth/:id', { unwrap: field('cancelled') }),
  oauth_connect: native('OAuth sign-in returns to a loopback catcher only the desktop app runs'),
  oauth_reconnect: native('OAuth reconnect returns to a loopback catcher only the desktop app runs'),

  issue_endpoint: broker('POST', '/v1/manage/connections/:connectionId/endpoint', {
    body: NO_BODY,
  }),
  renew_endpoint: broker('POST', '/v1/manage/connections/:connectionId/endpoint/renew', {
    body: NO_BODY,
  }),
  get_endpoint: broker('GET', '/v1/manage/connections/:connectionId/endpoint'),
  set_endpoint_expiry: broker('POST', '/v1/manage/connections/:connectionId/endpoint/expiry', {
    body: pick('expire'),
  }),
  set_endpoint_require_auth: broker(
    'POST',
    '/v1/manage/connections/:connectionId/endpoint/require-auth',
    { body: rename('requireAuth', 'require_auth'), unwrap: field('changed') },
  ),
  revoke_endpoint: broker('DELETE', '/v1/manage/endpoints/:endpointId', {
    unwrap: field('revoked'),
  }),

  get_identity: broker('GET', '/v1/manage/identity'),
  rotate_key: broker('POST', '/v1/manage/identity/rotate', { body: NO_BODY }),
  get_agent_setup: broker('GET', '/v1/manage/agent-setup'),

  list_approvals: broker('GET', '/v1/manage/approvals'),
  respond_approval: broker('POST', '/v1/manage/approvals/:id', {
    body: pick('decision'),
    unwrap: field('answered'),
  }),
  list_elicitations: broker('GET', '/v1/manage/elicitations'),
  respond_elicitation: broker('POST', '/v1/manage/elicitations/:id', {
    body: pick('approved', 'values'),
    unwrap: field('answered'),
  }),
  list_requests: broker('GET', '/v1/manage/requests'),

  list_sessions: broker('GET', '/v1/manage/sessions'),
  close_session: broker('DELETE', '/v1/manage/sessions/:id', { unwrap: field('closed') }),

  // On a GET, `body` is the query string — see `requestFor`.
  list_activity: broker('GET', '/v1/manage/activity/page', {
    body: pick('limit', 'before'),
  }),
  clear_activity: broker('DELETE', '/v1/manage/activity'),

  get_settings: broker('GET', '/v1/manage/settings'),
  set_confirm_ssh_host_keys: broker('PATCH', '/v1/manage/settings', {
    body: rename('on', 'confirm_ssh_host_keys'),
  }),
};

/** Whether a command can be served outside the desktop app. */
export function commandHost(name: CommandName): CommandHost {
  return COMMANDS[name].host;
}

/** The reason a native-only command is unavailable, for the message a web
 * surface shows instead of the control. */
export function nativeOnlyReason(name: CommandName): string | null {
  const spec = COMMANDS[name];
  return spec.host === 'native' ? spec.reason : null;
}

/** Every command a browser can issue. */
export function brokerCommands(): CommandName[] {
  return (Object.keys(COMMANDS) as CommandName[]).filter(
    (name) => COMMANDS[name].host === 'broker',
  );
}

/**
 * Fill a route template from a command's arguments.
 *
 * Values are percent-encoded: an id is a UUID today, but a path built by
 * concatenation is one careless change away from letting an argument add
 * path segments of its own.
 */
export function resolvePath(path: string, args: Record<string, unknown>): string {
  return path.replace(/:([A-Za-z]+)/g, (_, key: string) => {
    const value = args?.[key];
    if (value === undefined || value === null) {
      throw new Error(`the ${key} argument is required`);
    }
    return encodeURIComponent(String(value));
  });
}

/**
 * The request a broker command becomes.
 *
 * On a safe method the `body` picker produces the query string instead: a
 * GET with a request body is legal and widely mishandled — by proxies, by
 * caches, and by `fetch` itself — so the two never both exist.
 */
export function requestFor<K extends CommandName>(
  name: K,
  args: CommandArgs<K>,
): { method: Method; path: string; body: unknown | undefined; unwrap?: (v: unknown) => unknown } {
  const spec = COMMANDS[name];
  if (spec.host !== 'broker') {
    throw new Error(`${name} is only available in the desktop app: ${spec.reason}`);
  }
  const record = (args ?? {}) as Record<string, unknown>;
  let path = resolvePath(spec.path, record);
  let body = spec.body ? spec.body(record) : undefined;
  if (spec.method === 'GET') {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries((body ?? {}) as Record<string, unknown>)) {
      if (value !== undefined && value !== null) query.set(key, String(value));
    }
    const encoded = query.toString();
    if (encoded) path = `${path}?${encoded}`;
    body = undefined;
  }
  return { method: spec.method, path, body, unwrap: spec.unwrap };
}

/** Type-level assertion that the table covers `CommandMap` exactly. */
type _Exhaustive = CommandMap extends Record<keyof typeof COMMANDS, unknown> ? true : never;
const _exhaustive: _Exhaustive = true;
void _exhaustive;
