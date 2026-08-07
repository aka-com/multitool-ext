// The production adapter for running this UI as a website.
//
// Same shape as the Tauri bridge — `invoke` and `listen` — over the broker's
// own `/v1/manage` API and its SSE feed. Nothing here chooses a broker: the
// broker that served this page is the only one we talk to, so every request
// is same-origin and the session cookie the browser already holds is the
// credential. There is no URL to configure and no token to paste, which is
// most of the point.
//
// Two rules the desktop bridge never had to think about:
//
// **Mutations carry the CSRF secret.** The cookie is `SameSite=Strict` and
// the broker also checks `Origin`, but the secret is the part a cross-origin
// page cannot obtain — same-origin policy already stops that page from
// reading any response that carries it. We fetch it once and refetch when
// the broker says it is stale.
//
// **A 401 means signed out, not failed.** Sessions expire on their own, and
// the honest response is to send the user back to the sign-in page rather
// than to render an app full of error toasts.

import { requestFor } from './commands';
import type {
  CommandArgs,
  CommandName,
  CommandResult,
  EventMap,
  EventName,
  EventPayload,
  Unlisten,
} from './types';

const CSRF_HEADER = 'x-multitool-csrf';

/** Where the sign-in page lives on the broker's origin. */
export const SIGN_IN_PATH = '/';

interface SessionInfo {
  account: string;
  session: string;
  scopes: string[];
  authenticated_at: string | null;
  csrf: string;
}

let session: SessionInfo | null = null;
let pending: Promise<SessionInfo | null> | null = null;

/** Raised when the broker no longer recognizes this browser. */
export class SignedOutError extends Error {
  constructor() {
    super('Your session has ended. Sign in again to continue.');
    this.name = 'SignedOutError';
  }
}

/** Raised when a command exists but only inside the desktop app. */
export class NotAvailableHereError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = 'NotAvailableHereError';
  }
}

async function readSession(force = false): Promise<SessionInfo | null> {
  if (session && !force) return session;
  // A forced refresh must reflect the broker's answer *now*, so it must not
  // piggyback on a read that started before the caller asked to force one.
  // Wait that earlier read out, then fall through to start a fresh one.
  if (force && pending) {
    try {
      await pending;
    } catch {
      /* the fresh read below is what matters */
    }
  }
  // One in-flight read, however many callers: a page load fires several
  // queries at once and they would otherwise each fetch the same thing.
  pending ??= (async () => {
    try {
      const response = await fetch('/v1/auth/session', {
        credentials: 'same-origin',
        headers: { accept: 'application/json' },
      });
      if (response.ok) {
        session = (await response.json()) as SessionInfo;
      } else if (response.status === 401) {
        // The broker is authoritative that this browser is not signed in.
        session = null;
      }
      // Any other status is a broker hiccup, not a verdict on the session:
      // leave what we had rather than converting it into a sign-out.
    } catch {
      // A transport failure is a blip, not a sign-out. Keep the cached
      // session so a momentary network drop does not eject the user.
    } finally {
      pending = null;
    }
    return session;
  })();
  return pending;
}

/** Who is signed in, or null. The shell renders sign-in from this. */
export async function currentSession(): Promise<SessionInfo | null> {
  return readSession();
}

export async function signOut(): Promise<void> {
  const csrf = (await readSession())?.csrf;
  try {
    await fetch('/v1/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: csrf ? { [CSRF_HEADER]: csrf } : {},
    });
  } finally {
    session = null;
  }
}

function isSafe(method: string): boolean {
  return method === 'GET' || method === 'HEAD';
}

async function send(
  method: string,
  path: string,
  body: unknown | undefined,
  csrf: string | undefined,
): Promise<Response> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (!isSafe(method) && csrf) headers[CSRF_HEADER] = csrf;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/**
 * The error a failed manage call becomes.
 *
 * The broker's structured `ManageError` is what the desktop's command layer
 * already surfaces, so the same objects reach the same error formatting.
 */
async function failure(response: Response): Promise<unknown> {
  const text = await response.text().catch(() => '');
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    // A step-up refusal is not an error to display — it is a prompt.
    if (parsed.reason === 'step_up_required') {
      return new StepUpRequiredError(String(parsed.detail ?? ''));
    }
    return parsed;
  } catch {
    return text || response.statusText;
  }
}

/** The broker wants a fresh passkey gesture before it will do this. */
export class StepUpRequiredError extends Error {
  constructor(detail: string) {
    super(detail || 'Confirm with your passkey to continue.');
    this.name = 'StepUpRequiredError';
  }
}

export async function invoke<K extends CommandName>(
  command: K,
  args?: CommandArgs<K>,
): Promise<CommandResult<K>> {
  let request;
  try {
    request = requestFor(command, args as CommandArgs<K>);
  } catch (error) {
    throw new NotAvailableHereError(String((error as Error).message ?? error));
  }
  const mutating = !isSafe(request.method);
  let csrf = mutating ? (await readSession())?.csrf : undefined;
  if (mutating && !csrf) throw new SignedOutError();

  let response = await send(request.method, request.path, request.body, csrf);
  // A stale CSRF secret is indistinguishable from a signed-out session at
  // the call site, so try once with a fresh one before giving up. A second
  // failure is genuine.
  if (response.status === 403 && mutating) {
    csrf = (await readSession(true))?.csrf;
    if (!csrf) throw new SignedOutError();
    response = await send(request.method, request.path, request.body, csrf);
  }
  if (response.status === 401) {
    // A step-up demand is also a 401, but it is a prompt for a fresh passkey
    // gesture — not a sign-out. Read the body to tell the two apart before
    // discarding a session that is in fact still live.
    const problem = await failure(response);
    if (problem instanceof StepUpRequiredError) throw problem;
    session = null;
    throw new SignedOutError();
  }
  if (!response.ok) throw await failure(response);
  if (response.status === 204) return undefined as CommandResult<K>;
  const text = await response.text();
  const value = text ? JSON.parse(text) : undefined;
  return (request.unwrap ? request.unwrap(value) : value) as CommandResult<K>;
}

/* -------------------------------- events --------------------------------- */

/**
 * One SSE connection for the whole page, fanned out to listeners.
 *
 * `EventSource` reconnects and resumes by `Last-Event-ID` on its own, which
 * is exactly the protocol the broker's feed already speaks — so the
 * reconnect logic the desktop client hand-rolls is the browser's here.
 */
type Handler = (event: EventPayload<unknown>) => void;

const handlers = new Map<string, Set<Handler>>();
let stream: EventSource | null = null;

/** Events that exist only inside the desktop shell. Nothing emits them
 * here, and a listener for one is harmless — it simply never fires. */
const NATIVE_EVENTS = new Set<EventName>([
  'aka://broker-changed',
  'aka://notification-settings-changed',
  'aka://lock-changed',
  'aka://dropdown-hidden',
  'aka://dropdown-shown',
  'aka://open-settings',
  'aka://open-requests',
]);

/**
 * The broker's SSE payloads, mapped onto the shell's event names.
 *
 * Keyed by the wire tag exactly as `ManageEvent` serializes it — an
 * internally-tagged enum (`#[serde(tag = "event", rename_all = "snake_case")]`),
 * so each frame is `{"event":"secrets_changed", …}`. The variants that carry a
 * payload (`activity_appended`, `mcp_auth_changed`, `connect_requested`) and
 * `resync` are handled separately below; everything here is a bare "refetch
 * this" signal.
 */
const EVENT_NAMES: Record<string, EventName> = {
  sessions_changed: 'aka://sessions-changed',
  agents_changed: 'aka://agents-changed',
  wirings_changed: 'aka://wirings-changed',
  connections_changed: 'aka://connections-changed',
  secrets_changed: 'aka://secrets-changed',
  integrations_changed: 'aka://integrations-changed',
  elicitations_changed: 'aka://elicitations-changed',
  approvals_changed: 'aka://approvals-changed',
  // No dedicated web event exists for a single expiry; a queue refetch is the
  // web equivalent of what the desktop does with it.
  approval_expired: 'aka://approvals-changed',
  // The log was cleared (as opposed to appended to): refetch the view.
  activity_cleared: 'aka://activity-changed',
};

/** What a `resync` refetches: the same topics the desktop reloads. */
const RESYNC_TOPICS: EventName[] = [
  'aka://connections-changed',
  'aka://secrets-changed',
  'aka://integrations-changed',
  'aka://sessions-changed',
  'aka://wirings-changed',
  'aka://agents-changed',
  'aka://activity-changed',
  'aka://approvals-changed',
  'aka://elicitations-changed',
];

function deliver(name: EventName, payload: unknown): void {
  for (const handler of handlers.get(name) ?? []) {
    handler({ event: name, payload });
  }
}

function ensureStream(): void {
  if (stream) return;
  stream = new EventSource('/v1/manage/events', { withCredentials: true });
  stream.onmessage = (message) => {
    let parsed: { event?: string } & Record<string, unknown>;
    try {
      parsed = JSON.parse(message.data);
    } catch {
      return;
    }
    const tag = parsed?.event;
    if (!tag) return;
    if (tag === 'resync') {
      // The broker lost track of this client's position: refetch everything
      // the way the desktop does on the same signal.
      for (const name of RESYNC_TOPICS) deliver(name, {});
      return;
    }
    if (tag === 'activity_appended') {
      deliver('aka://activity-appended', parsed.entry);
      return;
    }
    if (tag === 'mcp_auth_changed') {
      deliver('aka://mcp-auth-changed', parsed.state);
      return;
    }
    if (tag === 'connect_requested') {
      deliver('aka://connect-requested', { agent: parsed.agent, service: parsed.service });
      return;
    }
    const name = EVENT_NAMES[tag];
    if (name) deliver(name, {});
  };
  stream.onerror = () => {
    // EventSource retries on its own. A closed stream means the broker
    // refused the credential — a sign-out rather than a network blip: close
    // it so the browser drops the dead socket, and reset so a later `listen`
    // opens a fresh one instead of reusing the corpse.
    if (stream?.readyState === EventSource.CLOSED) {
      stream.close();
      stream = null;
      session = null;
    }
  };
}

export async function listen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  const handler = callback as Handler;
  const set = handlers.get(event) ?? new Set<Handler>();
  set.add(handler);
  handlers.set(event, set);
  if (!NATIVE_EVENTS.has(event)) ensureStream();
  return () => {
    set.delete(handler);
    if (!set.size) handlers.delete(event);
  };
}
