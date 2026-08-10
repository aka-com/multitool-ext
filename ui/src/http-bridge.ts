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
import { ConnectionSpecError } from './connection-spec';
import { manageErrorContext, manageFormError } from './manage-errors';
import { unthrottledTimeout } from './worker-timer';
import type {
  BrokerProfile,
  CommandArgs,
  CommandName,
  CommandResult,
  EventMap,
  EventName,
  EventPayload,
  Unlisten,
} from './types';

const CSRF_HEADER = 'x-multitool-csrf';

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

/** Re-read the session from the broker, bypassing the cache. The sign-in
 * ceremonies call this after the broker sets the cookie, so the next
 * mutation carries the fresh CSRF secret instead of eating a 403 first. */
export async function refreshSession(): Promise<SessionInfo | null> {
  return readSession(true);
}

/** Capabilities advertised by this broker, fetched once per page. */
let capabilities: string[] | null = null;

/**
 * The web answer to `get_broker_profile`.
 *
 * The desktop asks its shell which broker it manages; a browser is already
 * *at* the answer — the broker that served this page — so the profile is
 * built here rather than asked for. `connected` reflects the session: the
 * broker is reachable (it just served the bundle), but without a session
 * every manage call would 401, and the sign-in pane is the honest surface
 * for that state.
 */
export async function webBrokerProfile(): Promise<BrokerProfile> {
  const current = await readSession();
  if (current && capabilities === null) {
    try {
      const response = await fetch('/v1/manage/whoami', {
        credentials: 'same-origin',
        headers: { accept: 'application/json' },
      });
      if (response.ok) {
        const whoami = (await response.json()) as { capabilities?: unknown };
        capabilities = Array.isArray(whoami.capabilities)
          ? whoami.capabilities.filter((value): value is string => typeof value === 'string')
          : [];
      }
    } catch {
      // Leave capabilities unknown: the surfaces they gate stay hidden and
      // the next profile read tries again.
    }
  }
  return {
    mode: 'remote',
    url: location.origin,
    connected: current != null,
    error: null,
    has_saved_token: false,
    // The session cookie is this browser's grant; there is nothing saved
    // beyond it.
    has_saved_grant: current != null,
    credential: current ? 'passkey' : null,
    device_name: null,
    capabilities: (current ? capabilities : null) ?? [],
  };
}

export async function signOut(): Promise<void> {
  // A polling request-inbox lease is independent of the SSE observer. Drop
  // it while this session can still authenticate the DELETE instead of
  // leaving the broker to wait for its short expiry.
  await detachApprovalSurface();
  stream?.close();
  stream = null;
  // A reconnect timer left armed here would reopen the stream after the
  // sign-out it is meant to be part of.
  stopStreamReconnect();
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
    // The auth plane answers `{reason, detail}` and older brokers' manage
    // errors carry only `{code, …}` — neither has the `message` the form
    // error helpers read, and without one a toast renders as
    // "[object Object]". Words beat a tag, however generic.
    if (typeof parsed.message !== 'string') {
      const detail = typeof parsed.detail === 'string' ? parsed.detail : '';
      const tag = typeof parsed.reason === 'string' ? parsed.reason
        : typeof parsed.code === 'string' ? parsed.code
        : '';
      const message = detail || tag.replace(/_/g, ' ');
      if (message) parsed.message = message;
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
    // A rejected connection draft is a form error, not a missing capability:
    // surface it in the same shape the broker's 400 would, so the form marks
    // the offending field instead of showing "unavailable here".
    if (error instanceof ConnectionSpecError) throw error.formError;
    throw new NotAvailableHereError(String((error as Error).message ?? error));
  }
  const mutating = !isSafe(request.method);
  let csrf = mutating ? (await readSession())?.csrf : undefined;
  if (mutating && !csrf) throw new SignedOutError();

  let response = await send(request.method, request.path, request.body, csrf);
  // A stale CSRF secret is indistinguishable from a signed-out session at
  // the call site, so try once with a fresh one before giving up. A second
  // failure is genuine. (The broker reports a CSRF mismatch as a 401, the
  // same as a dead cookie; the 403 branch covers older brokers and any
  // proxy that answers differently.)
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
    // On a mutation, a 401 can also be the stale-CSRF case: the broker
    // refuses the pair without distinguishing it from a dead cookie.
    // Re-read the session once to tell them apart — a dead cookie reads
    // back as signed out, a live one yields the fresh secret and the call
    // gets exactly one retry.
    if (mutating) {
      const fresh = (await readSession(true))?.csrf;
      if (fresh && fresh !== csrf) {
        response = await send(request.method, request.path, request.body, fresh);
        // The retry can hit the step-up demand the stale secret was
        // masking; that is still a prompt, not a sign-out.
        if (response.status === 401) {
          const retried = await failure(response);
          if (retried instanceof StepUpRequiredError) throw retried;
        }
      }
    }
    if (response.status === 401) {
      session = null;
      throw new SignedOutError();
    }
  }
  if (!response.ok) {
    const problem = await failure(response);
    // A manage error carries a `code`; route it onto the same field-level
    // shape the desktop's command layer produces, so the forms mark the
    // offending input here too instead of toasting everything globally.
    if (problem && typeof problem === 'object' && !(problem instanceof Error)) {
      const structured = manageFormError(
        problem as Record<string, unknown>,
        manageErrorContext(command, args),
      );
      if (structured) throw structured;
    }
    throw problem;
  }
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

/**
 * The app's handler for "this browser's session ended", discovered here at
 * the transport rather than by a user action. Without it, a stream that
 * dies to a revoked session leaves the page rendering its last snapshot
 * until the next fetch happens to 401 — and a page the user is only
 * reading never fetches.
 */
let sessionLost: (() => void) | null = null;

export function onSessionLost(callback: () => void): void {
  sessionLost = callback;
}

/* --------------------------- stream recovery ----------------------------- */
// EventSource's own retry covers a dropped socket, and only that: any
// non-2xx answer on reconnect — a proxy's 502 while the broker restarts, a
// revoked session's 401 — lands the object in CLOSED, permanently. These
// reopen it: with backoff for transport failures, and never for a session
// the broker actually ended (that is `sessionLost`'s job).

let streamRetryMs = 1_000;
let cancelStreamReconnect: (() => void) | null = null;
/** A manual reopen carries no Last-Event-ID, so whatever the broker sent
 * during the outage is gone: refetch everything once the stream is back. */
let resyncOnOpen = false;

function scheduleStreamReconnect(): void {
  cancelStreamReconnect?.();
  const delay = streamRetryMs;
  streamRetryMs = Math.min(streamRetryMs * 2, 30_000);
  cancelStreamReconnect = unthrottledTimeout(() => {
    cancelStreamReconnect = null;
    if (!stream && handlers.size) void ensureStream();
  }, delay);
}

function stopStreamReconnect(): void {
  cancelStreamReconnect?.();
  cancelStreamReconnect = null;
}

/**
 * Returning to the tab re-arms everything immediately — the worker timers
 * keep ticking while hidden, but a reopened laptop lid or a woken machine
 * may have missed arbitrary time, and the user is looking right now.
 */
let visibilityHooked = false;
function hookVisibility(): void {
  if (visibilityHooked || typeof document === 'undefined') return;
  visibilityHooked = true;
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    if (stream) void attachApprovalSurface();
    else if (handlers.size) void ensureStream();
  });
}

/**
 * Browsers cannot attach the request-inbox header to a native `EventSource`.
 * The manage API therefore offers the same capability as a short polling
 * lease: mint one while this page has a live observer and renew it often
 * enough that closing the tab fails closed after a few missed heartbeats.
 */
interface ApprovalSurface {
  id: string;
  expires_in_ms: number;
}

const APPROVAL_SURFACE_HEARTBEAT_MS = 5_000;
let approvalSurfaceId: string | null = null;
// Cancels the pending heartbeat/attach tick. The tick runs on a worker
// timer (see worker-timer.ts): a hidden tab's page timers are throttled far
// past the lease's 15-second expiry, and a lease that lapses whenever the
// tab is backgrounded means approvals fail closed while nothing looks wrong.
let cancelApprovalSurfaceTick: (() => void) | null = null;
let approvalSurfaceGeneration = 0;
let approvalSurfacePending: Promise<void> | null = null;

async function surfaceMutation(method: 'POST' | 'PUT' | 'DELETE', path: string): Promise<Response | null> {
  let csrf = (await readSession())?.csrf;
  if (!csrf) return null;
  let response = await send(method, path, undefined, csrf);
  if (response.status === 403) {
    csrf = (await readSession(true))?.csrf;
    if (!csrf) return null;
    response = await send(method, path, undefined, csrf);
  }
  if (response.status === 401) {
    // Same stale-CSRF ambiguity as `invoke`: the broker reports a drifted
    // pair as a 401. One forced session read settles it — losing the
    // approval-surface lease to a secret that merely rotated would leave
    // agent traffic waiting on prompts this page can no longer show.
    const fresh = (await readSession(true))?.csrf;
    if (fresh && fresh !== csrf) {
      response = await send(method, path, undefined, fresh);
    }
    if (response.status === 401) session = null;
  }
  return response;
}

function scheduleApprovalSurfaceHeartbeat(generation: number): void {
  cancelApprovalSurfaceTick?.();
  cancelApprovalSurfaceTick = unthrottledTimeout(() => {
    void heartbeatApprovalSurface(generation);
  }, APPROVAL_SURFACE_HEARTBEAT_MS);
}

function scheduleApprovalSurfaceAttach(generation: number): void {
  if (generation !== approvalSurfaceGeneration || !stream) return;
  cancelApprovalSurfaceTick?.();
  cancelApprovalSurfaceTick = unthrottledTimeout(() => {
    if (generation === approvalSurfaceGeneration && stream) void attachApprovalSurface();
  }, APPROVAL_SURFACE_HEARTBEAT_MS);
}

async function heartbeatApprovalSurface(generation: number): Promise<void> {
  const id = approvalSurfaceId;
  if (!id || generation !== approvalSurfaceGeneration || !stream) return;
  let response: Response | null;
  try {
    response = await surfaceMutation(
      'PUT',
      `/v1/manage/approval-surfaces/${encodeURIComponent(id)}`,
    );
  } catch {
    // A transport interruption should not strand the page permanently. The
    // old lease expires safely if the retries cannot reach the broker.
    if (generation === approvalSurfaceGeneration && approvalSurfaceId === id && stream) {
      scheduleApprovalSurfaceHeartbeat(generation);
    }
    return;
  }
  if (generation !== approvalSurfaceGeneration || approvalSurfaceId !== id || !stream) return;
  if (response?.status === 404) {
    approvalSurfaceId = null;
    await attachApprovalSurface();
    return;
  }
  if (response?.status === 401) {
    approvalSurfaceId = null;
    return;
  }
  // Retry transport and broker failures too. The broker expires the old
  // lease after three missed heartbeats; a later 404 remints a fresh one.
  scheduleApprovalSurfaceHeartbeat(generation);
}

async function attachApprovalSurface(): Promise<void> {
  if (approvalSurfaceId) return;
  if (approvalSurfacePending) return approvalSurfacePending;
  const generation = approvalSurfaceGeneration;
  const operation = (async () => {
    let response: Response | null;
    try {
      response = await surfaceMutation('POST', '/v1/manage/approval-surfaces');
    } catch {
      scheduleApprovalSurfaceAttach(generation);
      return;
    }
    if (!response?.ok) {
      if (response?.status !== 401) scheduleApprovalSurfaceAttach(generation);
      return;
    }
    let surface: ApprovalSurface;
    try {
      surface = (await response.json()) as ApprovalSurface;
    } catch {
      scheduleApprovalSurfaceAttach(generation);
      return;
    }
    if (!surface.id) return;
    if (generation !== approvalSurfaceGeneration || !stream) {
      try {
        await surfaceMutation(
          'DELETE',
          `/v1/manage/approval-surfaces/${encodeURIComponent(surface.id)}`,
        );
      } catch {
        // The lease is deliberately short; failure to release it immediately
        // is bounded by the broker's expiry.
      }
      return;
    }
    approvalSurfaceId = surface.id;
    scheduleApprovalSurfaceHeartbeat(generation);
  })();
  approvalSurfacePending = operation;
  try {
    await operation;
  } finally {
    if (approvalSurfacePending === operation) approvalSurfacePending = null;
  }
}

async function detachApprovalSurface(): Promise<void> {
  approvalSurfaceGeneration += 1;
  cancelApprovalSurfaceTick?.();
  cancelApprovalSurfaceTick = null;
  const id = approvalSurfaceId;
  approvalSurfaceId = null;
  // Let an in-flight mint observe the generation change and release the id
  // it received before sign-out revokes this page's credential.
  if (approvalSurfacePending) await approvalSurfacePending;
  if (id) {
    try {
      await surfaceMutation(
        'DELETE',
        `/v1/manage/approval-surfaces/${encodeURIComponent(id)}`,
      );
    } catch {
      // Logout and teardown must continue through a network interruption;
      // the broker expires an unreleased lease after 15 seconds.
    }
  }
}

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

async function ensureStream(): Promise<void> {
  hookVisibility();
  if (stream) {
    await attachApprovalSurface();
    return;
  }
  stopStreamReconnect();
  stream = new EventSource('/v1/manage/events', { withCredentials: true });
  stream.onopen = () => {
    streamRetryMs = 1_000;
    if (resyncOnOpen) {
      resyncOnOpen = false;
      for (const name of RESYNC_TOPICS) deliver(name, {});
    }
  };
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
    // EventSource retries a dropped socket on its own; CLOSED is final.
    // But final is ambiguous: a revoked session closes the stream, and so
    // does a proxy answering 502 while the broker restarts. Ask the broker
    // which one this was, and either hand the sign-out to the app or
    // reopen with backoff.
    if (stream?.readyState !== EventSource.CLOSED) return;
    stream.close();
    stream = null;
    void detachApprovalSurface();
    void (async () => {
      const current = await readSession(true);
      if (!current) {
        session = null;
        stopStreamReconnect();
        sessionLost?.();
        return;
      }
      resyncOnOpen = true;
      scheduleStreamReconnect();
    })();
  };
  await attachApprovalSurface();
}

export async function listen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  const handler = callback as Handler;
  const set = handlers.get(event) ?? new Set<Handler>();
  set.add(handler);
  handlers.set(event, set);
  if (!NATIVE_EVENTS.has(event)) await ensureStream();
  return () => {
    set.delete(handler);
    if (!set.size) handlers.delete(event);
  };
}
