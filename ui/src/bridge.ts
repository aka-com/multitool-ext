// Bridge to whatever is behind this UI.
//
// Three hosts, chosen once at load:
//
// - **Tauri** — the desktop app. Everything works: broker calls go over IPC
//   to the shell's command layer, which reaches a local or hosted broker.
// - **A browser served by the broker** — the web app. Broker calls go to
//   `/v1/manage` on the same origin with the session cookie; the desktop's
//   native commands are not available and the UI does not offer them.
// - **A dev server** — a mock, so the frontend runs with no backend. The
//   compile-time DEV branch keeps its fixtures out of production bundles.
//
// `isNativeHost()` is what the views ask before rendering something only the
// desktop can do. The check is deliberately about the *host* rather than
// about individual commands: an affordance whose command is unavailable
// should not appear disabled with an explanation nobody wants, it should not
// appear.

import { commandHost, nativeOnlyReason } from './commands';
import type {
  CommandArgs,
  CommandName,
  CommandResult,
  EventMap,
  EventName,
  EventPayload,
  Unlisten,
} from './types';

const tauri = typeof window !== 'undefined' ? window.__TAURI__ : undefined;

/**
 * Whether this is a development build.
 *
 * Written as the bare `import.meta.env.DEV` on purpose: Vite substitutes
 * that exact expression for a literal, which is what lets the bundler drop
 * the mock's dynamic import — and the fixtures behind it — from a production
 * build entirely. The try/catch is for the node test runner, which imports
 * this module with no `import.meta.env` at all.
 */
function development(): boolean {
  try {
    return Boolean(import.meta.env.DEV);
  } catch {
    return false;
  }
}

/**
 * Whether the broker served this page itself.
 *
 * A production build with no Tauri is the web app. Development without Tauri
 * is the mock, which stands in for the desktop and answers everything.
 */
const webHost = !tauri && !development();

/** Whether the desktop app's native commands are available. */
export function isNativeHost(): boolean {
  return !webHost;
}

/** Why a native-only feature is missing here, or null when it is present. */
export function unavailableReason(command: CommandName): string | null {
  if (!webHost) return null;
  return nativeOnlyReason(command);
}

async function developmentMock() {
  if (!import.meta.env.DEV) {
    throw new Error('The Multitool frontend must run inside Tauri');
  }
  return import('./mock-bridge');
}

/** Which window chrome to render, from the URL hash. The hash is the
 * desktop shell's channel for naming its tray and popup surfaces; in a
 * browser anyone can type one, and a hand-typed #dropdown would boot tray
 * chrome full of native calls — the web app is always the plain window. */
export const mode = webHost ? 'window' : location.hash.replace('#', '') || 'window';

export async function invoke<K extends CommandName>(
  command: K,
  args?: CommandArgs<K>,
): Promise<CommandResult<K>> {
  if (tauri) {
    return tauri.core.invoke(
      command,
      args as Record<string, unknown> | undefined,
    ) as Promise<CommandResult<K>>;
  }
  if (webHost) {
    const http = await import('./http-bridge');
    // The desktop asks its shell which broker it manages. A browser is
    // already at the answer — the broker that served this page — so the
    // bridge answers locally instead of refusing a native command and
    // leaving the app to guess at a dead local broker.
    if (command === 'get_broker_profile') {
      return http.webBrokerProfile() as Promise<CommandResult<K>>;
    }
    // Refuse here rather than at the network: a native command has no
    // route to attempt, and a 404 would read as a broker problem.
    if (commandHost(command) === 'native') {
      throw new http.NotAvailableHereError(
        `${command} is only available in the desktop app: ${nativeOnlyReason(command)}`,
      );
    }
    return http.invoke(command, args);
  }
  const mock = await developmentMock();
  return mock.invoke(command, args);
}

export async function listen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  if (tauri) {
    return tauri.event.listen(event, callback as (event: EventPayload<unknown>) => void);
  }
  if (webHost) {
    const http = await import('./http-bridge');
    return http.listen(event, callback);
  }
  const mock = await developmentMock();
  return mock.listen(event, callback);
}
