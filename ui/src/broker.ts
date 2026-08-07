// Broker-switcher helpers: which broker the app manages (this Mac or a
// remote one over its manage API), how the header labels it, and which
// full-pane takeover the main content shows while a remote link is not
// usable. Pure functions — the shell owns the actual state.

import type { BrokerProfile, ConnectionType } from './types';

export const ONEPASSWORD_PROVIDER_CAPABILITY = 'onepassword_provider_v1';
export const TYPED_CREDENTIALS_CAPABILITY = 'typed_credentials_v1';
export const PASSKEY_AUTH_CAPABILITY = 'passkey_auth_v1';

export const LOCAL_BROKER: BrokerProfile = {
  mode: 'local',
  url: null,
  connected: true,
  error: null,
  has_saved_token: false,
  has_saved_grant: false,
  credential: null,
  device_name: null,
  capabilities: [ONEPASSWORD_PROVIDER_CAPABILITY, TYPED_CREDENTIALS_CAPABILITY],
};

export function supportsOnePassword(profile: BrokerProfile): boolean {
  return profile.capabilities.includes(ONEPASSWORD_PROVIDER_CAPABILITY);
}

/** Whether this broker stores typed credentials (passwords with site,
 * username, and an optional TOTP factor). Older remote brokers do not. */
export function supportsTypedCredentials(profile: BrokerProfile): boolean {
  return profile.capabilities.includes(TYPED_CREDENTIALS_CAPABILITY);
}

/** The switcher's label: "Local" for this machine, or the remote host. */
export function brokerLabel(profile: BrokerProfile): string {
  if (profile.mode === 'local') return 'Local';
  if (profile.mode === 'unset') return 'Choose broker';
  if (!profile.url) return 'Remote broker';
  try {
    return new URL(profile.url).host;
  } catch {
    return profile.url;
  }
}

/** Whether this broker can be signed in to with a passkey at all. A broker
 * predating the auth plane sees only the management token, and the setup
 * pane must not offer a sign-in it would fail. */
export function supportsPasskeys(profile: BrokerProfile): boolean {
  return profile.capabilities.includes(PASSKEY_AUTH_CAPABILITY);
}

/** Whether this connection is still on the management token. The setup
 * pane offers to move it to a passkey, which is per-device and revocable. */
export function usesLegacyToken(profile: BrokerProfile): boolean {
  return profile.mode === 'remote' && profile.credential === 'token';
}

export type BrokerTone = 'local' | 'ok' | 'pending' | 'error';

/** The status dot next to the switcher label. */
export function brokerTone(profile: BrokerProfile): BrokerTone {
  if (profile.mode === 'local' && profile.connected) return 'local';
  if (profile.connected) return 'ok';
  return profile.error ? 'error' : 'pending';
}

export type BrokerTakeover = 'choose' | 'setup' | 'connecting' | 'error' | null;

/**
 * Which full-pane takeover the main content shows. `setupOpen` is the
 * user-driven "configure a remote broker" form; `choose` is a first run
 * where no broker exists yet; the others derive from the link state: an
 * unavailable broker owns the whole content pane (and disables the nav)
 * until it responds or the user switches brokers.
 */
export function brokerTakeover(
  profile: BrokerProfile,
  setupOpen: boolean,
): BrokerTakeover {
  // The setup form opens over the chooser (its "Hosted broker" option), and
  // closing it falls back here rather than into an app with no broker.
  if (setupOpen) return 'setup';
  if (profile.mode === 'unset') return 'choose';
  if (profile.connected) return null;
  if (profile.mode === 'local') return 'error';
  // Nothing saved for this broker means the user has never signed in to it,
  // so the setup pane is the only useful thing to show — not a retry loop
  // against a credential that does not exist.
  if (profile.mode === 'remote' && !profile.has_saved_token && !profile.has_saved_grant) {
    return 'setup';
  }
  return profile.error ? 'error' : 'connecting';
}

/**
 * A caution shown alongside direct-endpoint issuance on a remote broker, or
 * null in local mode. Endpoints work remotely, but PG/SSH ones are Unix
 * sockets on the broker host and the SSH agent socket is a filesystem path;
 * only the HTTP endpoint's address (advertised host) is reachable off-box.
 */
export function remoteEndpointCaution(
  profile: BrokerProfile,
  type: ConnectionType,
): string | null {
  if (profile.mode !== 'remote') return null;
  if (type === 'api') {
    return 'The address uses the broker’s advertised host — make sure agents can reach it.';
  }
  if (type === 'pg') {
    return 'A remote broker’s Postgres endpoint is a socket on the broker host; agents must run there.';
  }
  if (type === 'ssh') {
    return 'A remote broker’s SSH agent socket lives on the broker host; agents must run there.';
  }
  return null;
}
