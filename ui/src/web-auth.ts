// The web app's passkey ceremonies, against the broker's own sign-in surface.
//
// Same-origin like everything else in the web app: the broker that served
// this page runs `/v1/auth`, WebAuthn binds the passkey to this origin, and
// the ceremony's reward is the session cookie the http bridge already rides.
// The desktop app never imports this — it signs in through the system
// browser (`/authorize`), which runs its own inline copy of the sign-in
// half of these ceremonies.
//
// Wire shapes are webauthn-rs's: the options come back with base64url
// binary fields to decode before `navigator.credentials`, and the browser's
// binary results go back base64url-encoded.

import { refreshSession } from './http-bridge';

/** What the sign-in pane needs to render before anybody is signed in.
 * `GET /v1/auth/config` deliberately says nothing about who the owner is. */
export interface WebAuthConfig {
  /** A passkey exists, so sign-in is possible. False is a first run. */
  enrolled: boolean;
  /** `aka admin enroll` has been run and its secret is still live. */
  enrollment_open: boolean;
  /** The broker has a public origin to bind passkeys to. Without one
   * (`--public-url`), neither ceremony can run. */
  passkeys_available: boolean;
}

/** The ceremony was cancelled at the browser's passkey prompt. Not a
 * failure to report loudly — the user closed the sheet. */
export class PasskeyCancelledError extends Error {
  constructor() {
    super('The passkey prompt was closed before it finished.');
    this.name = 'PasskeyCancelledError';
  }
}

const b64url = (buffer: ArrayBuffer): string =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const unb64url = (text: string): Uint8Array => {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(padded + '='.repeat((4 - padded.length % 4) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
};

/** The `{reason, detail}` refusals `/v1/auth` answers with, as one message. */
async function refusal(response: Response): Promise<Error> {
  const fallback = `sign-in failed (${response.status})`;
  try {
    const parsed = await response.json() as { reason?: string; detail?: string };
    return new Error(parsed.detail || parsed.reason || fallback);
  } catch {
    return new Error(fallback);
  }
}

async function post(path: string, body: unknown): Promise<unknown> {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!response.ok) throw await refusal(response);
  return response.json();
}

export async function fetchAuthConfig(): Promise<WebAuthConfig> {
  const response = await fetch('/v1/auth/config', {
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
  });
  if (!response.ok) throw await refusal(response);
  const config = await response.json() as WebAuthConfig;
  return {
    enrolled: Boolean(config.enrolled),
    enrollment_open: Boolean(config.enrollment_open),
    passkeys_available: Boolean(config.passkeys_available),
  };
}

/** A closed passkey sheet surfaces as NotAllowedError; everything else from
 * `navigator.credentials` is a real failure worth showing as it is. */
function ceremonyError(error: unknown): Error {
  if (error instanceof DOMException && error.name === 'NotAllowedError') {
    return new PasskeyCancelledError();
  }
  return error instanceof Error ? error : new Error(String(error));
}

/* ------------------------------- sign-in --------------------------------- */

interface SignInChallenge {
  challenge_id: string;
  options: {
    publicKey: {
      challenge: string;
      allowCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
    } & Record<string, unknown>;
  };
}

/**
 * Run the sign-in ceremony. On success the broker set the session cookie;
 * the bridge's cached session is refreshed so the next mutation carries a
 * current CSRF secret.
 *
 * This is also the step-up gesture: with a live session the broker
 * re-stamps it instead of opening a second one.
 */
export async function signInWithPasskey(): Promise<void> {
  const { challenge_id, options } = await post('/v1/auth/signin/options', {}) as SignInChallenge;
  const publicKey = {
    ...options.publicKey,
    challenge: unb64url(options.publicKey.challenge),
    allowCredentials: (options.publicKey.allowCredentials ?? []).map((credential) => ({
      ...credential,
      id: unb64url(credential.id),
    })),
  } as PublicKeyCredentialRequestOptions;
  let assertion: PublicKeyCredential | null;
  try {
    assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
  } catch (error) {
    throw ceremonyError(error);
  }
  // A null resolution is the spec's other way of saying "no credential".
  if (!assertion) throw new PasskeyCancelledError();
  const response = assertion.response as AuthenticatorAssertionResponse;
  await post('/v1/auth/signin', {
    challenge_id,
    credential: {
      id: assertion.id,
      rawId: b64url(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: b64url(response.clientDataJSON),
        authenticatorData: b64url(response.authenticatorData),
        signature: b64url(response.signature),
        userHandle: response.userHandle ? b64url(response.userHandle) : null,
      },
      extensions: assertion.getClientExtensionResults(),
    },
  });
  await refreshSession();
}

/* ------------------------------ enrollment ------------------------------- */

interface RegisterChallenge {
  challenge_id: string;
  options: {
    publicKey: {
      challenge: string;
      user: { id: string } & Record<string, unknown>;
      excludeCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
    } & Record<string, unknown>;
  };
}

/** The transports webauthn-rs knows; anything newer is left out rather than
 * risked against its deserializer. */
const KNOWN_TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid']);

/**
 * Create and enroll a passkey.
 *
 * `secret` is the one-use enrollment secret `aka admin enroll` printed on
 * the broker host — the proof that whoever is enrolling has that machine.
 * A signed-in owner adding another passkey passes null; the session is the
 * authorization. Enrolling signs the browser in, same as the sign-in
 * ceremony would.
 */
export async function registerPasskey(secret: string | null, label: string | null): Promise<void> {
  const { challenge_id, options } = await post('/v1/auth/register/options', {
    enrollment_secret: secret,
    label,
  }) as RegisterChallenge;
  const publicKey = {
    ...options.publicKey,
    challenge: unb64url(options.publicKey.challenge),
    user: { ...options.publicKey.user, id: unb64url(options.publicKey.user.id) },
    excludeCredentials: (options.publicKey.excludeCredentials ?? []).map((credential) => ({
      ...credential,
      id: unb64url(credential.id),
    })),
    // The remaining fields (rp, pubKeyCredParams, …) ride the spread; the
    // wire type deliberately does not restate them.
  } as unknown as PublicKeyCredentialCreationOptions;
  let created: PublicKeyCredential | null;
  try {
    created = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
  } catch (error) {
    throw ceremonyError(error);
  }
  if (!created) throw new PasskeyCancelledError();
  const response = created.response as AuthenticatorAttestationResponse;
  const transports = (response.getTransports?.() ?? [])
    .filter((transport) => KNOWN_TRANSPORTS.has(transport));
  await post('/v1/auth/register', {
    challenge_id,
    credential: {
      id: created.id,
      rawId: b64url(created.rawId),
      type: created.type,
      response: {
        attestationObject: b64url(response.attestationObject),
        clientDataJSON: b64url(response.clientDataJSON),
        transports: transports.length ? transports : null,
      },
      extensions: created.getClientExtensionResults(),
    },
  });
  await refreshSession();
}
