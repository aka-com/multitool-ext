// A TypeScript port of the desktop shell's `ConnectionInput::into_spec`
// (src-tauri/src/commands.rs).
//
// On the desktop, the webview hands a flat `ConnectionInput` to a Rust command
// that decomposes it into the `ConnectionSpec` the broker's manage API wants.
// The web app has no Rust command in front of the broker, so it must do that
// same shaping itself before POSTing to `/v1/manage/connections`. This module
// is that transform, kept deliberately faithful to the Rust so the two agree
// field-for-field — which `ui/tests/connection-spec.test.ts` checks against a
// golden produced by the real `into_spec` (see that file's header to run it).
//
// Scope: this is `into_spec` only — the pure `ConnectionInput -> ConnectionSpec`
// shaping. Secret decomposition (new_secret / new_secrets) and the SSH-key
// handling that needs native crypto live in `commands.ts` around this, and the
// SSH raw-key path stays desktop-only.

import type { ConnectionInput } from './types';

/** The broker's `ConnectionSpec` as JSON: name, a tagged config, bound secrets. */
export interface ConnectionSpec {
  name: string;
  config: Record<string, unknown>;
  secrets: string[];
}

/** Mirrors the Rust `FormResult<ConnectionSpec>`: a spec, or a form error whose
 * `code` matches what `into_spec` returns (so a rejection reads the same on both
 * hosts instead of arriving as an opaque 400). */
export type IntoSpecResult =
  | { ok: true; spec: ConnectionSpec }
  | { ok: false; code: string; field?: string; message: string };

/** Trim, treating blank as absent — the counterpart of Rust `present`. */
function present(value: string | null | undefined): string | undefined {
  if (value == null) return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function err(code: string, field: string, message: string): IntoSpecResult {
  return { ok: false, code, field, message };
}

/** `cloud_required`: a present cloud field, or a `cloud_field_required` error. */
function cloudRequired(
  value: string | null | undefined,
  field: string,
  message: string,
): { ok: true; value: string } | { ok: false; result: IntoSpecResult } {
  const present_ = present(value);
  if (present_ === undefined) {
    return { ok: false, result: err('cloud_field_required', field, message) };
  }
  return { ok: true, value: present_ };
}

// Session-lifetime bounds, mirroring aka-core's DEFAULT/MIN/MAX constants.
const DEFAULT_CLOUD_SESSION_TTL_SECS = 900;
const MIN_CLOUD_SESSION_TTL_SECS = 900;
const MAX_CLOUD_SESSION_TTL_SECS = 3600;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** Only set a key when the value is present — serde's `skip_serializing_if`. */
function setSome(target: Record<string, unknown>, key: string, value: string | undefined): void {
  if (value !== undefined) target[key] = value;
}

/**
 * Build the `SignerSpec` for an API connection, or `undefined`.
 *
 * SigV4 wins when its four parts are all present; otherwise a GCP
 * service-account signer when both of its parts are; otherwise none.
 */
function buildSigner(input: ConnectionInput): Record<string, unknown> | undefined {
  const region = present(input.signer_region);
  const service = present(input.signer_service);
  const accessKeyRef = present(input.signer_access_key_ref);
  const secretKeyRef = present(input.signer_secret_key_ref);
  if (region && service && accessKeyRef && secretKeyRef) {
    const signer: Record<string, unknown> = {
      algorithm: 'aws_sigv4',
      region,
      service,
      access_key_ref: accessKeyRef,
      secret_key_ref: secretKeyRef,
    };
    setSome(signer, 'session_token_ref', present(input.signer_session_token_ref));
    return signer;
  }
  const gcpKeyRef = present(input.signer_gcp_key_ref);
  const gcpScope = present(input.signer_gcp_scope);
  if (gcpKeyRef && gcpScope) {
    return { algorithm: 'gcp_service_account', key_ref: gcpKeyRef, scope: gcpScope };
  }
  return undefined;
}

/** The `provider`-tagged cloud config body, or a form error. */
function buildCloud(input: ConnectionInput): { ok: true; config: Record<string, unknown> } | { ok: false; result: IntoSpecResult } {
  const provider = cloudRequired(input.cloud_provider, 'cloudProvider', 'Choose a cloud provider');
  if (!provider.ok) return provider;

  const ttl = input.cloud_session_ttl ?? DEFAULT_CLOUD_SESSION_TTL_SECS;
  if (ttl < MIN_CLOUD_SESSION_TTL_SECS || ttl > MAX_CLOUD_SESSION_TTL_SECS) {
    return {
      ok: false,
      result: err('invalid_cloud_session_ttl', 'cloudSessionTtl', 'Choose a session lifetime from 15 to 60 minutes'),
    };
  }

  const config: Record<string, unknown> = { kind: 'cloud' };
  const sourceProfile = present(input.cloud_source_profile);

  if (provider.value === 'aws' && sourceProfile !== undefined) {
    // Reuse an existing ~/.aws sign-in: nothing is vaulted.
    config.provider = 'aws_profile';
    setSome(config, 'region', present(input.cloud_region));
    config.profile = sourceProfile;
    config.origin = present(input.cloud_source_origin) ?? '';
    setSome(config, 'origin_label', present(input.cloud_source_origin_label));
    setSome(config, 'role_arn', present(input.cloud_role_arn));
    setSome(config, 'external_id', present(input.cloud_external_id));
    setSome(config, 'session_policy_arn', present(input.cloud_session_policy_arn));
    setSome(config, 'session_policy', present(input.cloud_session_policy));
    config.session_ttl_secs = ttl;
    return { ok: true, config };
  }

  switch (provider.value) {
    case 'aws': {
      const region = cloudRequired(input.cloud_region, 'cloudRegion', 'Enter the AWS region');
      if (!region.ok) return region;
      const accessKeyRef = cloudRequired(input.cloud_access_key_ref, 'cloudAccessKeyRef', 'Provide or choose an access key ID');
      if (!accessKeyRef.ok) return accessKeyRef;
      const secretKeyRef = cloudRequired(input.cloud_secret_key_ref, 'cloudSecretKeyRef', 'Provide or choose a secret access key');
      if (!secretKeyRef.ok) return secretKeyRef;
      config.provider = 'aws';
      config.region = region.value;
      config.access_key_ref = accessKeyRef.value;
      config.secret_key_ref = secretKeyRef.value;
      setSome(config, 'session_token_ref', present(input.cloud_session_token_ref));
      setSome(config, 'role_arn', present(input.cloud_role_arn));
      setSome(config, 'external_id', present(input.cloud_external_id));
      config.session_ttl_secs = ttl;
      return { ok: true, config };
    }
    case 'gcp': {
      const keyRef = cloudRequired(input.cloud_gcp_key_ref, 'cloudGcpKeyRef', 'Provide or choose a service-account JSON key');
      if (!keyRef.ok) return keyRef;
      config.provider = 'gcp';
      config.key_ref = keyRef.value;
      config.scope = present(input.cloud_scope) ?? 'https://www.googleapis.com/auth/cloud-platform';
      setSome(config, 'project', present(input.cloud_project));
      config.session_ttl_secs = ttl;
      return { ok: true, config };
    }
    case 'azure': {
      const tenantId = cloudRequired(input.cloud_tenant_id, 'cloudTenantId', 'Enter the tenant ID');
      if (!tenantId.ok) return tenantId;
      const clientId = cloudRequired(input.cloud_client_id, 'cloudClientId', 'Enter the application client ID');
      if (!clientId.ok) return clientId;
      const clientSecretRef = cloudRequired(input.cloud_client_secret_ref, 'cloudClientSecretRef', 'Provide or choose a client secret');
      if (!clientSecretRef.ok) return clientSecretRef;
      config.provider = 'azure';
      config.tenant_id = tenantId.value;
      config.client_id = clientId.value;
      config.client_secret_ref = clientSecretRef.value;
      setSome(config, 'subscription_id', present(input.cloud_subscription_id));
      config.scope = present(input.cloud_scope) ?? 'https://management.azure.com/.default';
      config.session_ttl_secs = ttl;
      return { ok: true, config };
    }
    default:
      return { ok: false, result: err('invalid_cloud_provider', 'cloudProvider', 'Choose AWS, Google Cloud, or Azure') };
  }
}

/** The faithful port of `ConnectionInput::into_spec`. */
export function intoSpec(input: ConnectionInput): IntoSpecResult {
  const signer = buildSigner(input);
  const clientCertPath = present(input.client_cert_path);
  const clientKeyPath = present(input.client_key_path);

  let config: Record<string, unknown>;
  switch (input.type) {
    case 'api': {
      const api: Record<string, unknown> = {
        kind: 'api',
        host: input.host ?? '',
        // Rust: `unwrap_or_else(https)` — a present-but-empty scheme stays "".
        scheme: input.scheme ?? 'https',
        // Rust `port: self.port` passes the Option straight through: null when
        // absent, so serde emits `"port": null` rather than omitting it.
        port: input.port ?? null,
        template: input.template ?? '',
      };
      setSome(api, 'trusted_ca_bundle_path', present(input.trusted_ca_bundle_path));
      setSome(api, 'mcp_path', present(input.mcp_path));
      setSome(api, 'test_path', present(input.test_path));
      // OAuth is present only when all three coordinates are (a present-but-
      // empty string counts as present, matching the Rust `Some(_)` match).
      if (input.oauth_auth_url != null && input.oauth_token_url != null && input.oauth_client_id != null) {
        const oauth: Record<string, unknown> = {
          auth_url: input.oauth_auth_url.trim(),
          token_url: input.oauth_token_url.trim(),
          client_id: input.oauth_client_id.trim(),
          scopes: input.oauth_scopes ?? [],
        };
        const extra = input.oauth_extra_params ?? [];
        if (extra.length) oauth.extra_auth_params = extra;
        api.oauth = oauth;
      }
      if (signer !== undefined) api.signer = signer;
      setSome(api, 'client_cert_path', clientCertPath);
      setSome(api, 'client_key_path', clientKeyPath);
      config = api;
      break;
    }
    case 'pg': {
      config = {
        kind: 'pg',
        host: input.host ?? '',
        port: input.port ?? 5432,
        dbname: input.dbname ?? '',
        user: input.user ?? '',
        // Rust maps None -> VerifyFull; a supplied mode is passed verbatim.
        sslmode: present(input.sslmode) ?? 'verify-full',
      };
      setSome(config, 'trusted_ca_bundle_path', present(input.trusted_ca_bundle_path));
      break;
    }
    case 'ssh': {
      const ssh: Record<string, unknown> = {
        kind: 'ssh',
        host: input.host ?? '',
        port: input.port ?? 22,
        user: input.user ?? '',
        host_key_fingerprint: input.host_key_fingerprint ?? '',
      };
      // Rust `filter(|v| !v.is_empty())`: kept when non-empty, not trimmed.
      if (input.destination != null && input.destination !== '') {
        ssh.destination = input.destination;
      }
      config = ssh;
      break;
    }
    case 'cloud': {
      const cloud = buildCloud(input);
      if (!cloud.ok) return cloud.result;
      config = cloud.config;
      break;
    }
    default:
      return { ok: false, code: 'unknown_connection_type', message: `unknown connection type ${JSON.stringify(input.type)}` };
  }

  // The single bound secret (pg/ssh). An unparseable id is a form error, the
  // same one the Rust returns.
  const secrets: string[] = [];
  if (input.secret_id != null) {
    if (!UUID_RE.test(input.secret_id)) {
      return err('secret_not_found', 'secret', 'This credential no longer exists; choose another');
    }
    secrets.push(input.secret_id);
  }

  return { ok: true, spec: { name: input.name, config, secrets } };
}

/** A client-side rejection shaped like the broker's `FormError`, so the web
 * app surfaces an invalid draft the same way a 400 from the broker would. */
export class ConnectionSpecError extends Error {
  readonly formError: { kind: string; code: string; field?: string; message: string };
  constructor(code: string, message: string, field?: string) {
    super(message);
    this.name = 'ConnectionSpecError';
    this.formError = field
      ? { kind: 'validation', code, field, message }
      : { kind: 'global', code, message };
  }
}

/** Run [`intoSpec`] and return the spec, or throw a [`ConnectionSpecError`]. */
export function specForRequest(input: ConnectionInput): ConnectionSpec {
  const result = intoSpec(input);
  if (!result.ok) throw new ConnectionSpecError(result.code, result.message, result.field);
  return result.spec;
}
