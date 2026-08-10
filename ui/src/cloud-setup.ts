import type { ConnectionDraft } from './app-state';
import type { CloudInfo, ConnectionInput } from './types';

export const CLOUD_NEW_CREDENTIAL = '__cloud_new__';
export const CLOUD_NO_CREDENTIAL = '__cloud_none__';

/** Quote one argument for the paste-ready POSIX shell commands shown in UI. */
function shellArgument(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

/**
 * The one command that points a stock cloud CLI at this connection.
 *
 * AWS gets a shared-config profile because the AWS CLI supports
 * `credential_process`: written once, it re-mints on demand. Azure and GCP
 * have no such hook, so their tokens arrive as shell exports that have to be
 * re-run before expiry. Both the tool's detail panel and the Connect-agents
 * walkthrough render this, so it lives here rather than in either of them.
 */
export function cloudSetupCommand(connection: { name: string; cloud?: CloudInfo | null }): string {
  const name = shellArgument(connection.name);
  return connection.cloud?.provider === 'aws'
    ? `aka cloud config ${name}`
    : `eval "$(aka cloud env ${name})"`;
}

/** The CLI this connection's minted session is for, named as its vendor does. */
export function cloudCliLabel(provider: CloudInfo['provider']): string {
  return provider === 'aws' ? 'the AWS CLI'
    : provider === 'gcp' ? 'gcloud'
    : 'az rest';
}

/** How much of a reused sign-in agents get. The leash is a real STS
 * parameter — a session policy on GetFederationToken / AssumeRole — so AWS
 * enforces it, not the broker: an administrator profile can safely back a
 * read-only connection. Lives beside the builder that submits it, so the
 * option shown checked and the ARN sent on save can never diverge. */
export const AWS_ATTENUATIONS: Array<{
  id: string;
  label: string;
  detail: string;
  policyArn: string | null;
}> = [
  {
    id: 'read',
    label: 'Read-only',
    detail: 'Sessions are bounded by the ReadOnlyAccess policy, whatever the profile can do.',
    policyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess',
  },
  {
    id: 'power',
    label: 'Power user (no IAM)',
    detail: 'Everything except IAM, Organizations, and account settings.',
    policyArn: 'arn:aws:iam::aws:policy/PowerUserAccess',
  },
  {
    id: 'full',
    label: 'Everything the profile can do',
    detail: 'No session policy. Agents inherit the profile’s full access.',
    policyArn: null,
  },
];

export function awsAttenuation(id: string | undefined): typeof AWS_ATTENUATIONS[number] {
  return AWS_ATTENUATIONS.find((option) => option.id === id) ?? AWS_ATTENUATIONS[0];
}

export type CloudCredentialSlot =
  | 'awsAccessKey'
  | 'awsSecretKey'
  | 'awsSessionToken'
  | 'gcpKey'
  | 'azureClientSecret';

export function cloudCredentialSource(
  draft: ConnectionDraft,
  slot: CloudCredentialSlot,
  optional = false,
): 'existing' | 'new' | 'none' {
  return draft.cloudCredentialSources?.[slot] ?? (optional ? 'none' : 'new');
}

function credentialName(connectionName: string, suffix: string, reserved: Set<string>): string {
  const stem = String(connectionName || 'CLOUD')
    .toUpperCase()
    .replace(/[^A-Z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'CLOUD';
  const prefix = `MULTITOOL_${stem}`;
  for (let number = 1; ; number += 1) {
    const tail = `${suffix}${number === 1 ? '' : `_${number}`}`;
    const candidate = `${prefix.slice(0, 63 - tail.length)}_${tail}`;
    if (!reserved.has(candidate)) {
      reserved.add(candidate);
      return candidate;
    }
  }
}

interface CredentialResult {
  ref: string | null;
  pending: { name: string; value: string } | null;
}

function credential(
  draft: ConnectionDraft,
  slot: CloudCredentialSlot,
  ref: string | null | undefined,
  value: string | undefined,
  suffix: string,
  errorKey: string,
  errors: Record<string, string>,
  reserved: Set<string>,
  optional = false,
): CredentialResult {
  const source = cloudCredentialSource(draft, slot, optional);
  if (source === 'none') {
    if (!optional) errors[errorKey] = 'Provide or choose a credential.';
    return { ref: null, pending: null };
  }
  if (source === 'existing') {
    if (!ref) errors[errorKey] = 'Choose a saved credential.';
    return { ref: ref || null, pending: null };
  }
  if (!value) {
    errors[errorKey] = 'Credential value is required.';
    return { ref: null, pending: null };
  }
  const name = credentialName(draft.name ?? '', suffix, reserved);
  return { ref: name, pending: { name, value } };
}

export interface CloudSetupBuild {
  errors: Record<string, string>;
  input: Partial<ConnectionInput>;
  newSecrets: Array<{ name: string; value: string }>;
}

interface GcpServiceAccountKey {
  type?: unknown;
  project_id?: unknown;
  client_email?: unknown;
  private_key?: unknown;
  token_uri?: unknown;
}

function parseGcpServiceAccountKey(raw: string): GcpServiceAccountKey | null {
  try {
    const value = JSON.parse(raw) as unknown;
    return value && typeof value === 'object' ? value as GcpServiceAccountKey : null;
  } catch {
    return null;
  }
}

export function gcpProjectFromKey(raw: string): string | null {
  const project = parseGcpServiceAccountKey(raw)?.project_id;
  return typeof project === 'string' && project.trim() ? project.trim() : null;
}

export function buildAwsCloudSetup(
  draft: ConnectionDraft,
  existingSecretNames: string[],
): CloudSetupBuild {
  const errors: Record<string, string> = {};
  const reserved = new Set(existingSecretNames);
  const access = credential(
    draft,
    'awsAccessKey',
    draft.cloudAccessKeyRef,
    draft.cloudAccessKeyValue,
    'AWS_ACCESS_KEY_ID',
    'cloudAccessKeyRef',
    errors,
    reserved,
  );
  const secret = credential(
    draft,
    'awsSecretKey',
    draft.cloudSecretKeyRef,
    draft.cloudSecretKeyValue,
    'AWS_SECRET_ACCESS_KEY',
    'cloudSecretKeyRef',
    errors,
    reserved,
  );
  const sessionToken = credential(
    draft,
    'awsSessionToken',
    draft.cloudSessionTokenRef,
    draft.cloudSessionTokenValue,
    'AWS_SESSION_TOKEN',
    'cloudSessionTokenRef',
    errors,
    reserved,
    true,
  );
  const region = (draft.cloudRegion || '').trim();
  const roleArn = (draft.cloudRoleArn || '').trim();
  const externalId = (draft.cloudExternalId || '').trim();
  if (!region) errors.cloudRegion = 'Enter the AWS region.';
  else if (!/^[a-z]{2,3}(-[a-z]+)+-\d$/.test(region)) {
    errors.cloudRegion = 'Enter an AWS region like us-west-2.';
  }
  if (externalId && !roleArn) errors.cloudExternalId = 'External ID requires a role ARN.';
  if (sessionToken.ref && !roleArn) {
    errors.cloudSessionTokenRef = 'A source session token requires a role ARN.';
  }
  const ttl = Number(draft.cloudSessionTtl || '900');
  if (![900, 1800, 3600].includes(ttl)) {
    errors.cloudSessionTtl = 'Choose 15, 30, or 60 minutes.';
  }
  const newSecrets = [access.pending, secret.pending, sessionToken.pending]
    .filter((pending): pending is { name: string; value: string } => pending !== null);
  return {
    errors,
    input: {
      cloud_provider: 'aws',
      cloud_region: region,
      cloud_access_key_ref: access.ref,
      cloud_secret_key_ref: secret.ref,
      cloud_session_token_ref: sessionToken.ref,
      cloud_role_arn: roleArn || null,
      cloud_external_id: externalId || null,
      cloud_session_ttl: ttl,
    },
    newSecrets,
  };
}

/** A reuse connection: no credential is created or bound, so the build is
 * just the profile, the leash, and the optional role. */
export function buildAwsProfileCloudSetup(draft: ConnectionDraft): CloudSetupBuild {
  const errors: Record<string, string> = {};
  const profile = (draft.cloudSourceProfile || '').trim();
  const roleArn = (draft.cloudRoleArn || '').trim();
  const externalId = (draft.cloudExternalId || '').trim();
  if (!profile) errors.cloudSourceProfile = 'Choose one of your AWS profiles.';
  // Without the machine stamp the broker cannot tell whose ~/.aws this is,
  // and fails closed at mint time. Refuse to save something that shape.
  if (profile && !(draft.cloudSourceOrigin || '').trim()) {
    errors.cloudSourceProfile = 'Could not identify this machine; reopen the picker.';
  }
  if (externalId && !roleArn) errors.cloudExternalId = 'External ID requires a role ARN.';
  const ttl = Number(draft.cloudSessionTtl || '900');
  if (![900, 1800, 3600].includes(ttl)) {
    errors.cloudSessionTtl = 'Choose 15, 30, or 60 minutes.';
  }
  return {
    errors,
    input: {
      cloud_provider: 'aws',
      cloud_source_profile: profile,
      cloud_source_origin: draft.cloudSourceOrigin || null,
      cloud_source_origin_label: draft.cloudSourceOriginLabel || null,
      // Always blank — "use whatever region the profile names" at mint time.
      // The guided reuse flow renders no region field, so draft.cloudRegion
      // only ever holds the capture path's us-east-1 prefill; reading it
      // here would silently pin every reuse connection to that default.
      cloud_region: null,
      cloud_role_arn: roleArn || null,
      cloud_external_id: externalId || null,
      // Derived from the attenuation choice, never a separate field: the
      // preselected "Read-only" radio never fires onChange, so a field only
      // written there would submit the unbounded shape for the default.
      cloud_session_policy_arn: awsAttenuation(draft.cloudAttenuation).policyArn,
      cloud_session_ttl: ttl,
    },
    newSecrets: [],
  };
}

export function buildGcpCloudSetup(
  draft: ConnectionDraft,
  existingSecretNames: string[],
): CloudSetupBuild {
  const errors: Record<string, string> = {};
  const reserved = new Set(existingSecretNames);
  const key = credential(
    draft,
    'gcpKey',
    draft.cloudGcpKeyRef,
    draft.cloudGcpKeyValue,
    'GCP_SERVICE_ACCOUNT_JSON',
    'cloudGcpKeyRef',
    errors,
    reserved,
  );
  if (cloudCredentialSource(draft, 'gcpKey') === 'new' && draft.cloudGcpKeyValue) {
    const parsed = parseGcpServiceAccountKey(draft.cloudGcpKeyValue);
    if (!parsed
      || parsed.type !== 'service_account'
      || typeof parsed.client_email !== 'string'
      || typeof parsed.private_key !== 'string'
      || !/BEGIN (RSA )?PRIVATE KEY/.test(parsed.private_key)) {
      errors.cloudGcpKeyRef = 'Choose a Google service-account JSON key file.';
    }
  }
  const project = (draft.cloudProject || '').trim()
    || gcpProjectFromKey(draft.cloudGcpKeyValue || '') || '';
  const scope = (draft.cloudScope
    || 'https://www.googleapis.com/auth/cloud-platform').trim();
  if (!project) errors.cloudProject = 'Enter the Google Cloud project ID.';
  else if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(project)) {
    errors.cloudProject = 'Project IDs are 6–30 lowercase letters, digits, and hyphens.';
  }
  if (!scope) errors.cloudScope = 'Enter at least one OAuth scope.';
  return {
    errors,
    input: {
      cloud_provider: 'gcp',
      cloud_gcp_key_ref: key.ref,
      cloud_project: project,
      cloud_scope: scope,
      // Service-account OAuth tokens are provider-controlled one-hour tokens.
      cloud_session_ttl: 3600,
    },
    newSecrets: key.pending ? [key.pending] : [],
  };
}

const AZURE_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function buildAzureCloudSetup(
  draft: ConnectionDraft,
  existingSecretNames: string[],
): CloudSetupBuild {
  const errors: Record<string, string> = {};
  const reserved = new Set(existingSecretNames);
  const secret = credential(
    draft,
    'azureClientSecret',
    draft.cloudClientSecretRef,
    draft.cloudClientSecretValue,
    'AZURE_CLIENT_SECRET',
    'cloudClientSecretRef',
    errors,
    reserved,
  );
  const tenant = (draft.cloudTenantId || '').trim();
  const client = (draft.cloudClientId || '').trim();
  const subscription = (draft.cloudSubscriptionId || '').trim();
  const scope = (draft.cloudScope || 'https://management.azure.com/.default').trim();
  if (!tenant) errors.cloudTenantId = 'Enter the Entra tenant ID or domain.';
  if (!client) errors.cloudClientId = 'Enter the application (client) ID.';
  else if (!AZURE_GUID.test(client)) {
    errors.cloudClientId = 'The application (client) ID is a GUID like 22222222-2222-….';
  }
  if (!subscription) errors.cloudSubscriptionId = 'Enter the Azure subscription ID.';
  else if (!AZURE_GUID.test(subscription)) {
    errors.cloudSubscriptionId = 'The subscription ID is a GUID like 33333333-3333-….';
  }
  if (!scope) errors.cloudScope = 'Enter the OAuth scope for minted tokens.';
  return {
    errors,
    input: {
      cloud_provider: 'azure',
      cloud_tenant_id: tenant,
      cloud_client_id: client,
      cloud_client_secret_ref: secret.ref,
      cloud_subscription_id: subscription,
      cloud_scope: scope,
      // Entra client-credential tokens are provider-controlled one-hour tokens.
      cloud_session_ttl: 3600,
    },
    newSecrets: secret.pending ? [secret.pending] : [],
  };
}
