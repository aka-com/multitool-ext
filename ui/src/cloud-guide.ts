/** Guided cloud setup: the smart paste, capture checklist, and provisioning
 * script behind the stepped AWS / GCP / Azure add flow.
 *
 * The paste parsers are deliberately forgiving about shape: they accept what
 * the provider consoles and CLIs actually emit — the IAM access-key CSV,
 * `export AWS_…` lines, credentials-file profiles, `aws iam create-access-key`
 * JSON, service-account JSON keys, `az ad sp create-for-rbac` output (plus
 * `az account show` pasted alongside) — and map whatever they find onto the
 * same ConnectionDraft fields the one-shot form edits, so the existing
 * cloud-setup build/validation path applies unchanged.
 */
import type { ConnectionDraft } from './app-state';
import { gcpProjectFromKey } from './cloud-setup';

export type CloudProvider = 'aws' | 'gcp' | 'azure';

const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const EXACT_GUID = new RegExp(`^${GUID.source}$`, 'i');

/** Tolerate several concatenated pretty-printed JSON objects, the shape a
 * terminal paste of `create-for-rbac` + `account show` actually has. Brace
 * counting ignores braces inside strings; none of the accepted formats put
 * braces in string values, and a miscount only means one candidate fails to
 * parse and is skipped. */
function jsonObjects(text: string): unknown[] {
  const objects: unknown[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '{') {
      if (!depth) start = i;
      depth += 1;
    } else if (ch === '}' && depth) {
      depth -= 1;
      if (!depth && start >= 0) {
        try {
          objects.push(JSON.parse(text.slice(start, i + 1)));
        } catch {
          // Not JSON after all; skip the candidate.
        }
        start = -1;
      }
    }
  }
  return objects;
}

function matchGroup(text: string, re: RegExp): string | undefined {
  const match = text.match(re);
  return match ? match[1].trim() : undefined;
}

export interface CloudPasteFields {
  access?: string;
  secret?: string;
  region?: string;
  keyJson?: string;
  project?: string;
  tenant?: string;
  client?: string;
  clientSecret?: string;
  subscription?: string;
}

export interface CloudPasteParse {
  fields: CloudPasteFields;
  /** What was recognized, in the user's language. */
  source: string;
}

function parseAwsPaste(text: string): CloudPasteParse | null {
  const fields: CloudPasteFields = {};
  let source: string | null = null;
  for (const value of jsonObjects(text)) {
    if (!value || typeof value !== 'object') continue;
    const object = value as Record<string, unknown>;
    // `aws iam create-access-key` nests under AccessKey; a --query projection
    // (like the one our provisioning script prints) is flat.
    const key = (object.AccessKey && typeof object.AccessKey === 'object'
      ? object.AccessKey
      : object) as Record<string, unknown>;
    if (typeof key.AccessKeyId === 'string' && typeof key.SecretAccessKey === 'string') {
      fields.access = key.AccessKeyId;
      fields.secret = key.SecretAccessKey;
      source = 'create-access-key output';
    }
    if (typeof key.AWS_ACCESS_KEY_ID === 'string' && typeof key.AWS_SECRET_ACCESS_KEY === 'string') {
      fields.access = key.AWS_ACCESS_KEY_ID;
      fields.secret = key.AWS_SECRET_ACCESS_KEY;
      source = 'the provisioning script’s output';
    }
  }
  if (!fields.access) {
    fields.access = matchGroup(text, /(?:AWS_ACCESS_KEY_ID|aws_access_key_id)\s*[=:]\s*["']?([A-Z0-9]{16,32})/i)
      ?? matchGroup(text, /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/);
    fields.secret = matchGroup(
      text,
      /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{30,64})/i,
    );
    if (fields.access) {
      source = /aws_access_key_id/i.test(text) ? 'credentials-file / env values' : 'an access key';
    }
  }
  // The console's access-key download: a CSV header line, then the values.
  // Read the columns off the header rather than assuming they lead the row —
  // the IAM user-creation CSV puts them third and fourth, behind the user
  // name and console password, and taking positions 0 and 1 there captures
  // that password as the secret key and shows a green tick for it.
  if (!fields.access || !fields.secret) {
    const rows = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const headerIndex = rows.findIndex((row) => /access key id\s*,/i.test(row)
      && /secret access key/i.test(row));
    if (headerIndex >= 0) {
      const header = rows[headerIndex].split(',').map((cell) => cell.trim().toLowerCase());
      const accessColumn = header.indexOf('access key id');
      const secretColumn = header.indexOf('secret access key');
      const values = (rows[headerIndex + 1] ?? '').split(',');
      const access = accessColumn >= 0 ? values[accessColumn]?.trim() : undefined;
      const secret = secretColumn >= 0 ? values[secretColumn]?.trim() : undefined;
      if (access && secret) {
        fields.access = access;
        fields.secret = secret;
        source = 'the console access-key CSV';
      }
    }
  }
  if (!fields.access && !fields.secret) return null;
  fields.region = matchGroup(
    text,
    /(?:AWS_(?:DEFAULT_)?REGION|^\s*region)\s*[=:]\s*["']?([a-z]{2,3}(?:-[a-z]+)+-\d)/im,
  );
  return { fields, source: source ?? 'an access key' };
}

function parseGcpPaste(text: string): CloudPasteParse | null {
  for (const value of jsonObjects(text)) {
    if (!value || typeof value !== 'object') continue;
    const object = value as Record<string, unknown>;
    if (object.type === 'service_account'
      && typeof object.client_email === 'string'
      && typeof object.private_key === 'string') {
      return {
        fields: {
          keyJson: JSON.stringify(value),
          project: typeof object.project_id === 'string' ? object.project_id : undefined,
        },
        source: `service-account key for ${object.client_email}`,
      };
    }
  }
  return null;
}

function parseAzurePaste(text: string): CloudPasteParse | null {
  const fields: CloudPasteFields = {};
  const sources: string[] = [];
  for (const value of jsonObjects(text)) {
    if (!value || typeof value !== 'object') continue;
    const object = value as Record<string, unknown>;
    const password = object.password ?? object.clientSecret;
    if (typeof object.appId === 'string' && typeof password === 'string') {
      fields.client = object.appId;
      fields.clientSecret = password;
      const tenant = object.tenant ?? object.tenantId;
      if (typeof tenant === 'string') fields.tenant = tenant;
      sources.push('create-for-rbac output');
    } else if (typeof object.id === 'string' && EXACT_GUID.test(object.id)
      && (typeof object.tenantId === 'string' || typeof object.environmentName === 'string')) {
      // `az account show`: subscription id plus the tenant it lives in. The
      // id must *be* a GUID, not merely contain one — an ARM resource id
      // like /subscriptions/<guid>/resourceGroups/x is not a subscription.
      fields.subscription = object.id;
      if (!fields.tenant && typeof object.tenantId === 'string') fields.tenant = object.tenantId;
      sources.push('account show output');
    }
  }
  if (!fields.client) {
    fields.tenant = fields.tenant
      ?? matchGroup(text, new RegExp('(?:AZURE_TENANT_ID|tenant)\\s*[=:]\\s*["\']?(' + GUID.source + ')', 'i'));
    fields.client = matchGroup(
      text,
      new RegExp('(?:AZURE_CLIENT_ID|appId|client)\\s*[=:]\\s*["\']?(' + GUID.source + ')', 'i'),
    );
    fields.clientSecret = matchGroup(text, /(?:AZURE_CLIENT_SECRET|password)\s*[=:]\s*["']?([^\s"',]{20,})/i);
    if (fields.client && !sources.length) sources.push('env-format values');
  }
  if (!fields.client && !fields.tenant && !fields.subscription) return null;
  return { fields, source: sources.join(' + ') || 'Azure values' };
}

export function parseCloudPaste(provider: CloudProvider, text: string): CloudPasteParse | null {
  if (!text.trim()) return null;
  if (provider === 'aws') return parseAwsPaste(text);
  if (provider === 'gcp') return parseGcpPaste(text);
  return parseAzurePaste(text);
}

export interface CloudPasteApplied {
  /** Recognition summary for the "Recognized: …" line; null = nothing usable. */
  source: string | null;
  /** sheetErrors keys whose fields the paste just filled. */
  clearedErrorKeys: string[];
}

/** Write whatever the paste contained onto the draft, switching the touched
 * credential slots to fresh values. Fields the paste did not name are left
 * alone, so a partial paste composes with typed fill-ins and prefills. */
export function applyCloudPaste(
  draft: ConnectionDraft,
  provider: CloudProvider,
  text: string,
): CloudPasteApplied {
  const parsed = parseCloudPaste(provider, text);
  if (!parsed) return { source: null, clearedErrorKeys: [] };
  const cleared: string[] = [];
  const sources = { ...(draft.cloudCredentialSources ?? {}) };
  const record = draft as Record<string, unknown>;
  const setCredential = (
    value: string | undefined,
    valueKey: string,
    refKey: string,
    credentialSlot: string,
    errorKey: string,
  ): void => {
    if (value === undefined) return;
    record[valueKey] = value;
    record[refKey] = null;
    sources[credentialSlot] = 'new';
    cleared.push(errorKey);
  };
  const setPlain = (value: string | undefined, key: string): void => {
    if (value === undefined) return;
    record[key] = value;
    cleared.push(key);
  };
  if (provider === 'aws') {
    setCredential(parsed.fields.access, 'cloudAccessKeyValue', 'cloudAccessKeyRef', 'awsAccessKey', 'cloudAccessKeyRef');
    setCredential(parsed.fields.secret, 'cloudSecretKeyValue', 'cloudSecretKeyRef', 'awsSecretKey', 'cloudSecretKeyRef');
    setPlain(parsed.fields.region, 'cloudRegion');
  } else if (provider === 'gcp') {
    setCredential(parsed.fields.keyJson, 'cloudGcpKeyValue', 'cloudGcpKeyRef', 'gcpKey', 'cloudGcpKeyRef');
    if (parsed.fields.keyJson && !(draft.cloudProject || '').trim()) {
      const project = gcpProjectFromKey(parsed.fields.keyJson);
      if (project) setPlain(project, 'cloudProject');
    }
  } else {
    setPlain(parsed.fields.tenant, 'cloudTenantId');
    setPlain(parsed.fields.client, 'cloudClientId');
    setCredential(
      parsed.fields.clientSecret,
      'cloudClientSecretValue', 'cloudClientSecretRef', 'azureClientSecret', 'cloudClientSecretRef',
    );
    setPlain(parsed.fields.subscription, 'cloudSubscriptionId');
  }
  draft.cloudCredentialSources = sources;
  return { source: parsed.source, clearedErrorKeys: cleared };
}

/* ---------------------------- capture checklist --------------------------- */

export interface CloudCaptureSlot {
  key: string;
  label: string;
  valueKey: keyof ConnectionDraft & string;
  /** Set when a saved credential can satisfy the slot (via the skip form). */
  refKey?: keyof ConnectionDraft & string;
  credentialSlot?: string;
  /** The build*CloudSetup error key this slot's validation lands on. */
  errorKey: string;
  /** Masked once captured; typed through a password input while missing. */
  secret: boolean;
  /** Rendered as a visible, always-editable input (region, IDs). */
  editable: boolean;
  placeholder: string;
}

export function cloudCaptureSlots(provider: CloudProvider): CloudCaptureSlot[] {
  if (provider === 'aws') {
    return [
      { key: 'aws-access', label: 'Access key ID', valueKey: 'cloudAccessKeyValue',
        refKey: 'cloudAccessKeyRef', credentialSlot: 'awsAccessKey', errorKey: 'cloudAccessKeyRef',
        secret: true, editable: false, placeholder: 'AKIA…' },
      { key: 'aws-secret', label: 'Secret access key', valueKey: 'cloudSecretKeyValue',
        refKey: 'cloudSecretKeyRef', credentialSlot: 'awsSecretKey', errorKey: 'cloudSecretKeyRef',
        secret: true, editable: false, placeholder: 'Paste or type the secret access key' },
      { key: 'aws-region', label: 'Region', valueKey: 'cloudRegion', errorKey: 'cloudRegion',
        secret: false, editable: true, placeholder: 'us-west-2' },
    ];
  }
  if (provider === 'gcp') {
    return [
      { key: 'gcp-key', label: 'Service-account key', valueKey: 'cloudGcpKeyValue',
        refKey: 'cloudGcpKeyRef', credentialSlot: 'gcpKey', errorKey: 'cloudGcpKeyRef',
        secret: true, editable: false, placeholder: 'Paste the JSON key above' },
      { key: 'gcp-project', label: 'Project ID', valueKey: 'cloudProject', errorKey: 'cloudProject',
        secret: false, editable: true, placeholder: 'my-production-project' },
    ];
  }
  return [
    { key: 'azure-tenant', label: 'Tenant ID', valueKey: 'cloudTenantId', errorKey: 'cloudTenantId',
      secret: false, editable: true, placeholder: '11111111-… or contoso.onmicrosoft.com' },
    { key: 'azure-client', label: 'Client ID', valueKey: 'cloudClientId', errorKey: 'cloudClientId',
      secret: false, editable: true, placeholder: '22222222-…' },
    { key: 'azure-secret', label: 'Client secret', valueKey: 'cloudClientSecretValue',
      refKey: 'cloudClientSecretRef', credentialSlot: 'azureClientSecret', errorKey: 'cloudClientSecretRef',
      secret: true, editable: false, placeholder: 'Paste or type the client secret value' },
    { key: 'azure-subscription', label: 'Subscription ID', valueKey: 'cloudSubscriptionId',
      errorKey: 'cloudSubscriptionId', secret: false, editable: true, placeholder: '33333333-…' },
  ];
}

export function cloudSlotPresent(draft: ConnectionDraft, slot: CloudCaptureSlot): boolean {
  if (slot.refKey && slot.credentialSlot
    && draft.cloudCredentialSources?.[slot.credentialSlot] === 'existing'
    && typeof draft[slot.refKey] === 'string' && draft[slot.refKey]) {
    return true;
  }
  return Boolean(String((draft[slot.valueKey] as string | undefined) ?? '').trim());
}

export function cloudCaptureComplete(draft: ConnectionDraft, provider: CloudProvider): boolean {
  return cloudCaptureSlots(provider).every((slot) => cloudSlotPresent(draft, slot));
}

/** Enough of a captured value to confirm it landed, never all of it. */
export function maskCredential(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return '••••';
  return `${v.slice(0, 4)}…${v.slice(-4)}`;
}

/** The stable, non-secret identity inside a captured service-account key. */
export function gcpKeyEmail(raw: string): string | null {
  try {
    const value = JSON.parse(raw) as unknown;
    const email = value && typeof value === 'object'
      ? (value as Record<string, unknown>).client_email
      : null;
    return typeof email === 'string' && email.trim() ? email.trim() : null;
  } catch {
    return null;
  }
}

/** Each provider's CLI and where its sign-in lives on disk, for the copy
 * that offers to reuse it. Only AWS is wired today; naming the others here
 * means adding one is a config change rather than a string hunt. */
export const PROVIDER_CLI: Record<CloudProvider, { command: string; config: string }> = {
  aws: { command: 'aws', config: '~/.aws' },
  gcp: { command: 'gcloud', config: '~/.config/gcloud' },
  azure: { command: 'az', config: '~/.azure' },
};

/* ------------------------ reuse a local AWS sign-in ------------------------ */

// The attenuation options live beside the builder that submits them
// (cloud-setup.ts), so the option shown checked and the ARN sent on save can
// never diverge; re-exported here with the rest of the reuse-path helpers.
export { AWS_ATTENUATIONS, awsAttenuation } from './cloud-setup';

export interface AwsProfileChoice {
  name: string;
  kind: 'keys' | 'temporary' | 'sso' | 'incomplete';
  region?: string | null;
}

/** Why a profile can't back a connection, or null when it can. Mirrors what
 * the broker enforces at mint time, so the picker refuses up front rather
 * than saving something that fails on first use. */
export function awsProfileBlocker(profile: AwsProfileChoice): string | null {
  if (profile.kind === 'sso') {
    return 'Signs in through IAM Identity Center — Multitool can’t read that cached session.';
  }
  if (profile.kind === 'incomplete') return 'No active aws access keys found.';
  return null;
}

export function awsProfileNote(profile: AwsProfileChoice): string | null {
  if (profile.kind === 'temporary') {
    return 'Temporary credentials: they expire with your local session, and minting needs a role to assume.';
  }
  return null;
}

/* --------------------------- shell commands -------------------------------- */

/** Quote one argument for the paste-ready POSIX shell commands shown in UI. */
export function shellArgument(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

/** The one command that hooks a saved cloud connection up to its CLI. The
 * single source for both the add flow's Connect step and the detail pane. */
export function cloudConnectCommand(provider: CloudProvider, name: string): string {
  return provider === 'aws'
    ? `aka cloud config ${shellArgument(name)}`
    : `eval "$(aka cloud env ${shellArgument(name)})"`;
}

/** A copy-ready first Azure call. Minted tokens don't sign in the Azure CLI
 * itself — they ride the Authorization header via `az rest` (or any HTTP
 * client) — so the hookup shows a working call instead of leaving the user
 * to discover that `az vm list` still wants its own login.
 *
 * The subscription rides inside a double-quoted shell string, where `$(…)`,
 * backticks, and `"` stay live. The guided flow validates it as a GUID
 * before save, but the core and CLI accept any string, so a connection
 * created elsewhere on a shared broker could carry shell in this field —
 * only an exact GUID is interpolated into the copyable command. */
export function azureRestExample(subscription?: string | null): string {
  const trimmed = (subscription ?? '').trim();
  const url = EXACT_GUID.test(trimmed)
    ? `https://management.azure.com/subscriptions/${trimmed}/resourceGroups?api-version=2021-04-01`
    : 'https://management.azure.com/subscriptions?api-version=2022-12-01';
  return `az rest --url "${url}" \\\n  --headers "Authorization=Bearer $AZURE_ACCESS_TOKEN"`;
}

/** A recognizable, provider-legal identity name derived from the connection
 * name, so two connections do not silently share one cloud identity. GCP
 * service-account ids are the tightest constraint (6–30 chars, lowercase
 * letters/digits/hyphens, starting with a letter), so every provider gets
 * that shape. */
export function cloudAgentName(connectionName: string | undefined): string {
  const slug = String(connectionName ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 20)
    .replace(/-+$/, '');
  return slug ? `multitool-${slug}` : 'multitool-agent';
}

/* --------------------------- provisioning script -------------------------- */

export const CLOUD_ACCESS_LEVELS: Record<CloudProvider, Array<[string, string]>> = {
  aws: [
    ['ReadOnlyAccess', 'Read-only'],
    ['PowerUserAccess', 'Power user (no IAM)'],
    ['AdministratorAccess', 'Administrator'],
  ],
  gcp: [
    ['roles/viewer', 'Viewer (read-only)'],
    ['roles/editor', 'Editor'],
    ['roles/owner', 'Owner'],
  ],
  azure: [
    ['Reader', 'Reader'],
    ['Contributor', 'Contributor'],
    ['Owner', 'Owner'],
  ],
};

export function defaultCloudAccessLevel(provider: CloudProvider): string {
  return CLOUD_ACCESS_LEVELS[provider][0][0];
}

/** The ready-made Cloud Shell commands for the "Run a script" path: create a
 * dedicated identity (named for this connection) at the chosen access level
 * and print exactly the blob the capture step's parsers accept. */
export function cloudProvisionScript(
  provider: CloudProvider,
  role: string,
  agent = 'multitool-agent',
): string {
  if (provider === 'aws') {
    return `aws iam create-user --user-name ${agent}\n`
      + `aws iam attach-user-policy --user-name ${agent} \\\n`
      + `  --policy-arn arn:aws:iam::aws:policy/${role}\n`
      + `aws iam create-access-key --user-name ${agent} \\\n`
      + '  --query \'AccessKey.{AWS_ACCESS_KEY_ID:AccessKeyId,AWS_SECRET_ACCESS_KEY:SecretAccessKey}\'';
  }
  if (provider === 'gcp') {
    return `gcloud iam service-accounts create ${agent}\n`
      + 'gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \\\n'
      + `  --member serviceAccount:${agent}@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com \\\n`
      + `  --role ${role}\n`
      + 'gcloud iam service-accounts keys create /dev/stdout \\\n'
      + `  --iam-account ${agent}@$GOOGLE_CLOUD_PROJECT.iam.gserviceaccount.com`;
  }
  return `az ad sp create-for-rbac --name ${agent} --role ${role} \\\n`
    + '  --scopes /subscriptions/$(az account show --query id -o tsv)\n'
    + 'az account show';
}

/** The console walkthrough's starter policy: what it grants as the label,
 * the JSON one disclosure away. */
export const AWS_GUIDE_POLICY = {
  label: 'S3 + EC2 + CloudWatch, read-only',
  json: [
    '{',
    '  "Version": "2012-10-17",',
    '  "Statement": [{',
    '    "Effect": "Allow",',
    '    "Action": ["s3:Get*", "s3:List*", "ec2:Describe*", "cloudwatch:Get*"],',
    '    "Resource": "*"',
    '  }]',
    '}',
  ].join('\n'),
};
