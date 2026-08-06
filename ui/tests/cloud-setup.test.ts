import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildAwsCloudSetup, buildAzureCloudSetup, buildGcpCloudSetup, gcpProjectFromKey,
} from '../src/cloud-setup';
import type { ConnectionDraft } from '../src/app-state';

function awsDraft(overrides: ConnectionDraft = {}): ConnectionDraft {
  return {
    name: 'Production AWS',
    cloudProvider: 'aws',
    cloudRegion: 'us-west-2',
    cloudSessionTtl: '900',
    cloudCredentialSources: { awsAccessKey: 'new', awsSecretKey: 'new' },
    cloudAccessKeyValue: 'AKIAEXAMPLE',
    cloudSecretKeyValue: 'very-secret',
    ...overrides,
  };
}

test('AWS setup turns pasted values into atomic write-only credentials', () => {
  const built = buildAwsCloudSetup(awsDraft(), []);
  assert.deepEqual(built.errors, {});
  assert.deepEqual(built.newSecrets, [
    { name: 'MULTITOOL_PRODUCTION_AWS_AWS_ACCESS_KEY_ID', value: 'AKIAEXAMPLE' },
    { name: 'MULTITOOL_PRODUCTION_AWS_AWS_SECRET_ACCESS_KEY', value: 'very-secret' },
  ]);
  assert.equal(built.input.cloud_access_key_ref, built.newSecrets[0].name);
  assert.equal(built.input.cloud_secret_key_ref, built.newSecrets[1].name);
  assert.equal('cloud_access_key_value' in built.input, false);
});

test('AWS setup can bind existing credentials without rewriting them', () => {
  const built = buildAwsCloudSetup(awsDraft({
    cloudCredentialSources: { awsAccessKey: 'existing', awsSecretKey: 'existing' },
    cloudAccessKeyRef: 'TEAM_AWS_ACCESS_KEY_ID',
    cloudSecretKeyRef: 'TEAM_AWS_SECRET_ACCESS_KEY',
    cloudAccessKeyValue: '',
    cloudSecretKeyValue: '',
  }), ['TEAM_AWS_ACCESS_KEY_ID', 'TEAM_AWS_SECRET_ACCESS_KEY']);
  assert.deepEqual(built.errors, {});
  assert.deepEqual(built.newSecrets, []);
  assert.equal(built.input.cloud_access_key_ref, 'TEAM_AWS_ACCESS_KEY_ID');
  assert.equal(built.input.cloud_secret_key_ref, 'TEAM_AWS_SECRET_ACCESS_KEY');
});

test('AWS role-only inputs are rejected without a role ARN', () => {
  const external = buildAwsCloudSetup(awsDraft({ cloudExternalId: 'customer-123' }), []);
  assert.match(external.errors.cloudExternalId, /role ARN/);

  const session = buildAwsCloudSetup(awsDraft({
    cloudCredentialSources: {
      awsAccessKey: 'new', awsSecretKey: 'new', awsSessionToken: 'new',
    },
    cloudSessionTokenValue: 'source-session-token',
  }), []);
  assert.match(session.errors.cloudSessionTokenRef, /role ARN/);
});

test('generated AWS credential names avoid collisions and stay within vault limits', () => {
  const collision = 'MULTITOOL_A_VERY_LONG_CONNECTION_NAME_THAT_WILL_BE_TRUNCATED_BE_AWS_ACCESS_KEY_ID';
  const built = buildAwsCloudSetup(awsDraft({
    name: 'A very long connection name that will be truncated before the credential suffix',
  }), [collision]);
  assert.ok(built.newSecrets.every(({ name }) => name.length <= 64));
  assert.equal(new Set(built.newSecrets.map(({ name }) => name)).size, 2);
  assert.ok(built.newSecrets.every(({ name }) => name !== collision));
});

test('AWS setup rejects region values that are not region-shaped', () => {
  for (const region of ['us-west', 'US-WEST-2', 'us west 2', 'sts.amazonaws.com']) {
    const built = buildAwsCloudSetup(awsDraft({ cloudRegion: region }), []);
    assert.match(built.errors.cloudRegion ?? '', /us-west-2/, region);
  }
  for (const region of ['us-west-2', 'ap-southeast-3', 'us-gov-west-1', 'il-central-1']) {
    const built = buildAwsCloudSetup(awsDraft({ cloudRegion: region }), []);
    assert.deepEqual(built.errors, {}, region);
  }
});

const GCP_KEY = JSON.stringify({
  type: 'service_account',
  project_id: 'production-project',
  client_email: 'multitool@production-project.iam.gserviceaccount.com',
  private_key: '-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----\n',
  token_uri: 'https://oauth2.googleapis.com/token',
});

test('GCP setup validates a pasted service-account key and derives its project', () => {
  const built = buildGcpCloudSetup({
    name: 'Production GCP',
    cloudCredentialSources: { gcpKey: 'new' },
    cloudGcpKeyValue: GCP_KEY,
    cloudScope: 'https://www.googleapis.com/auth/cloud-platform',
  }, []);
  assert.deepEqual(built.errors, {});
  assert.equal(gcpProjectFromKey(GCP_KEY), 'production-project');
  assert.equal(built.input.cloud_project, 'production-project');
  assert.equal(built.input.cloud_session_ttl, 3600);
  assert.equal(built.newSecrets.length, 1);
  assert.equal(built.input.cloud_gcp_key_ref, built.newSecrets[0].name);
});

test('GCP setup supports an existing key reference and requires a project', () => {
  const existing = buildGcpCloudSetup({
    name: 'Production GCP',
    cloudCredentialSources: { gcpKey: 'existing' },
    cloudGcpKeyRef: 'GCP_SERVICE_ACCOUNT',
    cloudProject: 'manually-selected-project',
  }, ['GCP_SERVICE_ACCOUNT']);
  assert.deepEqual(existing.errors, {});
  assert.deepEqual(existing.newSecrets, []);
  assert.equal(existing.input.cloud_gcp_key_ref, 'GCP_SERVICE_ACCOUNT');

  const missingProject = buildGcpCloudSetup({
    name: 'Production GCP',
    cloudCredentialSources: { gcpKey: 'existing' },
    cloudGcpKeyRef: 'GCP_SERVICE_ACCOUNT',
  }, ['GCP_SERVICE_ACCOUNT']);
  assert.match(missingProject.errors.cloudProject, /project ID/);
});

test('GCP setup rejects project values that are not project-id-shaped', () => {
  for (const project of ['My Project', 'proj', '1-starts-with-digit', 'ends-with-hyphen-']) {
    const built = buildGcpCloudSetup({
      name: 'Production GCP',
      cloudCredentialSources: { gcpKey: 'existing' },
      cloudGcpKeyRef: 'GCP_SERVICE_ACCOUNT',
      cloudProject: project,
    }, ['GCP_SERVICE_ACCOUNT']);
    assert.match(built.errors.cloudProject ?? '', /lowercase/, project);
  }
});

test('GCP setup rejects arbitrary JSON in place of a service-account key', () => {
  const built = buildGcpCloudSetup({
    name: 'Production GCP',
    cloudCredentialSources: { gcpKey: 'new' },
    cloudGcpKeyValue: '{"type":"authorized_user"}',
    cloudProject: 'production-project',
  }, []);
  assert.match(built.errors.cloudGcpKeyRef, /service-account JSON key/);
});

function azureDraft(overrides: ConnectionDraft = {}): ConnectionDraft {
  return {
    name: 'Production Azure',
    cloudCredentialSources: { azureClientSecret: 'new' },
    cloudTenantId: '11111111-1111-1111-1111-111111111111',
    cloudClientId: '22222222-2222-2222-2222-222222222222',
    cloudClientSecretValue: 'entra-client-secret',
    cloudSubscriptionId: '33333333-3333-3333-3333-333333333333',
    cloudScope: 'https://management.azure.com/.default',
    ...overrides,
  };
}

test('Azure setup vaults a new client secret and keeps the ARM defaults', () => {
  const built = buildAzureCloudSetup(azureDraft(), []);
  assert.deepEqual(built.errors, {});
  assert.equal(built.input.cloud_provider, 'azure');
  assert.equal(built.input.cloud_scope, 'https://management.azure.com/.default');
  assert.equal(built.input.cloud_session_ttl, 3600);
  assert.equal(built.newSecrets.length, 1);
  assert.equal(built.input.cloud_client_secret_ref, built.newSecrets[0].name);
  assert.equal(built.newSecrets[0].value, 'entra-client-secret');
});

test('Azure setup accepts an existing secret reference and a domain tenant', () => {
  const built = buildAzureCloudSetup(azureDraft({
    cloudCredentialSources: { azureClientSecret: 'existing' },
    cloudClientSecretRef: 'AZURE_SP_SECRET',
    cloudClientSecretValue: undefined,
    cloudTenantId: 'contoso.onmicrosoft.com',
  }), ['AZURE_SP_SECRET']);
  assert.deepEqual(built.errors, {});
  assert.deepEqual(built.newSecrets, []);
  assert.equal(built.input.cloud_client_secret_ref, 'AZURE_SP_SECRET');
  assert.equal(built.input.cloud_tenant_id, 'contoso.onmicrosoft.com');
});

test('Azure setup requires its IDs and rejects non-GUID client and subscription', () => {
  const missing = buildAzureCloudSetup({
    name: 'Production Azure',
    cloudCredentialSources: { azureClientSecret: 'new' },
    cloudClientSecretValue: 'entra-client-secret',
  }, []);
  assert.match(missing.errors.cloudTenantId, /tenant ID/);
  assert.match(missing.errors.cloudClientId, /client/);
  assert.match(missing.errors.cloudSubscriptionId, /subscription ID/);

  const malformed = buildAzureCloudSetup(azureDraft({
    cloudClientId: 'not-a-guid',
    cloudSubscriptionId: 'also-not-a-guid',
  }), []);
  assert.match(malformed.errors.cloudClientId, /GUID/);
  assert.match(malformed.errors.cloudSubscriptionId, /GUID/);
});
