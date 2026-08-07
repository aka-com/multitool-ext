import test from 'node:test';
import assert from 'node:assert/strict';

import {
  LOCAL_BROKER,
  brokerLabel,
  brokerTakeover,
  brokerTone,
  remoteEndpointCaution,
  supportsOnePassword,
  supportsPasskeys,
  usesLegacyToken,
} from '../src/broker';
import type { BrokerProfile } from '../src/types';

function remote(overrides: Partial<BrokerProfile> = {}): BrokerProfile {
  return {
    mode: 'remote',
    url: 'https://broker.example.dev',
    connected: true,
    error: null,
    has_saved_token: true,
    has_saved_grant: false,
    credential: 'token',
    device_name: null,
    capabilities: ['onepassword_provider_v1'],
    ...overrides,
  };
}

test('1Password requires the broker capability', () => {
  assert.equal(supportsOnePassword(LOCAL_BROKER), true);
  assert.equal(supportsOnePassword(remote()), true);
  assert.equal(supportsOnePassword(remote({ capabilities: [] })), false);
});

test('the switcher labels local mode and remote hosts', () => {
  assert.equal(brokerLabel(LOCAL_BROKER), 'Local');
  assert.equal(brokerLabel(remote()), 'broker.example.dev');
  assert.equal(brokerLabel(remote({ url: 'http://10.0.1.5:4780' })), '10.0.1.5:4780');
  // An unparseable URL falls back to the raw value rather than throwing.
  assert.equal(brokerLabel(remote({ url: 'not a url' })), 'not a url');
  assert.equal(brokerLabel(remote({ url: null })), 'Remote broker');
});

test('the status dot follows the link state', () => {
  assert.equal(brokerTone(LOCAL_BROKER), 'local');
  assert.equal(
    brokerTone({ ...LOCAL_BROKER, connected: false, error: 'broker stopped' }),
    'error',
  );
  assert.equal(brokerTone(remote()), 'ok');
  assert.equal(brokerTone(remote({ connected: false })), 'pending');
  assert.equal(brokerTone(remote({ connected: false, error: 'refused' })), 'error');
});

test('the takeover pane renders exactly when the active broker is unusable', () => {
  // Healthy local and remote brokers show normal tabs.
  assert.equal(brokerTakeover(LOCAL_BROKER, false), null);
  assert.equal(brokerTakeover(remote(), false), null);
  assert.equal(
    brokerTakeover({ ...LOCAL_BROKER, connected: false, error: 'broker stopped' }, false),
    'error',
  );
  // The user opened the configuration form (from any mode).
  assert.equal(brokerTakeover(LOCAL_BROKER, true), 'setup');
  assert.equal(brokerTakeover(remote(), true), 'setup');
  // Remote without a saved token: nothing to retry — configure.
  assert.equal(
    brokerTakeover(remote({ connected: false, has_saved_token: false }), false),
    'setup',
  );
  // Saved token, no verdict yet: connecting; with an error: the error pane.
  assert.equal(brokerTakeover(remote({ connected: false }), false), 'connecting');
  assert.equal(
    brokerTakeover(remote({ connected: false, error: 'connection refused' }), false),
    'error',
  );
});

function unset(overrides: Partial<BrokerProfile> = {}): BrokerProfile {
  return {
    mode: 'unset',
    url: null,
    connected: false,
    error: null,
    has_saved_token: false,
    has_saved_grant: false,
    credential: null,
    device_name: null,
    capabilities: [],
    ...overrides,
  };
}

test('a first run with no chosen broker shows the chooser', () => {
  assert.equal(brokerTakeover(unset(), false), 'choose');
  assert.equal(brokerTone(unset()), 'pending');
  assert.equal(brokerLabel(unset()), 'Choose broker');
  // The "Hosted broker" option opens the setup form over the chooser, and
  // closing it (setupOpen back to false) returns to the chooser rather than
  // an app with no broker behind it.
  assert.equal(brokerTakeover(unset(), true), 'setup');
});

test('remote endpoint cautions describe reachability per type', () => {
  // Local mode: no caution.
  assert.equal(remoteEndpointCaution(LOCAL_BROKER, 'api'), null);
  assert.equal(remoteEndpointCaution(LOCAL_BROKER, 'pg'), null);
  // Remote: the HTTP endpoint is reachable (advertised host); PG/SSH are
  // broker-host-local sockets.
  assert.match(remoteEndpointCaution(remote(), 'api') ?? '', /advertised host/);
  assert.match(remoteEndpointCaution(remote(), 'pg') ?? '', /broker host/);
  assert.match(remoteEndpointCaution(remote(), 'ssh') ?? '', /broker host/);
});


test('a saved passkey sign-in is enough to skip the setup pane', () => {
  // Before passkeys, a saved management token was the only thing that meant
  // "this broker has been set up". A device grant means it too, and a broker
  // reached that way has no token to have saved.
  const grantOnly = remote({
    connected: false,
    has_saved_token: false,
    has_saved_grant: true,
  });
  assert.equal(brokerTakeover(grantOnly, false), 'connecting');

  // Nothing saved at all is still the setup pane: retrying against a
  // credential that does not exist would just loop.
  const nothingSaved = remote({
    connected: false,
    has_saved_token: false,
    has_saved_grant: false,
  });
  assert.equal(brokerTakeover(nothingSaved, false), 'setup');
});

test('the legacy credential is identified so it can be migrated', () => {
  assert.equal(usesLegacyToken(remote({ credential: 'token' })), true);
  assert.equal(usesLegacyToken(remote({ credential: 'passkey' })), false);
  assert.equal(usesLegacyToken(remote({ credential: null })), false);
  // Local mode has no credential to migrate.
  assert.equal(usesLegacyToken(LOCAL_BROKER), false);
});

test('a broker predating passkeys is not offered a passkey sign-in', () => {
  assert.equal(supportsPasskeys(remote({ capabilities: ['passkey_auth_v1'] })), true);
  assert.equal(supportsPasskeys(remote({ capabilities: ['onepassword_provider_v1'] })), false);
  assert.equal(supportsPasskeys(remote({ capabilities: [] })), false);
});
