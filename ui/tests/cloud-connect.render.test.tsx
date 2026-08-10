// The Connect-agents walkthrough for a cloud tool.
//
// Cloud is the one connect mode with nothing to hand over: no DSN, no socket,
// no endpoint the broker will issue. What the user needs instead is a command
// that mints on demand, and the two facts that make it different from every
// other kind — a lifetime measured in minutes, and no way to revoke a session
// once minted. These tests pin that the pane says so, per provider, and that
// the step only finishes on a mint the broker actually recorded.

import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import type { ActivityEntry, ConnectionSummary } from '../src/types';

const dom = new JSDOM('<!doctype html><html><body><div id="overlays"></div></body></html>', {
  url: 'http://localhost/',
});

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperties(globalThis, {
  window: { configurable: true, value: dom.window },
  document: { configurable: true, value: dom.window.document },
  // The bridge reads location at module load to choose the mock transport.
  location: { configurable: true, value: dom.window.location },
  localStorage: { configurable: true, value: dom.window.localStorage },
  navigator: { configurable: true, value: dom.window.navigator },
  Node: { configurable: true, value: dom.window.Node },
  Element: { configurable: true, value: dom.window.Element },
  HTMLElement: { configurable: true, value: dom.window.HTMLElement },
  HTMLButtonElement: { configurable: true, value: dom.window.HTMLButtonElement },
  Event: { configurable: true, value: dom.window.Event },
  MouseEvent: { configurable: true, value: dom.window.MouseEvent },
  MutationObserver: { configurable: true, value: dom.window.MutationObserver },
  ResizeObserver: { configurable: true, value: TestResizeObserver },
  getComputedStyle: {
    configurable: true,
    value: dom.window.getComputedStyle.bind(dom.window),
  },
});
// Importing the state module installs the broker's polling timers. Unref them
// so a finished test run exits instead of waiting on the next tick.
const nativeSetInterval = globalThis.setInterval;
const nativeSetTimeout = globalThis.setTimeout;
Object.defineProperty(globalThis, 'setInterval', {
  configurable: true,
  value: (...args: Parameters<typeof setInterval>) => {
    const timer = nativeSetInterval(...args);
    timer.unref();
    return timer;
  },
});
Object.defineProperty(globalThis, 'setTimeout', {
  configurable: true,
  value: (...args: Parameters<typeof setTimeout>) => {
    const timer = nativeSetTimeout(...args);
    timer.unref();
    return timer;
  },
});
Object.defineProperty(dom.window, 'matchMedia', {
  configurable: true,
  value: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }),
});
Object.defineProperty(dom.window, 'scrollTo', { configurable: true, value: () => {} });

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

type TestingLibrary = typeof import('@testing-library/react');
let testingLibrary: TestingLibrary;
let StartViewPage: typeof import('../src/features/connect-agents-view')['StartViewPage'];
let state: typeof import('../src/app-state')['state'];

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  ({ StartViewPage } = await import('../src/features/connect-agents-view'));
  ({ state } = await import('../src/app-state'));
});

test.afterEach(() => {
  testingLibrary.cleanup();
  document.body.replaceChildren();
});

function cloudConnection(
  name: string,
  cloud: NonNullable<ConnectionSummary['cloud']>,
): ConnectionSummary {
  return {
    id: name, name, updated_at: '2026-08-06T12:00:00.000Z',
    type: 'cloud', target: `${cloud.provider}:${name}`, secret_names: [], oauth: false,
    agent_access: { enabled: true },
    host: null, scheme: cloud.provider, port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null,
    trusted_ca_bundle_path: null,
    cloud,
  } as ConnectionSummary;
}

const CONNECTIONS: Record<string, ConnectionSummary> = {
  'aws-cli': cloudConnection('aws-prod', {
    provider: 'aws',
    region: 'us-east-1',
    role_arn: 'arn:aws:iam::123456789012:role/AgentReadOnly',
    session_ttl_secs: 900,
  }),
  'gcp-cli': cloudConnection('gcp-prod', {
    provider: 'gcp',
    project: 'aka-prod',
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    session_ttl_secs: 3600,
  }),
  azure: cloudConnection('azure-prod', {
    provider: 'azure',
    tenant_id: '8f2c1d40-1111-2222-3333-abcdefabcdef',
    subscription_id: 'e91b7a55-dddd-eeee-ffff-0987654321fe',
    scope: 'https://management.azure.com/.default',
    session_ttl_secs: 3600,
  }),
};

/** Render the walkthrough for one cloud row, with the given activity behind it. */
function renderCloud(optionId: string, activity: ActivityEntry[] = []): HTMLElement {
  state.startOption = optionId;
  state.connectMode = 'cloud-cli';
  state.connections = [CONNECTIONS[optionId]];
  state.activity = activity;
  state.startMenuOpen = null;
  return testingLibrary.render(<StartViewPage />).container;
}

function mintFor(name: string): ActivityEntry {
  return {
    icon: 'cloud', tone: 'neutral', kind: 'cloud_session_minted',
    text: `session minted: ${name}`, detail: null,
    agent: 'claude-code', connection: name,
    at: '2026-08-06T11:00:00.000Z',
  } as ActivityEntry;
}

test('a cloud walkthrough hands over the command that mints, per provider', () => {
  const expected: Record<string, string> = {
    // Only the AWS CLI has a credential_process hook, so only AWS gets a
    // profile written once; the others export into the shell each time.
    'aws-cli': "aka cloud config 'aws-prod'",
    'gcp-cli': `eval "$(aka cloud env 'gcp-prod')"`,
    azure: `eval "$(aka cloud env 'azure-prod')"`,
  };
  for (const [optionId, command] of Object.entries(expected)) {
    const container = renderCloud(optionId);
    const shown = [...container.querySelectorAll('.setup-instructions')]
      .map((block) => block.textContent);
    assert.ok(shown.includes(command), `${optionId} shows ${command}, got ${shown.join(' | ')}`);
    // The copy button carries the same text the pane displays.
    const copy = container.querySelector<HTMLButtonElement>(
      'button[data-act="copy-text"][data-text]',
    );
    assert.equal(copy?.dataset.text, command, optionId);
    testingLibrary.cleanup();
  }
});

test('the cloud pane states the lifetime and that a minted session cannot be revoked', () => {
  for (const [optionId, minutes] of [['aws-cli', 15], ['gcp-cli', 60], ['azure', 60]] as const) {
    const container = renderCloud(optionId);
    const text = container.textContent ?? '';
    assert.ok(text.includes(`about ${minutes} minutes`), `${optionId} names its lifetime`);
    // The security argument for this kind is the short TTL, because the
    // broker cannot take a session back. Saying so is the pane's job.
    assert.ok(text.includes('cannot revoke'), `${optionId} states the revocation limit`);
    testingLibrary.cleanup();
  }
});

test('the cloud step waits for a mint the broker recorded', () => {
  const waiting = renderCloud('aws-cli');
  assert.ok(waiting.textContent?.includes('Waiting for the first session to be minted'));
  assert.equal(waiting.querySelector('.start-step.done:nth-of-type(2)'), null);
  testingLibrary.cleanup();

  // Another tool's mint is not this tool's, so the step stays unfinished.
  const other = renderCloud('aws-cli', [mintFor('gcp-prod')]);
  assert.ok(other.textContent?.includes('Waiting for the first session to be minted'));
  testingLibrary.cleanup();

  const done = renderCloud('aws-cli', [mintFor('aws-prod')]);
  assert.ok(done.textContent?.includes('Session minted'));
  assert.equal(done.textContent?.includes('Waiting for the first session'), false);
});

test('the cloud hero reads without repeating the CLI name', () => {
  const container = renderCloud('aws-cli');
  const sentence = container.querySelector('.start-sentence')?.textContent ?? '';
  assert.ok(sentence.includes('AWS CLI'), sentence);
  assert.ok(sentence.includes('a local shell'), sentence);
  // Regression: the mode used to be labelled with the vendor CLI too, which
  // rendered as "Connect to AWS CLI from the AWS CLI".
  assert.equal(sentence.match(/AWS CLI/g)?.length, 1, sentence);
});

test('the cloud walkthrough asks for something that needs the credential', () => {
  const container = renderCloud('aws-cli', [mintFor('aws-prod')]);
  const prompt = [...container.querySelectorAll('.setup-instructions')]
    .map((block) => block.textContent ?? '')
    .find((text) => text.includes('Multitool connection'));
  assert.ok(prompt, 'step 3 offers a prompt naming the tool');
  assert.ok(prompt.includes("aka cloud config 'aws-prod'"), 'it shows config before asking');
  assert.ok(prompt.includes('15 minutes'), 'it warns the session expires');
  assert.ok(prompt.includes('"aws-prod"'), 'it names the tool the broker knows');
});

test('a cloud tool can still be reached through an MCP client', () => {
  state.startOption = 'azure';
  state.connectMode = 'claude-code';
  state.connections = [CONNECTIONS.azure];
  state.activity = [];
  state.startMenuOpen = null;
  const container = testingLibrary.render(<StartViewPage />).container;
  const text = container.textContent ?? '';
  // Picking an agent client must not fall back to the cloud pane: the shared
  // key route is a real alternative for cloud, not a special case.
  assert.ok(text.includes('claude mcp add multitool'), text.slice(0, 400));
  assert.equal(text.includes('cannot revoke'), false, 'the shell caveat belongs to the shell mode');
});
