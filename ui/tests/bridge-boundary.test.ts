import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('the standalone browser mock stays behind the development boundary', async () => {
  const bridge = await readFile(new URL('../src/bridge.ts', import.meta.url), 'utf8');

  // The bare expression matters, not just the intent: Vite substitutes
  // exactly `import.meta.env.DEV` for a literal, and that substitution is
  // what lets the bundler drop the mock and its fixtures from a production
  // build. Writing it any other way — behind optional chaining, say — keeps
  // the branch and ships the fixtures.
  assert.match(bridge, /if \(!import\.meta\.env\.DEV\)/);
  assert.match(bridge, /Boolean\(import\.meta\.env\.DEV\)/);
  assert.match(bridge, /return import\('\.\/mock-bridge'\)/);
  assert.doesNotMatch(bridge, /MOCK_ENDPOINT_SECRET|MOCK_ACTIVITY_LIMIT|mockInvoke/);
});

test('the web host never reaches for the mock', async () => {
  const bridge = await readFile(new URL('../src/bridge.ts', import.meta.url), 'utf8');

  // Three hosts now share this file, and only one of them may load
  // fixtures. A production browser must go to the HTTP adapter.
  assert.match(bridge, /import\('\.\/http-bridge'\)/);
  for (const branch of bridge.split('if (webHost)').slice(1)) {
    const body = branch.slice(0, branch.indexOf('\n  }'));
    assert.doesNotMatch(
      body,
      /mock-bridge/,
      'the web branch must not import the development mock',
    );
  }
});
