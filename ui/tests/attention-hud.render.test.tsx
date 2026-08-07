import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import type { ViteDevServer } from 'vite';

// The HUD has its own hash and boot path: it must never mount either
// interactive app surface or load the shared sheet/menu state.
const dom = new JSDOM(
  '<!doctype html><html><body><div id="root"></div><div id="overlays"></div></body></html>',
  { url: 'http://localhost/#attention' },
);

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperties(globalThis, {
  window: { configurable: true, value: dom.window },
  document: { configurable: true, value: dom.window.document },
  location: { configurable: true, value: dom.window.location },
  localStorage: { configurable: true, value: dom.window.localStorage },
  navigator: { configurable: true, value: dom.window.navigator },
  Node: { configurable: true, value: dom.window.Node },
  Element: { configurable: true, value: dom.window.Element },
  HTMLElement: { configurable: true, value: dom.window.HTMLElement },
  HTMLButtonElement: { configurable: true, value: dom.window.HTMLButtonElement },
  HTMLInputElement: { configurable: true, value: dom.window.HTMLInputElement },
  HTMLTextAreaElement: { configurable: true, value: dom.window.HTMLTextAreaElement },
  Event: { configurable: true, value: dom.window.Event },
  MouseEvent: { configurable: true, value: dom.window.MouseEvent },
  MutationObserver: { configurable: true, value: dom.window.MutationObserver },
  ResizeObserver: { configurable: true, value: TestResizeObserver },
  getComputedStyle: {
    configurable: true,
    value: dom.window.getComputedStyle.bind(dom.window),
  },
});
Object.defineProperty(dom.window, 'matchMedia', {
  configurable: true,
  value: () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  }),
});
Object.defineProperty(dom.window, 'scrollTo', {
  configurable: true,
  value: () => {},
});
dom.window.__TAURI__ = {
  core: {
    async invoke(command, args) {
      const mock = await import('../src/mock-bridge');
      return (mock.invoke as (
        command: never,
        args?: never,
      ) => Promise<unknown>)(command as never, args as never);
    },
  },
  event: {
    async listen(event, callback) {
      const mock = await import('../src/mock-bridge');
      return (mock.listen as (
        event: never,
        callback: never,
      ) => Promise<() => void>)(event as never, callback as never);
    },
  },
};

type TestingLibrary = typeof import('@testing-library/react');
let testingLibrary: TestingLibrary;
let vite: ViteDevServer;

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  vite = await createServer({
    appType: 'custom',
    server: { middlewareMode: true },
  });
  await vite.ssrLoadModule('/app.tsx');
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.attention-hud-shell'));
  });
});

test.after(async () => {
  await vite.close();
});

test('the attention HUD boots without either interactive app surface', () => {
  assert.equal(document.querySelector('.surface'), null);
  assert.equal(document.querySelector('[role="dialog"]'), null);
  assert.match(document.body.textContent ?? '', /2 requests waiting in Multitool/);
  assert.ok(testingLibrary.getByRole(document.body, 'button', { name: 'Review' }));
});

test('dismissing the popup clears only the HUD view', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Dismiss popup' }),
  );
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.attention-hud-shell'), null);
  });
  assert.equal(document.querySelector('.surface'), null);
});
