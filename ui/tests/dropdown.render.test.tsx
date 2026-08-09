import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import type { ViteDevServer } from 'vite';

// The tray shell: location.hash picks the window at import time, so this
// file boots the app once with '#dropdown' and exercises the combined
// Tools-over-Credentials view, the header's Activity toggle, and the
// tool-detail slide-over the Tools tab used to host.
const dom = new JSDOM(
  '<!doctype html><html><body><div id="root"></div><div id="overlays"></div></body></html>',
  { url: 'http://localhost/#dropdown' },
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
    assert.ok(document.querySelector('.dropdown-surface'));
    assert.equal(document.querySelector('.app-loading'), null);
  });
});

test.after(async () => {
  await vite.close();
});

test('the tray boots as one combined view with no tab switcher', async () => {
  assert.equal(document.querySelector('.seg'), null, 'the segmented tabs are gone');
  assert.ok(document.querySelector('.dd-combined'), 'the combined view hosts the content');
  // The tray carries the window's group register, so both surfaces name the
  // same sections.
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.dd-cred-list .dd-cred'), 'the credential rows render');
  });
  assert.deepEqual(
    [...document.querySelectorAll('.dd-sec-h')].map((h) => h.textContent),
    ['Connections', 'Passwords', 'Secrets'],
  );
  assert.equal(document.querySelector('.dd-tools .agent-tools-context'), null,
    'the menu-bar section uses the compact Connections label');
  // Flat connection rows: one bar per tool; overflow past five is "All tools ›".
  const band = document.querySelector<HTMLElement>('.tools-band');
  assert.ok(band, 'the tools slim-bar band renders');
  const bars = [...band.querySelectorAll<HTMLElement>('.tool-bar')];
  assert.equal(bars.length, 5, 'the band caps at five bars');
  assert.match(
    document.querySelector('.tool-bar-more')?.textContent ?? '',
    /All tools/,
  );
  // No section head / add path — tools and credentials are browse-only here.
  assert.equal(document.querySelector('.tool-band-label'), null);
  assert.equal(document.querySelector('.tool-band-add'), null);
  assert.equal(document.querySelector('button[data-act="open-add-secret"]'), null);
  // No bottom status bar; 1Password is main-window only (Credentials titlebar).
  assert.equal(document.querySelector('.secrets-statusbar'), null);
  assert.equal(document.querySelector('.dd-head .vault-switch-wrap'), null);
});

test('the tray header is one identity line, not a brand block', async () => {
  const head = document.querySelector<HTMLElement>('.dd-head');
  assert.ok(head);
  // No 34px app tile: you clicked the Multitool icon to get here.
  assert.equal(head.querySelector('.dd-appicon'), null);
  const line = head.querySelector<HTMLElement>('.dd-identity-line');
  assert.ok(line, 'the identity collapses to a single line');
  assert.ok(line.querySelector('.dot'), 'the status dot rides the line');
  assert.equal(line.querySelector('.dd-title')?.textContent, 'Multitool');
  assert.equal(line.querySelector('.dd-scope')?.textContent, 'Local',
    'the managed broker is named beside the app');
  // The window button sits immediately left of the gear; appearance rides
  // the gear menu, so no theme button spends a header slot.
  assert.equal(head.querySelector('[data-act="toggle-theme"]'), null);
  const acts = [...head.querySelectorAll<HTMLElement>('button[data-act]')]
    .map((b) => b.dataset.act);
  // Activity is a menu destination now, so the header is the mockup's two
  // buttons: open-as-window, then the gear that holds everything else.
  assert.deepEqual(acts, ['mode-window', 'toggle-settings-menu']);
});

/** Open the tray gear's popover. Selector-based on purpose: accessible-name
 * role queries walk and name the whole tray on every call, which is both
 * slow here and unnecessary — the panel's controls are addressed by their
 * dispatch action everywhere else in this file. */
async function openTrayMenu(): Promise<HTMLElement> {
  // Idempotent: the gear toggles, so clicking an already-open menu would
  // close it and turn one failure into every later test's failure.
  if (!document.querySelector('.dd-head .settings-menu')) {
    testingLibrary.fireEvent.click(
      document.querySelector<HTMLButtonElement>('.dd-head [data-act="toggle-settings-menu"]')!,
    );
  }
  return testingLibrary.waitFor(() => {
    const el = document.querySelector<HTMLElement>('.dd-head .settings-menu');
    assert.ok(el, 'the gear opens a popover');
    return el;
  });
}

/** Click one item of the open popover, addressed by its dispatch action. */
function pickTrayMenuItem(menu: HTMLElement, selector: string): void {
  const item = menu.querySelector<HTMLButtonElement>(selector);
  assert.ok(item, `the menu offers ${selector}`);
  testingLibrary.fireEvent.click(item);
}

test('the tray gear opens the panel menu, not the Settings sheet', async () => {
  const menu = await openTrayMenu();
  // The caption names the build; the items are the panel's ways out.
  assert.match(menu.querySelector('.menu-version')?.textContent ?? '', /^Multitool \S+/);
  const labels = [...menu.querySelectorAll<HTMLElement>('.menu-item')]
    // The Activity row carries a pending-request count; drop it to compare.
    .map((item) => item.textContent?.replace(/\s+/g, ' ').replace(/\s*\d+$/, '').trim());
  assert.deepEqual(labels, [
    'Credentials', 'Activity Log', 'Settings', 'Quit Multitool',
  ]);
  // Connecting an agent is a window-only walkthrough: no route from here.
  assert.equal(menu.querySelector('[data-tab="start"]'), null);
  assert.ok(menu.querySelector('[data-act="open-settings"]'),
    'Settings moved behind the gear rather than owning it');
  // Quit is a native-shell command; this harness supplies __TAURI__, so the
  // panel offers the way out the tray icon's own menu has always had.
  assert.ok(menu.querySelector('[data-act="quit-app"]'), 'the panel can quit the app');
  // Appearance previews in place: choosing a mode must not dismiss the menu.
  const dark = menu.querySelector<HTMLButtonElement>('[data-theme-mode="dark"]')!;
  const light = menu.querySelector<HTMLButtonElement>('[data-theme-mode="light"]')!;
  testingLibrary.fireEvent.click(dark);
  assert.equal(document.documentElement.dataset.theme, 'dark');
  assert.ok(document.querySelector('.dd-head .settings-menu'), 'the menu stays open');
  testingLibrary.fireEvent.click(light);
  assert.equal(document.documentElement.dataset.theme, 'light');
  // A destination click dismisses the popover. Credentials is the view the tray
  // is already on, so this leaves the panel where the next test expects it.
  pickTrayMenuItem(menu, '[data-tab="secrets"]');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.dd-head .settings-menu'), null);
  });
});

test('the request notice is an inset card inside the tray scroller', () => {
  const band = document.querySelector<HTMLElement>('.dd-global.request-route-only');
  assert.ok(band, 'the waiting-request band renders in the tray');
  assert.ok(band.parentElement?.classList.contains('dd-content'),
    'the notice scrolls with Connections and credentials');
  assert.ok(band.querySelector('.request-banner'));
});

test('a lone request is named in the banner and Review opens the decision', async () => {
  const appState = await vite.ssrLoadModule('/src/app-state.ts') as
    typeof import('../src/app-state');
  const presentation = await vite.ssrLoadModule('/src/approval-presentation.ts') as
    typeof import('../src/approval-presentation');
  const { state } = appState;
  const approvals = state.approvals;
  const elicitations = state.elicitations;

  // A queue tallies and routes to the inbox.
  assert.equal(
    document.querySelector<HTMLElement>('.request-banner')?.dataset.act,
    'open-inbox',
  );
  try {
    await testingLibrary.act(async () => {
      state.approvals = [approvals[0]];
      state.elicitations = [];
      appState.uiStore.publish();
    });
    const banner = document.querySelector<HTMLElement>('.request-banner');
    assert.ok(banner, 'the banner stays for a single request');
    assert.equal(banner.dataset.act, 'approval-open',
      'Review opens the decision sheet, not the inbox');
    assert.equal(banner.dataset.id, approvals[0].id);
    const detail = banner.querySelector('.request-banner-copy span');
    assert.ok(
      detail?.textContent?.startsWith(presentation.approvalWantsLine(approvals[0])),
      'the band names the ask instead of tallying it');
    assert.ok(detail?.classList.contains('untrusted-identity'),
      'agent-derived copy keeps the untrusted marking');
  } finally {
    await testingLibrary.act(async () => {
      state.approvals = approvals;
      state.elicitations = elicitations;
      appState.uiStore.publish();
    });
  }
});

test('the tray omits the tools ledge when there are no tools', async () => {
  const appState = await vite.ssrLoadModule('/src/app-state.ts') as
    typeof import('../src/app-state');
  const connections = appState.state.connections;

  try {
    await testingLibrary.act(async () => {
      appState.state.connections = [];
      appState.uiStore.publish();
    });
    assert.equal(document.querySelector('.dd-tools'), null);
    assert.doesNotMatch(document.body.textContent ?? '', /No tools yet\./);
    const search = document.querySelector('.dd-cat-search');
    assert.ok(search);
    assert.ok(search.nextElementSibling?.classList.contains('dd-creds'),
      'the credential list directly consumes the search gap');
  } finally {
    await testingLibrary.act(async () => {
      appState.state.connections = connections;
      appState.uiStore.publish();
    });
    assert.ok(document.querySelector('.tools-band'));
  }
});

test('menu-bar settings visibility is independent from the desktop', async () => {
  const appState = await vite.ssrLoadModule('/src/app-state.ts') as
    typeof import('../src/app-state');

  appState.state.settingsSheetOpen.desktop = true;
  appState.uiStore.publish();
  await testingLibrary.waitFor(() => {
    assert.equal(testingLibrary.queryByRole(document.body, 'dialog', { name: 'Settings' }), null);
  });

  // Settings now sits behind the gear menu rather than owning the gear.
  pickTrayMenuItem(await openTrayMenu(), '[data-act="open-settings"]');
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  assert.equal(appState.state.settingsSheetOpen.desktop, true);
  assert.equal(appState.state.settingsSheetOpen.menubar, true);

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Done' }),
  );
  await testingLibrary.waitFor(() => {
    assert.equal(testingLibrary.queryByRole(document.body, 'dialog', { name: 'Settings' }), null);
  });
  assert.equal(appState.state.settingsSheetOpen.desktop, true);
  assert.equal(appState.state.settingsSheetOpen.menubar, false);

  appState.state.settingsSheetOpen.desktop = false;
  appState.uiStore.publish();
});

test('a tool bar opens the detail slide-over', async () => {
  const bars = await testingLibrary.waitFor(() => {
    const list = [...document.querySelectorAll<HTMLElement>('.tool-bar')];
    assert.ok(list.length >= 1, 'tool bars render');
    return list;
  });
  // Every bar carries the access switch; trouble adds a word pill beside it.
  assert.ok(bars[0]?.querySelector('.tool-bar-switch[role="switch"]'));
  const github = bars.find((bar) => bar.querySelector('b')?.textContent === 'github');
  assert.ok(github, 'the github tool has a bar');
  testingLibrary.fireEvent.click(github);
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.dd-combined.detail-open'));
    assert.ok(document.querySelector('.conn-detail-pane'));
    assert.equal(github.getAttribute('aria-current'), 'true');
    assert.ok(github.classList.contains('on'));
  });
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('.conn-detail-backdrop')!,
  );
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.dd-combined.detail-open'), null);
    assert.equal(github.getAttribute('aria-current'), null);
  });
});

test('credential rows use the compact copy-action cluster', async () => {
  const rows = await testingLibrary.waitFor(() => {
    const list = [...document.querySelectorAll<HTMLElement>('.dd-cred')];
    assert.ok(list.length >= 1, 'credential rows render');
    return list;
  });
  // Every row keeps a copy button outside the expand toggle (one-click copy).
  for (const row of rows) {
    assert.ok(row.querySelector('.dd-cred-wells button[data-act="copy-secret"]'),
      'the copy button copies without expanding');
    assert.equal(row.querySelector('.dd-cred-open .dd-cred-wells'), null,
      'wells are siblings of the toggle, not nested buttons');
  }
  // x.com has a TOTP seed in the mock fixtures — its pill opens the code menu.
  const withTotp = rows.find((row) =>
    row.querySelector('.dd-cred-open b')?.textContent === 'x.com');
  assert.ok(withTotp, 'the x.com password row is present');
  const pill = withTotp.querySelector<HTMLButtonElement>(
    'button[data-act="toggle-totp-menu"]');
  assert.ok(pill, 'the 2FA well is present on a seeded password');
  assert.match(pill.textContent ?? '', /2FA/);
  testingLibrary.fireEvent.click(pill);
  const menu = await testingLibrary.waitFor(() => {
    const panel = document.querySelector<HTMLElement>('.dd-totp-menu-wrap');
    assert.ok(panel);
    return panel;
  });
  assert.ok(menu.querySelector('button[data-act="copy-totp"]'));
  assert.ok(menu.querySelector('button[data-act="setup-code"]'));
  // Toggle closed via the pill (avoids leaving a live-code timer running).
  testingLibrary.fireEvent.click(pill);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.dd-totp-menu-wrap'), null);
  });
});

test('the credential search covers the tools slim-bar band', async () => {
  const search = document.querySelector<HTMLInputElement>('.dd-cat-search')!;
  testingLibrary.fireEvent.change(search, { target: { value: 'github' } });
  // Matching tools surface as bars while the needle is active.
  await testingLibrary.waitFor(() => {
    const bars = [...document.querySelectorAll<HTMLElement>('.tool-bar')];
    assert.equal(bars.length, 1);
    assert.equal(bars[0]?.querySelector('b')?.textContent, 'github');
  });
  // No tool matches: the band steps aside entirely.
  testingLibrary.fireEvent.change(search, { target: { value: 'zzz-no-such' } });
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.tools-band'), null);
  });
  testingLibrary.fireEvent.change(search, { target: { value: '' } });
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.tools-band'));
  });
});

test('activity is a menu destination, and the menu leads back', async () => {
  pickTrayMenuItem(await openTrayMenu(), '[data-tab="activity"]');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.dd-combined'), null, 'the combined view yields');
    assert.ok(document.querySelector('.dd-content.activity-content'),
      'the activity scroll pane gets its own top inset');
    assert.ok(document.querySelector('.act-list, .act-filters, .activity-empty, .act-row'),
      'the activity view fills the body');
    assert.equal(document.querySelector('.act-tool'), null,
      'compact activity rows do not repeat tool names in trailing badges');
  });
  // The way back is in the same menu, so a destination is never a one-way trip.
  pickTrayMenuItem(await openTrayMenu(), '[data-tab="secrets"]');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.dd-content.activity-content'), null);
    assert.ok(document.querySelector('.dd-combined'), 'credentials return');
  });
});
