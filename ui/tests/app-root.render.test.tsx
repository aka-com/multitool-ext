import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import type { ViteDevServer } from 'vite';

const dom = new JSDOM(
  '<!doctype html><html><body><div id="root"></div><div id="overlays"></div><div id="toasts" class="toasts"></div></body></html>',
  { url: 'http://localhost/' },
);

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const nativeSetInterval = globalThis.setInterval;
const nativeSetTimeout = globalThis.setTimeout;
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
  // Toasts animate in via rAF; jsdom does not provide it.
  requestAnimationFrame: {
    configurable: true,
    value: (cb: FrameRequestCallback) => nativeSetTimeout(() => cb(0), 0) as unknown as number,
  },
  cancelAnimationFrame: {
    configurable: true,
    value: (id: number) => clearTimeout(id),
  },
});
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
    assert.ok(document.querySelector('.surface'));
    assert.equal(document.querySelector('.app-loading'), null);
  });
});

test.after(async () => {
  await vite.close();
});

/** Navigate the way the window does now: the sidebar is gone, so every
 * destination hangs off the title bar's app menu. Opening it is idempotent —
 * the menu closes itself when an item is chosen. */
function goToTab(tab: 'secrets' | 'connections' | 'start' | 'activity'): void {
  const gear = document.querySelector<HTMLButtonElement>('.app-menu-btn');
  assert.ok(gear, 'the window has an app menu');
  if (!document.querySelector('.settings-menu')) testingLibrary.fireEvent.click(gear);
  const item = document.querySelector<HTMLButtonElement>(
    `.settings-menu [data-act="tab"][data-tab="${tab === 'connections' ? 'secrets' : tab}"]`,
  );
  assert.ok(item, `the app menu offers ${tab}`);
  testingLibrary.fireEvent.click(item);
}

test('the application root boots against the mock bridge', () => {
  assert.ok(testingLibrary.getAllByText(document.body, 'Multitool').length >= 1);
  // No sidebar: the window is one chrome bar over one content pane, and the
  // destinations hang off the title bar's app menu.
  assert.equal(document.querySelector('.dw-side'), null);
  assert.equal(document.querySelector('.dw-nav'), null);
  const gear = document.querySelector<HTMLButtonElement>('.app-menu-btn');
  assert.ok(gear, 'the app menu replaces the sidebar');
  testingLibrary.fireEvent.click(gear);
  const items = [...document.querySelectorAll<HTMLButtonElement>('.settings-menu [data-act="tab"]')];
  assert.deepEqual(
    // Activity carries its waiting-request count inline.
    items.map((item) => item.querySelector('.menu-count')
      ? item.textContent?.replace(/\d+$/, '').trim() : item.textContent?.trim()),
    ['Inventory', 'Activity Log', 'Connect agents'],
  );
  // The menu carries the way back as well as the way out.
  assert.equal(items[0]?.dataset.tab, 'secrets');
  assert.equal(items[0]?.classList.contains('on'), true);
  testingLibrary.fireEvent.click(gear);
  // The title bar is the inventory's header: no second strip under it, so
  // search and Add ride the same bar as the title.
  const bar = document.querySelector<HTMLElement>('.dw-titlebar');
  assert.ok(bar);
  assert.equal(bar.querySelector('.dw-title')?.textContent, 'Multitool');
  assert.ok(bar.querySelector('#secret-search'), 'search lives in the toolbar');
  const controls = bar.querySelector('.dw-titlebar-controls');
  assert.ok(controls?.querySelector('[data-act="toggle-add-credential-menu"]'),
    'Add joins the vault and broker controls');
  assert.equal(document.querySelector('.dw-head'), null, 'no second header strip');
  // Every control on the bar is one square the height of the search field.
  assert.equal(bar.querySelector('[data-act="toggle-inspector"]'), null,
    'the inspector fold is gone; the pane is always on screen');
});

test('secondary pages offer a titlebar Back button to Inventory', async () => {
  for (const [tab, title] of [['activity', 'Activity log'], ['start', 'Connect agents']] as const) {
    goToTab(tab);
    const heading = await testingLibrary.waitFor(() => {
      const found = document.querySelector<HTMLElement>('.dw-head');
      assert.equal(found?.querySelector('h2')?.textContent, title);
      return found!;
    });
    assert.equal(testingLibrary.queryByRole(heading, 'button', { name: 'Back' }), null,
      `${title} does not repeat Back in the page heading`);
    const titlebar = document.querySelector<HTMLElement>('.dw-titlebar')!;
    const back = testingLibrary.getByRole(titlebar, 'button', { name: 'Back' });
    assert.ok(back.classList.contains('broker-btn'), `${title} Back uses header control styling`);
    assert.ok(back.querySelector('svg'), `${title} Back button has a chevron`);
    testingLibrary.fireEvent.click(back);
    await testingLibrary.waitFor(() => {
      assert.equal(document.querySelector('.dw-head'), null);
      assert.ok(document.querySelector('#secret-search'), 'Back returns to Inventory');
      assert.equal(testingLibrary.queryByRole(titlebar, 'button', { name: 'Back' }), null);
    });
  }
});

test('desktop settings visibility is independent from the menu bar', async () => {
  const appState = await vite.ssrLoadModule('/src/app-state.ts') as
    typeof import('../src/app-state');

  appState.state.settingsSheetOpen.menubar = true;
  appState.uiStore.publish();
  await testingLibrary.waitFor(() => {
    assert.equal(testingLibrary.queryByRole(document.body, 'dialog', { name: 'Settings' }), null);
  });

  // Settings is reached through the title bar's app menu.
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Menu' }),
  );
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('.settings-menu button[data-act="open-settings"]')!,
  );
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  assert.equal(appState.state.settingsSheetOpen.desktop, true);
  assert.equal(appState.state.settingsSheetOpen.menubar, true);

  const settingTitles = [...dialog.querySelectorAll<HTMLElement>('.st-title')]
    .map((title) => title.textContent?.trim());
  assert.equal(settingTitles.includes('Request notifications'), false);
  assert.equal(settingTitles.includes('Open approvals automatically'), false);
  assert.equal(settingTitles.includes('Show agent and tool names'), false);
  assert.ok(settingTitles.includes('Play a sound on notification'));
  assert.ok(settingTitles.includes("Reset this computer's agent key"));
  assert.deepEqual(
    settingTitles.slice(
      settingTitles.indexOf('Launch Multitool at login'),
      settingTitles.indexOf('Hide Dock icon when in menu bar') + 1,
    ),
    ['Launch Multitool at login', 'Lock automatically', 'Hide Dock icon when in menu bar'],
  );
  const reminderRow = [...dialog.querySelectorAll<HTMLElement>('.set-row')]
    .find((row) => row.querySelector('.st-title')?.textContent === 'Re-alert before the deadline');
  assert.ok(reminderRow);
  // Two choices where one is "off" is a switch: the 15-second lead time is
  // the feature, so the only question is whether to re-alert at all.
  const reminderSwitch = reminderRow.querySelector<HTMLElement>('.switch');
  assert.ok(reminderSwitch, 'the re-alert control is a switch');
  assert.equal(reminderSwitch.getAttribute('role'), 'checkbox');
  assert.equal(reminderRow.querySelector('.seg'), null, 'no segmented control remains');

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Done' }),
  );
  await testingLibrary.waitFor(() => {
    assert.equal(testingLibrary.queryByRole(document.body, 'dialog', { name: 'Settings' }), null);
  });
  assert.equal(appState.state.settingsSheetOpen.desktop, false);
  assert.equal(appState.state.settingsSheetOpen.menubar, true);

  appState.state.settingsSheetOpen.menubar = false;
  appState.uiStore.publish();
});

/** Select a credential row by its title and wait for its inspector pane. */
async function openCredentialDetail(title: string): Promise<HTMLElement> {
  const row = [...document.querySelectorAll<HTMLElement>('.cred-row')]
    .find((candidate) => candidate.querySelector('b')?.textContent === title);
  assert.ok(row, `a list row for ${title}`);
  testingLibrary.fireEvent.click(row);
  return testingLibrary.waitFor(() => {
    const pane = document.querySelector<HTMLElement>('.cred-detail-pane');
    assert.ok(pane, 'the inspector pane is visible');
    assert.equal(pane.querySelector('.cdet-title')?.textContent, title);
    return pane;
  });
}

test('the credential library always groups passwords apart from secrets', async () => {
  goToTab('secrets');
  await testingLibrary.waitFor(() => {
    const cards = document.querySelectorAll('.cred-rows');
    // Connection-owned credentials moved onto the tool that owns them, so
    // the list carries only what the user curates.
    assert.equal(cards.length, 2, 'passwords and your secrets are visible');
  });
  // Every group is headed, in the same register as the page title. The
  // Connection Secrets group appears because the fixtures include
  // credentials minted by connection setup; it sits at the bottom.
  const sectionHeads = [...document.querySelectorAll<HTMLElement>('.creds-sec-h')];
  assert.deepEqual(
    sectionHeads.map((head) => head.textContent),
    // Tools head the merged inventory, above the credentials they use.
    ['Agent Tools MCPs, APIs, Cloud IAMs', 'Passwords', 'Secrets'],
  );
  assert.equal(sectionHeads[0]?.querySelector('.agent-tools-context')?.textContent,
    'MCPs, APIs, Cloud IAMs');
  assert.equal(document.querySelector('.secrets-group-h'), null);
  assert.equal(document.querySelector('.credential-group-add'), null,
    'the per-group add links are gone from the desktop listing');

  // The category tiles scope the list and count the whole inventory.
  const tiles = [...document.querySelectorAll<HTMLElement>('.cred-tile')];
  assert.deepEqual(
    tiles.map((tile) => tile.querySelector('.cred-tile-label')?.textContent),
    ['All', 'Agent Tools', 'Passwords', 'Secrets', '2FA Codes'],
    'the 1Password tile waits for the integration',
  );
  assert.equal(tiles[0]?.getAttribute('aria-checked'), 'true');

  // Password rows read site over username; selecting the x.com entry shows
  // its inspector with the current 2FA code and countdown.
  const hosts = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .map((host) => host.textContent);
  assert.deepEqual(hosts, ['google.com', 'x.com']);
  assert.ok(document.body.textContent?.includes('raykyri@gmail.com'));
  assert.equal(document.querySelectorAll('.flat-conn-wrap.sel, .cred-row.on').length, 1,
    'the unified inventory has only one selected row');
  const firstConnection = document.querySelector<HTMLElement>('.flat-conn-row');
  assert.ok(firstConnection);
  testingLibrary.fireEvent.click(firstConnection);
  assert.equal(document.querySelectorAll('.flat-conn-wrap.sel').length, 1);
  assert.equal(document.querySelectorAll('.cred-row.on').length, 0,
    'selecting a connection clears the selected credential');
  const googleDetail = await openCredentialDetail('google.com');
  assert.equal(document.querySelectorAll('.flat-conn-wrap.sel').length, 0,
    'selecting a credential clears the selected connection');
  assert.equal(document.querySelectorAll('.cred-row.on').length, 1);
  assert.equal(googleDetail.querySelector('.totp-live'), null);
  assert.ok(testingLibrary.getByRole(googleDetail, 'button', {
    name: 'Copy user name for google.com',
  }));
  assert.ok(testingLibrary.getByRole(googleDetail, 'button', {
    name: 'Reveal password for google.com',
  }));
  assert.ok(testingLibrary.getByRole(googleDetail, 'button', {
    name: 'Copy password for google.com',
  }));
  const googleAccess = testingLibrary.getByRole<HTMLButtonElement>(googleDetail, 'switch', {
    name: 'Allow agents to sign in with google.com',
  });
  assert.equal(googleAccess.disabled, true, 'an unused password cannot invent agent access');
  assert.ok(googleDetail.textContent?.includes('Allow agents to sign in with this'));
  assert.equal(googleDetail.textContent?.includes('Agents get a session'), false);
  const xRow = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .find((host) => host.textContent === 'x.com')?.closest('button');
  const xDetail = await openCredentialDetail('x.com');
  // Codes are issued on request: selection shows only the Show code button.
  assert.equal(xDetail.querySelector('.totp-live'), null);
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(xDetail, 'button', { name: 'Show the current 2FA code for x.com' }),
  );
  const liveTotp = await testingLibrary.waitFor(() => {
    const button = xDetail.querySelector<HTMLButtonElement>('.totp-live:not(.totp-live-loading)');
    assert.ok(button);
    assert.match(button.textContent ?? '', /246 801\d+s/);
    return button;
  });
  assert.equal(liveTotp.getAttribute('aria-label'), 'Copy the current 2FA code for x.com');
  // Passwords edit in place: per-field flows instead of a toolbar Edit.
  assert.ok(testingLibrary.getByRole(xDetail, 'button', { name: 'Change password for x.com' }));
  assert.ok(testingLibrary.getByRole(xDetail, 'button', { name: 'Change the 2FA code for x.com' }));
  const deletePassword = testingLibrary.getByRole(xDetail, 'button', {
    name: 'Delete password x.com',
  });
  // Derived names stay internal — password rows never show them.
  assert.equal(document.body.textContent?.includes('PASSWORD_X_COM'), false);

  // The titlebar vault control is the 1Password surface (no bottom status bar).
  assert.ok(document.querySelector('.vault-switch-wrap'));
  assert.equal(document.querySelector('.secrets-statusbar'), null);

  // The live display is still a copy action when pressed.
  testingLibrary.fireEvent.click(liveTotp);
  const mock = await import('../src/mock-bridge');
  await testingLibrary.waitFor(async () => {
    const page = await mock.invoke('list_activity', { limit: 5 }) as {
      entries: Array<{ text: string }>;
    };
    assert.ok(page.entries.some((entry) => entry.text.includes('2FA code issued')));
  });

  // Generated PASSWORD_* identifiers are wiring details, including in
  // context menus and destructive confirmations.
  testingLibrary.fireEvent.contextMenu(xRow!, { clientX: 20, clientY: 20 });
  const menu = await testingLibrary.findByLabelText(document.body, 'Options for x.com');
  const reveal = testingLibrary.getByRole(menu, 'button', { name: 'Reveal password' });
  testingLibrary.fireEvent.click(reveal);
  await testingLibrary.waitFor(() => {
    assert.ok(xDetail.textContent?.includes('demo-pw-x'));
  });
  assert.equal(document.querySelector('[aria-labelledby="reveal-secret-title"]'), null);

  testingLibrary.fireEvent.click(deletePassword);
  const deleteDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Delete x.com?',
  });
  assert.equal(deleteDialog.textContent?.includes('PASSWORD_X_COM'), false);
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(deleteDialog, 'button', { name: 'Cancel' }),
  );
});

test('the typed add sheet saves passwords with a 2FA seed', { timeout: 8_000 }, async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>(
      '.dw-head-actions button[data-act="toggle-add-credential-menu"]',
    )!,
  );
  const passwordOption = await testingLibrary.waitFor(() => {
    const option = document.querySelector<HTMLButtonElement>(
      '.add-credential-menu button[data-act="open-add-secret"][data-kind="password"]',
    );
    assert.ok(option, 'Add credential opens a Password / Secret menu');
    return option;
  });
  assert.deepEqual(
    [...document.querySelectorAll<HTMLElement>('.add-credential-menu .cred-name')]
      .map((label) => label.textContent),
    ['Add password', 'Add secret', 'Add tool'],
  );
  testingLibrary.fireEvent.click(passwordOption);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Add password',
  });
  assert.ok(dialog.classList.contains('add-secret-sheet'),
    'the add-password dialog uses the vertically centered add-sheet layout');
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('#f-site'), 'choosing Password opens the password form');
    assert.equal(dialog.querySelector('#f-name'), null);
    assert.equal(dialog.querySelector('.secret-kind-seg'), null,
      'the in-form type switcher is gone');
  });
  const passwordInput = dialog.querySelector<HTMLInputElement>('#f-value')!;
  const showPassword = testingLibrary.getByRole<HTMLInputElement>(dialog, 'checkbox', { name: 'Show password' });
  assert.equal(passwordInput.type, 'password');
  assert.equal(showPassword.checked, false);
  assert.ok(dialog.querySelector('#f-totp'), '2FA is a first-class Code row, no Advanced fold');
  assert.equal(dialog.textContent?.includes('the code it offers for manual entry'), false);
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#f-site')!, {
    target: { value: 'https://WWW.Example.com/login' },
  });
  assert.equal(dialog.querySelector('.field-hint')?.textContent, 'Stored as example.com');
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#f-username')!, {
    target: { value: 'user@example.com' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="generate-password"]')!,
  );
  const generated = passwordInput.value;
  assert.match(generated, /^[^-]{5}(-[^-]{5}){3}$/, 'Generate fills a grouped password');
  assert.equal(showPassword.checked, true, 'generated passwords are shown');
  assert.equal(passwordInput.type, 'text');

  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="generate-password-menu"]')!,
  );
  const formatMenu = await testingLibrary.findByRole(document.body, 'listbox', {
    name: 'Password format',
  });
  assert.deepEqual(
    testingLibrary.getAllByRole(formatMenu, 'option').map((option) => option.textContent?.trim()),
    ['Strong Password', 'Without Special Characters', 'Easy to Type'],
  );
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(formatMenu, 'option', { name: 'Without Special Characters' }),
  );
  assert.match(passwordInput.value, /^[A-Za-z0-9]{20}$/);
  assert.equal(showPassword.checked, true);

  testingLibrary.getByRole(dialog, 'button', { name: 'Choose QR Code Image…' });
  testingLibrary.getByRole(dialog, 'button', { name: 'Capture from Screen…' });
  const qrInput = dialog.querySelector<HTMLInputElement>('#f-totp-qr')!;
  assert.equal(qrInput.getAttribute('accept'), 'image/*');
  // jsdom decodes no images, so any chosen file takes the unreadable path;
  // that still proves the picker wires through to the field's error slot.
  testingLibrary.fireEvent.change(qrInput, {
    target: {
      files: [new dom.window.File(['not an image'], 'qr.png', { type: 'image/png' })],
    },
  });
  await testingLibrary.findByText(dialog, 'That image could not be read');
  // Failed file picks keep a preview so the user can see what was chosen.
  assert.ok(dialog.querySelector('.totp-qr-preview-thumb'), 'failed decode shows a preview thumb');
  const save = dialog.querySelector<HTMLButtonElement>('button[data-act="save-secret"]')!;

  // A hand edit made after a slow image decode starts must win. Before the
  // fix, the eventual decoder result could overwrite this controlled field
  // (and likewise reverse the edit sheet's explicit Remove choice).
  let resolveBitmap: ((bitmap: ImageBitmap) => void) | undefined;
  let bitmapClosed = false;
  const totpInput = dialog.querySelector<HTMLInputElement>('#f-totp')!;
  const createImageBitmapDescriptor = Object.getOwnPropertyDescriptor(
    globalThis, 'createImageBitmap',
  );
  const canvas = dom.window.HTMLCanvasElement.prototype;
  const getContextDescriptor = Object.getOwnPropertyDescriptor(canvas, 'getContext')!;
  try {
    Object.defineProperty(globalThis, 'createImageBitmap', {
      configurable: true,
      value: () => new Promise<ImageBitmap>((resolve) => { resolveBitmap = resolve; }),
    });
    // The stale scan need only reach its failure path; avoid jsdom's noisy
    // "canvas not implemented" diagnostic while exercising it.
    Object.defineProperty(canvas, 'getContext', {
      configurable: true,
      value: () => null,
    });
    testingLibrary.fireEvent.change(qrInput, {
      target: {
        files: [new dom.window.File(['slow image'], 'slow.png', { type: 'image/png' })],
      },
    });
    assert.ok(resolveBitmap, 'the image decode is in flight');
    assert.equal(
      testingLibrary.getByRole<HTMLButtonElement>(dialog, 'button', { name: 'Scanning…' }).disabled,
      true,
    );
    assert.equal(save.disabled, true, 'saving waits for the chosen image decode');
    testingLibrary.fireEvent.keyDown(totpInput, { key: 'Enter' });
    assert.equal(dialog.isConnected, true, 'Enter cannot bypass the pending-scan guard');

    testingLibrary.fireEvent.change(totpInput, {
      target: { value: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
    });
    assert.equal(save.disabled, false, 'editing the field supersedes the pending scan');
    assert.equal(
      testingLibrary.queryByText(dialog, 'That image could not be read'), null,
      'hand-editing the 2FA field clears the scan error',
    );
    resolveBitmap({
      width: 100,
      height: 100,
      close: () => { bitmapClosed = true; },
    } as ImageBitmap);
    await testingLibrary.waitFor(() => assert.equal(bitmapClosed, true));
    assert.equal(totpInput.value, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    assert.equal(testingLibrary.queryByText(dialog, 'That image could not be read'), null);
  } finally {
    if (createImageBitmapDescriptor) {
      Object.defineProperty(globalThis, 'createImageBitmap', createImageBitmapDescriptor);
    } else {
      Reflect.deleteProperty(globalThis, 'createImageBitmap');
    }
    Object.defineProperty(canvas, 'getContext', getContextDescriptor);
  }

  testingLibrary.fireEvent.click(save);
  // React Testing Library's waitFor act()-wrapper live-locks while this
  // save's command promise is pending, so settle natively — the same
  // reasoning as the 1Password save's deliberate nativeSetTimeout below.
  await new Promise<void>((resolve, reject) => {
    const t0 = Date.now();
    const iv = nativeSetInterval(() => {
      if (!document.querySelector('#f-site')) { clearInterval(iv); resolve(); }
      else if (Date.now() - t0 > 5000) { clearInterval(iv); reject(new Error('sheet still open')); }
    }, 50);
    iv.unref();
  });
  const hosts = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .map((host) => host.textContent);
  assert.ok(hosts.includes('example.com'), `site is canonicalized (got ${hosts.join(', ')})`);
  const newDetail = await openCredentialDetail('example.com');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(newDetail, 'button', {
      name: 'Show the current 2FA code for example.com',
    }),
  );
  assert.ok(newDetail.querySelector('.totp-live'), 'the saved 2FA seed shows a desktop live code');

  testingLibrary.fireEvent.click(
    newDetail.querySelector<HTMLButtonElement>('button[data-act="setup-code"]')!,
  );
  const editDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Change 2FA code',
  });
  testingLibrary.getByRole(editDialog, 'button', { name: 'Choose QR Code Image…' });
  testingLibrary.getByRole(editDialog, 'button', { name: 'Capture from Screen…' });
  const removeTotp = editDialog.querySelector<HTMLInputElement>('.totp-remove-check input');
  assert.ok(removeTotp, 'stored 2FA factors use the remove checkbox');
  assert.equal(removeTotp.checked, false);
  assert.equal(editDialog.querySelector('button[data-act="remove-totp"]'), null);
  testingLibrary.fireEvent.click(removeTotp);
  assert.equal(removeTotp.checked, true);
  testingLibrary.fireEvent.click(
    editDialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );
});

test('screen capture for 2FA surfaces cancel, permission, and no-QR outcomes', async () => {
  const mock = await import('../src/mock-bridge');
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>(
      '.dw-head-actions button[data-act="toggle-add-credential-menu"]',
    )!,
  );
  testingLibrary.fireEvent.click(
    await testingLibrary.waitFor(() => {
      const option = document.querySelector<HTMLButtonElement>(
        '.add-credential-menu button[data-act="open-add-secret"][data-kind="password"]',
      );
      assert.ok(option);
      return option;
    }),
  );
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Add password',
  });
  const capture = () => testingLibrary.getByRole(dialog, 'button', {
    name: 'Capture from Screen…',
  });

  mock.setMockScreenCapture({ status: 'cancelled' });
  testingLibrary.fireEvent.click(capture());
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('#toasts')?.textContent?.includes('Capture cancelled'), true);
  });
  assert.equal((dialog.querySelector('#f-totp') as HTMLInputElement).value, '');

  mock.setMockScreenCapture({ status: 'permission_denied' });
  testingLibrary.fireEvent.click(capture());
  await testingLibrary.findByText(dialog,
    'Screen Recording permission is required to capture a QR code.');
  const openSettings = testingLibrary.getByRole(dialog, 'button', { name: 'Open Settings' });
  assert.ok(openSettings.classList.contains('field-error-link'));
  assert.ok(openSettings.closest('.totp-capture-error'),
    'Open Settings stays inline with the permission error');

  // A real PNG (1×1, no modules) — jsdom may fail to decode or find no QR;
  // either way the capture strip stays with a retry action.
  const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
  mock.setMockScreenCapture({ status: 'captured', png_base64: png });
  testingLibrary.fireEvent.click(capture());
  await testingLibrary.waitFor(() => {
    const body = dialog.textContent ?? '';
    assert.ok(
      body.includes('No QR code found in that selection.')
        || body.includes('That capture couldn’t be read.'),
      `expected a capture failure message, got: ${body}`,
    );
  });
  assert.ok(dialog.querySelector('.totp-qr-preview-thumb'));
  testingLibrary.getByRole(dialog, 'button', { name: 'Try again' });

  mock.setMockScreenCapture({ status: 'cancelled' });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );
});

test('credential value visibility is direct on add and edit', async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>(
      '.dw-head-actions button[data-act="toggle-add-credential-menu"]',
    )!,
  );
  testingLibrary.fireEvent.click(
    await testingLibrary.waitFor(() => {
      const option = document.querySelector<HTMLButtonElement>(
        '.add-credential-menu button[data-act="open-add-secret"][data-kind="secret"]',
      );
      assert.ok(option, 'Add credential opens a Password / Secret menu');
      return option;
    }),
  );
  const addDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Add secret',
  });
  assert.ok(addDialog.classList.contains('add-secret-sheet'),
    'the add-secret dialog uses the vertically centered add-sheet layout');
  const addValue = addDialog.querySelector<HTMLInputElement>('#f-value')!;
  const addShow = testingLibrary.getByRole<HTMLInputElement>(addDialog, 'checkbox', { name: 'Show secret' });
  assert.equal(addValue.type, 'password');
  testingLibrary.fireEvent.click(addShow);
  assert.equal(addValue.type, 'text');
  testingLibrary.fireEvent.click(addShow);
  assert.equal(addValue.type, 'password');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(addDialog, 'button', { name: 'Cancel' }),
  );

  const xDetail = await openCredentialDetail('x.com');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(xDetail, 'button', { name: 'Change password for x.com' }),
  );
  let editDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Change password',
  });
  let editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
  let editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show password' });
  assert.equal(editValue.value, '', 'the stored password is not placed in the form on open');
  assert.equal(editValue.placeholder, '••••••••••••');
  testingLibrary.fireEvent.click(editShow);
  await testingLibrary.waitFor(() => {
    editDialog = testingLibrary.getByRole(document.body, 'dialog', { name: 'Change password' });
    editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
    editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show password' });
    assert.equal(editValue.value, 'demo-pw-x');
    assert.equal(editValue.type, 'text');
    assert.equal(editShow.checked, true);
  });
  testingLibrary.fireEvent.click(editShow);
  assert.equal(editValue.value, '', 'hiding scrubs the broker-released value from the draft');
  assert.equal(editValue.type, 'password');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(editDialog, 'button', { name: 'Cancel' }),
  );

  const secretDetail = await openCredentialDetail('GITHUB_API_KEY');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(secretDetail, 'button', { name: 'Edit secret GITHUB_API_KEY' }),
  );
  editDialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Edit secret' });
  editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
  editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show secret' });
  const groupLine = editDialog.querySelector('.secret-origin-line');
  assert.ok(groupLine?.querySelector('#f-secret-origin'),
    'the compact group picker is seated in its trailing-aligned row');
  assert.equal(editValue.value, '');
  testingLibrary.fireEvent.click(editShow);
  await testingLibrary.waitFor(() => {
    assert.equal(editValue.value, 'ghp_9aXf2Qe7LmNoP3demoToken41c');
    assert.equal(editValue.type, 'text');
  });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(editDialog, 'button', { name: 'Cancel' }),
  );
});

test('the 1Password sheet links a field through all three steps', { timeout: 8_000 }, async () => {
  goToTab('secrets');
  const open = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
    assert.ok(button);
    return button;
  });
  testingLibrary.fireEvent.click(open);

  const dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Connect 1Password',
  });
  assert.ok(dialog.querySelector('.onepassword-sheet-logo svg'));
  assert.equal(dialog.querySelectorAll('.onepassword-method-icon svg').length, 3);
  assert.equal(dialog.textContent?.includes('Link vault fields to this Mac'), false);
  assert.ok(dialog.textContent?.includes(
    'Use the name at the top of the 1Password sidebar, or account UUID.',
  ));
  assert.equal(dialog.textContent?.includes('1Password will ask you to authorize Multitool.'), false);
  assert.equal(dialog.querySelector('.onepassword-account-preview-nav')?.textContent, 'Profile');

  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-account')!, {
    target: { value: 'Work' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  const vault = await testingLibrary.waitFor(() => {
    const button = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-vault"][data-id="vault-work"]',
    );
    assert.ok(button);
    assert.equal(button.querySelector('.onepassword-vault-count')?.textContent, '(2)');
    assert.equal(button.querySelector('small'), null);
    return button;
  });
  testingLibrary.fireEvent.click(vault);
  const item = await testingLibrary.waitFor(() => {
    const button = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-item"][data-id="item-stripe"]',
    );
    assert.ok(button);
    const back = dialog.querySelector('.onepassword-browser-list')?.lastElementChild;
    assert.equal(back?.textContent?.trim(), 'Back');
    assert.ok(back?.querySelector('svg'));
    return button;
  });
  testingLibrary.fireEvent.click(item);
  assert.ok(dialog.querySelector(
    'button[data-act="onepassword-item"][data-id="item-stripe"]',
  ));
  assert.equal(dialog.querySelector('.onepassword-browser-list .onepassword-loading'), null);
  const checkbox = await testingLibrary.waitFor(() => {
    const input = dialog.querySelector<HTMLInputElement>('.onepassword-field input[type="checkbox"]');
    assert.ok(input);
    return input;
  });
  const unsupported = [...dialog.querySelectorAll<HTMLElement>('.onepassword-field')]
    .find((row) => row.querySelector('b')?.textContent === 'single sign-on');
  assert.ok(unsupported?.classList.contains('unsupported'));
  assert.equal(unsupported?.querySelector<HTMLInputElement>('input[type="checkbox"]')?.disabled, true);
  testingLibrary.fireEvent.click(checkbox);
  const alias = dialog.querySelector<HTMLInputElement>('.onepassword-alias input');
  assert.ok(alias?.value);
  assert.ok(dialog.textContent?.includes('Stored as'));

  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-review"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.textContent?.includes('Retrieved on use'));
    assert.equal(dialog.textContent?.includes('Resolved only when an agent uses them'), false);
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-save"]')!,
  );
  // The save handler publishes both integration and secret events before its
  // own final refresh. Let that deliberately concurrent work settle before
  // asserting the closed sheet and newly linked row.
  await new Promise((resolve) => nativeSetTimeout(resolve, 100));
  assert.equal(document.querySelector('.onepassword-sheet'), null);
  assert.ok(document.body.textContent?.includes(alias.value));
  const linkedRow = [...document.querySelectorAll<HTMLElement>('.s-name')]
    .find((name) => name.textContent === alias.value)?.closest('button');
  assert.ok(linkedRow?.querySelector('.s-source-icon svg'));
  assert.equal(linkedRow?.querySelector('.s-source'), null);
  testingLibrary.fireEvent.click(linkedRow!);
  const linkedDetail = await testingLibrary.waitFor(() => {
    const pane = document.querySelector<HTMLElement>('.cred-detail-pane');
    assert.equal(pane?.querySelector('.cdet-title')?.textContent, alias.value);
    return pane!;
  });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(linkedDetail, 'button', { name: `Edit secret ${alias.value}` }),
  );
  const linkedEditor = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Edit linked credential',
  });
  assert.equal(linkedEditor.querySelector('.linked-secret-source-label')?.textContent,
    'Synced from external source:');
  assert.ok(linkedEditor.querySelector('.linked-secret-source'));
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(linkedEditor, 'button', { name: 'Cancel' }),
  );
  assert.ok(document.querySelector('.vault-switch-wrap'));
  assert.equal(document.querySelector('.secrets-statusbar'), null);
  goToTab('connections');
});

/** Open the titlebar vault popover (idempotent) and return it. */
async function openVaultsPanel(): Promise<HTMLElement> {
  const toggle = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      'button[data-act="toggle-vaults-panel"]',
    );
    assert.ok(button, 'the titlebar offers a vault toggle');
    return button;
  });
  if (toggle.getAttribute('aria-expanded') !== 'true') testingLibrary.fireEvent.click(toggle);
  return testingLibrary.waitFor(() => {
    const panel = document.querySelector<HTMLElement>('.vaults-panel');
    assert.ok(panel);
    return panel;
  });
}

const vaultRowByLabel = (label: string): HTMLElement | undefined =>
  [...document.querySelectorAll<HTMLElement>('.onepassword-integration-row')]
    .find((element) => element.querySelector('b')?.textContent === label);

test('1Password credentials can recover and connections can be removed', { timeout: 8_000 }, async () => {
  goToTab('secrets');
  // The earlier test's desktop-app connection moves the vault surface behind
  // the titlebar vault button; connecting another lives in its popover.
  const connectPanel = await openVaultsPanel();
  testingLibrary.fireEvent.click(
    connectPanel.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]')!,
  );
  let dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Connect 1Password',
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-method="service_account"]')!,
  );
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-label')!, {
    target: { value: 'Recovery Account' },
  });
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'invalid-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.match(dialog.querySelector('[role="alert"]')?.textContent ?? '', /rejected/i);
  });

  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'valid-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"]'));
    const placeholder = dialog.querySelector('.onepassword-breadcrumb-placeholder');
    assert.equal(placeholder?.textContent, 'Select a vault…');
  });
  const allVaults = dialog.querySelector<HTMLButtonElement>(
    'button[data-act="onepassword-vault"][data-id="__all_vaults__"]',
  );
  assert.equal(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-vault"]'),
    allVaults,
  );
  assert.equal(allVaults?.querySelector('.onepassword-vault-count')?.textContent, '(4)');
  testingLibrary.fireEvent.click(allVaults!);
  const aggregatedItem = await testingLibrary.waitFor(() => {
    const item = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-item"][data-id="item-cloudflare"]',
    );
    assert.ok(item);
    return item;
  });
  assert.equal(aggregatedItem.dataset.vaultId, 'vault-shared');
  assert.equal(aggregatedItem.querySelector('small')?.textContent, 'Shared Services · API Credential');
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button.onepassword-list-back')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"][data-id="vault-empty"]'));
  });
  const emptyVault = dialog.querySelector<HTMLButtonElement>(
    'button[data-act="onepassword-vault"][data-id="vault-empty"]',
  );
  assert.equal(emptyVault?.querySelector('.onepassword-vault-count')?.textContent, '(0)');
  testingLibrary.fireEvent.click(emptyVault!);
  await testingLibrary.waitFor(() => {
    assert.equal(dialog.querySelector('.onepassword-list-empty')?.textContent, 'No items');
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button.onepassword-list-back')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"][data-id="vault-empty"]'));
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );

  await openVaultsPanel();
  const row = await testingLibrary.waitFor(() => {
    const candidate = vaultRowByLabel('Recovery Account');
    assert.ok(candidate);
    assert.equal(candidate.querySelector('.onepassword-integration-icon'), null);
    // Method stays under the name; the linked-count hint line is gone.
    const copy = candidate.querySelector('.onepassword-integration-copy');
    assert.equal(copy?.textContent, 'Recovery AccountService account');
    return candidate;
  });
  testingLibrary.fireEvent.click(
    row.querySelector<HTMLButtonElement>('button[data-act="onepassword-browse"]')!,
  );
  dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Edit linked credentials',
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );

  const menuRow = await openVaultsPanel().then(() => testingLibrary.waitFor(() => {
    const candidate = vaultRowByLabel('Recovery Account');
    assert.ok(candidate);
    return candidate;
  }));
  testingLibrary.fireEvent.click(
    menuRow.querySelector<HTMLButtonElement>('button[data-act="toggle-vault-menu"]')!,
  );
  const update = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      '.vault-menu-wrap button[data-act="onepassword-update"]',
    );
    assert.ok(button);
    assert.equal(button.textContent, 'Edit connection method…');
    return button;
  });
  testingLibrary.fireEvent.click(update);
  dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Update 1Password credential',
  });
  assert.equal(dialog.querySelector('.onepassword-steps'), null);
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'replacement-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => assert.ok(!document.querySelector('.onepassword-sheet')));

  await openVaultsPanel();
  const updatedRow = await testingLibrary.waitFor(() => {
    const candidate = vaultRowByLabel('Recovery Account');
    assert.ok(candidate);
    return candidate;
  });
  testingLibrary.fireEvent.click(
    updatedRow.querySelector<HTMLButtonElement>('button[data-act="toggle-vault-menu"]')!,
  );
  const remove = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      '.vault-menu-wrap button[data-act="onepassword-delete-ask"]',
    );
    assert.ok(button);
    return button;
  });
  testingLibrary.fireEvent.click(remove);
  const confirm = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Remove Recovery Account?',
  });
  assert.ok(confirm.textContent?.includes(
    'Multitool will remove the connected vault and credentials. No 1Password items will be changed.',
  ));
  testingLibrary.fireEvent.click(
    confirm.querySelector<HTMLButtonElement>('button[data-act="onepassword-delete-confirm"]')!,
  );
  // The surviving connection keeps the popover available; the removed one is
  // gone from it.
  await openVaultsPanel();
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelectorAll('.onepassword-integration-row').length >= 1);
    assert.equal(vaultRowByLabel('Recovery Account'), undefined);
  });
});

test('legacy remote brokers disable the 1Password surface', async () => {
  const mock = await import('../src/mock-bridge');
  await mock.invoke('connect_remote_broker', {
    url: 'https://legacy.example.test',
    token: 'akamgr_test',
  });
  goToTab('secrets');
  const connect = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
    assert.ok(button);
    assert.equal(button.disabled, true);
    return button;
  });
  // The vault control is icon-only in the toolbar, so its state lives in the
  // accessible name rather than a visible word.
  assert.equal(connect.textContent?.trim(), '');
  assert.match(connect.getAttribute('aria-label') ?? '', /unavailable/i);
  assert.match(connect.title, /remote broker/i);

  await mock.invoke('switch_broker_local');
  // Back on the local broker, the earlier tests' surviving connection
  // reloads and the vault surface returns.
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('button[data-act="toggle-vaults-panel"]'));
  });
  goToTab('connections');
});

test('dismissed sample tools can be restored from settings', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Hide sample tools' }),
  );
  assert.equal(
    testingLibrary.queryByRole(document.body, 'button', { name: 'Hide sample tools' }),
    null,
  );

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Menu' }),
  );
  const openSettings = document.querySelector<HTMLButtonElement>(
    'button[data-act="open-settings"]',
  );
  assert.ok(openSettings);
  testingLibrary.fireEvent.click(openSettings);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  const showSamples = testingLibrary.getByRole(dialog, 'checkbox', { name: 'Show sample tools' });
  assert.equal(showSamples.getAttribute('aria-checked'), 'false');
  testingLibrary.fireEvent.click(showSamples);
  assert.equal(showSamples.getAttribute('aria-checked'), 'true');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Done' }),
  );

  assert.ok(testingLibrary.getByRole(document.body, 'button', { name: 'Hide sample tools' }));
});

// Options are compared by their data-id, never by node identity: a failed
// assert.equal on two jsdom elements spends minutes inspecting the DOM graph
// to build its diff, which reads as a hung test rather than a failed one.
const activeOptionId = (): string | null | undefined =>
  document.activeElement?.getAttribute('data-id');

test('the hero-sentence menus open and move under the arrow keys', async () => {
  goToTab('start');
  const blank = await testingLibrary.waitFor(() => {
    const trigger = document.querySelector<HTMLButtonElement>('#start-blank-client');
    assert.ok(trigger, 'the client blank renders on the Connect agents tab');
    return trigger;
  });

  // ArrowDown on a closed blank opens its listbox on the current choice.
  blank.focus();
  testingLibrary.fireEvent.keyDown(blank, { key: 'ArrowDown' });
  const ids = await testingLibrary.waitFor(() => {
    const options = [...document.querySelectorAll<HTMLElement>('.start-menu [role="option"]')];
    assert.ok(options.length > 2, 'the client menu has options to walk');
    assert.equal(document.activeElement?.getAttribute('aria-selected'), 'true');
    return options.map((option) => option.dataset.id);
  });
  const last = ids[ids.length - 1];

  // Arrows step, Home/End jump, and neither runs off an end of the list.
  const press = (key: string): void => {
    testingLibrary.fireEvent.keyDown(document.activeElement as HTMLElement, { key });
  };
  press('Home');
  assert.equal(activeOptionId(), ids[0]);
  press('ArrowUp');
  assert.equal(activeOptionId(), ids[0]);
  press('ArrowDown');
  assert.equal(activeOptionId(), ids[1]);
  press('ArrowUp');
  assert.equal(activeOptionId(), ids[0]);
  press('End');
  assert.equal(activeOptionId(), last);
  press('ArrowDown');
  assert.equal(activeOptionId(), last);

  // Tab leaves the menu and Escape closes it — both hand the keyboard back to
  // the blank rather than dropping it on the document. ArrowUp reopens from
  // the far end, the way a native select does.
  press('Tab');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-client');
  });
  press('ArrowUp');
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.start-menu'));
    assert.equal(activeOptionId(), last);
  });
  press('Escape');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-client');
  });

  // Activating an option — the options are real buttons, so Enter clicks
  // them — rewrites the sentence and leaves focus on the blank it changed.
  const toolBlank = document.querySelector<HTMLButtonElement>('#start-blank-tool')!;
  const before = toolBlank.textContent;
  toolBlank.focus();
  testingLibrary.fireEvent.keyDown(toolBlank, { key: 'ArrowDown' });
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.start-menu'));
    assert.equal(document.activeElement?.getAttribute('aria-selected'), 'true');
  });
  press('ArrowDown');
  testingLibrary.fireEvent.click(document.activeElement as HTMLElement);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-tool');
    assert.notEqual(document.querySelector('#start-blank-tool')?.textContent, before);
  });
});

test('the activity agent filter holds one agent at a time', async () => {
  goToTab('activity');
  const trigger = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      'button[data-act="act-filter-agent-menu"]',
    );
    assert.ok(button, 'the activity filters offer an agent picker');
    return button;
  });
  assert.equal(document.querySelector('.act-tool'), null,
    'activity rows no longer repeat tool names in trailing badges');
  // The default covers every agent, so the picker starts unpressed.
  assert.equal(trigger.textContent, 'Agent:All');
  assert.equal(trigger.classList.contains('on'), false);

  testingLibrary.fireEvent.click(trigger);
  const options = await testingLibrary.waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.act-filter-menu [role="option"]')];
    assert.ok(found.length > 2, 'the menu lists the default plus the agents seen');
    return found;
  });
  assert.equal(options[0].textContent, 'All agents');
  assert.equal(options[0].getAttribute('aria-selected'), 'true');

  const agent = options[1].dataset.value!;
  testingLibrary.fireEvent.click(options[1]);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.act-filter-menu'), null);
    assert.equal(trigger.textContent, `Agent:${agent}`);
    assert.ok(trigger.classList.contains('on'));
  });

  // Every mounted entry belongs to the chosen agent — one filter, not the
  // union the chip row allowed.
  const chips = [...document.querySelectorAll<HTMLElement>('.act-chip.untrusted-identity')];
  assert.ok(chips.length, 'the filtered list still has entries');
  for (const chip of chips) assert.equal(chip.textContent, `reported as “${agent}”`);

  testingLibrary.fireEvent.click(trigger);
  const back = await testingLibrary.findByRole(document.body, 'option', { name: 'All agents' });
  testingLibrary.fireEvent.click(back);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.act-filter-menu'), null);
    assert.equal(trigger.textContent, 'Agent:All');
    assert.equal(trigger.classList.contains('on'), false);
  });
});

test('key rotation requires an ordinary destructive confirmation', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Menu' }),
  );
  const openSettings = document.querySelector<HTMLButtonElement>(
    'button[data-act="open-settings"]',
  );
  assert.ok(openSettings);
  testingLibrary.fireEvent.click(openSettings);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Rotate key…' }),
  );
  const confirmation = await testingLibrary.findByRole(
    document.body,
    'dialog',
    { name: 'Rotate this computer’s agent key?' },
  );
  assert.match(confirmation.textContent ?? '', /direct endpoint stops working immediately/);
  assert.ok(testingLibrary.getByRole(confirmation, 'button', { name: 'Rotate key' }));
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(confirmation, 'button', { name: 'Cancel' }),
  );
});

test('the app lock takes over both windows and is armed from Settings', async () => {
  // Self-contained: whatever the previous test left open is dismissed before
  // this one opens Settings for itself.
  const openSheet = testingLibrary.queryByRole(document.body, 'button', { name: 'Done' });
  if (openSheet) testingLibrary.fireEvent.click(openSheet);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.sheet-backdrop'), null);
  });

  // Lock Now is a one-shot action, independent of the automatic-lock
  // preference. It must work on a fresh install without also arming the
  // five-minute idle timer.
  testingLibrary.fireEvent.keyDown(document.body, { key: 'l', metaKey: true });
  const manualLock = await testingLibrary.findByLabelText(
    document.body, 'Multitool is locked',
  );
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(manualLock, 'button', { name: 'Enter password…' }),
  );
  for (let tries = 0; tries < 50 && document.querySelector('.lock-takeover'); tries += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(document.querySelector('.lock-takeover'), null);

  // Settings is reached through the title bar's app menu.
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Menu' }),
  );
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('.settings-menu button[data-act="open-settings"]')!,
  );
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  const toggle = testingLibrary.getByRole(dialog, 'checkbox', { name: 'Lock automatically' });
  assert.equal(toggle.getAttribute('aria-checked'), 'false');
  // The idle and put-away rows only exist once the lock is armed — an
  // unarmed lock has no schedule to configure.
  assert.equal(testingLibrary.queryByRole(dialog, 'radiogroup', { name: 'Lock when idle' }), null);

  testingLibrary.fireEvent.click(toggle);
  const idle = await testingLibrary.findByRole(dialog, 'radiogroup', { name: 'Lock when idle' });
  assert.deepEqual(
    [...idle.querySelectorAll<HTMLButtonElement>('.seg-btn')].map((b) => b.textContent),
    ['Never', '1 min', '5 min', '15 min', '1 hr'],
  );
  assert.equal(
    idle.querySelector('[data-id="300"]')?.getAttribute('aria-checked'),
    'true',
    'five minutes is the default delay',
  );
  assert.ok(testingLibrary.getByRole(dialog, 'checkbox', { name: 'Lock when closed' }));
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Done' }),
  );

  const mock = await import('../src/mock-bridge');
  await mock.invoke('lock_app');
  const lock = await testingLibrary.findByLabelText(document.body, 'Multitool is locked');
  assert.equal(lock.getAttribute('role'), 'dialog');
  assert.equal(lock.getAttribute('aria-modal'), 'true');
  // The inline Touch ID control is a native view parented over this slot, so
  // the webview must leave the hole and report where it is.
  const slot = lock.querySelector('.lock-sensor-slot');
  assert.ok(slot, 'the lock card leaves a slot for the native control');
  assert.equal(slot.textContent, '', 'nothing renders inside the slot');
  // Touch ID being armed already makes the button the password fallback.
  assert.ok(testingLibrary.getByRole(lock, 'button', { name: 'Enter password…' }));
  // The scope disclaimer is part of the lock screen, not a settings footnote:
  // this gate covers the windows, not the broker behind them.
  assert.match(lock.textContent ?? '', /Agents keep working while the app is locked/);
  // Locking closes whatever sheet was open rather than leaving it under the
  // takeover, and takes the settings menu with it.
  assert.equal(document.querySelector('.settings-menu'), null);

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(lock, 'button', { name: 'Enter password…' }),
  );
  // Polled directly rather than through waitFor: the unlock resolves from a
  // promise outside React's act(), which waitFor's act wrapper waits on
  // forever.
  for (let tries = 0; tries < 50 && document.querySelector('.lock-takeover'); tries += 1) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(document.querySelector('.lock-takeover'), null, 'the takeover is dismissed');
  assert.ok(document.querySelector('.surface'), 'the window is back');

  // Leave the shared app instance as the other tests expect to find it.
  await mock.invoke('set_lock_settings', {
    settings: { enabled: false, autoLockSecs: 300, lockOnHide: false },
  });
});
