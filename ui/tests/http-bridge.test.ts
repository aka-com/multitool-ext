import assert from 'node:assert/strict';
import test from 'node:test';

test('the browser holds an approval-surface lease while its event observer is live', async () => {
  const requests: Array<{ method: string; path: string; csrf: string | null }> = [];
  let eventSourceClosed = false;

  class FakeEventSource {
    static readonly CLOSED = 2;
    readonly readyState = 1;
    onmessage: ((event: MessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;

    constructor(readonly url: string, readonly options: EventSourceInit) {}

    close(): void {
      eventSourceClosed = true;
    }
  }

  globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
  globalThis.fetch = (async (input, init = {}) => {
    const path = String(input);
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    requests.push({ method, path, csrf: headers.get('x-multitool-csrf') });
    if (path === '/v1/auth/session') {
      return Response.json({
        account: 'operator',
        session: 'session-1',
        scopes: ['identity:manage'],
        authenticated_at: null,
        csrf: 'csrf-1',
      });
    }
    if (method === 'POST' && path === '/v1/manage/approval-surfaces') {
      return Response.json({ id: 'surface/1', expires_in_ms: 15_000 });
    }
    if (method === 'DELETE' && path === '/v1/manage/approval-surfaces/surface%2F1') {
      return Response.json({ released: true });
    }
    if (method === 'POST' && path === '/v1/auth/logout') {
      return new Response(null, { status: 204 });
    }
    throw new Error(`unexpected request: ${method} ${path}`);
  }) as typeof fetch;

  const bridge = await import('../src/http-bridge');
  await bridge.listen('aka://approvals-changed', () => {});

  assert.deepEqual(requests.slice(0, 2), [
    { method: 'GET', path: '/v1/auth/session', csrf: null },
    { method: 'POST', path: '/v1/manage/approval-surfaces', csrf: 'csrf-1' },
  ]);

  await bridge.signOut();
  assert.equal(eventSourceClosed, true);
  assert.deepEqual(requests.slice(2), [
    {
      method: 'DELETE',
      path: '/v1/manage/approval-surfaces/surface%2F1',
      csrf: 'csrf-1',
    },
    { method: 'POST', path: '/v1/auth/logout', csrf: 'csrf-1' },
  ]);
});
