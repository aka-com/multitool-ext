// A setTimeout that keeps its schedule while the tab is hidden.
//
// Page timers are throttled to roughly one tick a minute once a tab has
// been backgrounded for a while; a dedicated worker's are not. The
// approval-surface heartbeat runs on a 5-second cadence against a
// 15-second lease, so the page-timer version silently dropped the lease
// whenever the tab was hidden — and with it the broker's permission to
// hand prompts to this page, turning "tab in another window" into "agent
// traffic refused with nobody asked".
//
// One worker for the whole page, created on first use. Falls back to a
// plain page timer where workers are unavailable (the node test runner) or
// fail to start (a packaging problem) — throttled beats never.

let worker: Worker | null | undefined;
const callbacks = new Map<number, () => void>();
let nextId = 0;

function timerWorker(): Worker | null {
  if (worker !== undefined) return worker;
  if (typeof Worker === 'undefined') {
    worker = null;
    return worker;
  }
  try {
    worker = new Worker(new URL('./timer-worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<number>) => {
      const callback = callbacks.get(event.data);
      callbacks.delete(event.data);
      callback?.();
    };
    worker.onerror = () => {
      // A worker that cannot start must not eat every scheduled callback.
      // Re-arm what was queued on page timers and stay on them for the
      // life of the page.
      const pending = [...callbacks.values()];
      callbacks.clear();
      worker?.terminate();
      worker = null;
      for (const callback of pending) setTimeout(callback, 1_000);
    };
  } catch {
    worker = null;
  }
  return worker;
}

/**
 * Run `callback` after `ms` milliseconds on the worker's clock. Returns a
 * cancel function (the callback is dropped even if the tick still arrives).
 */
export function unthrottledTimeout(callback: () => void, ms: number): () => void {
  const timers = timerWorker();
  if (!timers) {
    const handle = setTimeout(callback, ms);
    return () => clearTimeout(handle);
  }
  const id = ++nextId;
  callbacks.set(id, callback);
  timers.postMessage({ id, ms });
  return () => {
    if (callbacks.delete(id)) timers.postMessage({ cancel: id });
  };
}
