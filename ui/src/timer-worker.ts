// The timer half of `unthrottledTimeout` (see worker-timer.ts): a map of
// plain setTimeout calls, running where the page's throttling rules do not
// apply. Messages in are `{id, ms}` to schedule and `{cancel}` to revoke;
// the only message out is the id of a timer that fired.

interface TimerCommand {
  id?: number;
  ms?: number;
  cancel?: number;
}

// `self` in a dedicated worker is DedicatedWorkerGlobalScope, whose
// one-argument postMessage the DOM lib's window typing does not cover.
const scope = self as unknown as {
  onmessage: ((event: MessageEvent<TimerCommand>) => void) | null;
  postMessage(value: number): void;
};

const timers = new Map<number, ReturnType<typeof setTimeout>>();

scope.onmessage = (event: MessageEvent<TimerCommand>) => {
  const { id, ms, cancel } = event.data;
  if (cancel !== undefined) {
    const handle = timers.get(cancel);
    if (handle !== undefined) clearTimeout(handle);
    timers.delete(cancel);
    return;
  }
  if (id === undefined || ms === undefined) return;
  timers.set(id, setTimeout(() => {
    timers.delete(id);
    scope.postMessage(id);
  }, ms));
};
