// Differential test: the TypeScript `intoSpec` port vs. the Rust
// `ConnectionInput::into_spec` it mirrors.
//
// The two must produce identical `ConnectionSpec` JSON (and identical form
// errors) for the same `ConnectionInput`, or the web app will send the broker
// a body that doesn't match what the desktop sends.
//
// How the cross-language check works:
//   - `fixtures/into-spec-cases.json`  — the shared inputs, fed to BOTH impls.
//   - `fixtures/into-spec-golden.json` — the expected output. It is the
//     arbiter, and the Rust side owns it: run the Rust test on macOS to
//     regenerate it from the *real* into_spec, which is the source of truth.
//   - This test runs the TS port over the cases and asserts it equals the
//     golden.
//
// To run the full differential (from the repo root):
//   1. On macOS (src-tauri only builds there):
//        INTO_SPEC_REGEN=1 cargo test -p multitool-desktop into_spec_differential
//      writes the golden from the real into_spec, then
//        cargo test -p multitool-desktop into_spec_differential
//      asserts the real into_spec still matches it.
//   2. Anywhere:
//        pnpm run test:ui
//      runs this test — the TS port against that same golden.
// Both green ⟹ the two implementations agree. (Substitute the crate's real
// package name for `multitool-desktop` if it differs — see src-tauri/Cargo.toml.)

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { intoSpec } from '../src/connection-spec';
import type { ConnectionInput } from '../src/types';

interface Case {
  name: string;
  input: ConnectionInput;
}

const cases: Case[] = JSON.parse(
  readFileSync(new URL('./fixtures/into-spec-cases.json', import.meta.url), 'utf8'),
);
const golden: Record<string, unknown> = JSON.parse(
  readFileSync(new URL('./fixtures/into-spec-golden.json', import.meta.url), 'utf8'),
);

/** The TS result, reduced to the same `{ spec } | { error: { code, field? } }`
 * shape the golden records — message prose is presentation, not contract. */
function comparable(input: ConnectionInput): unknown {
  const result = intoSpec(input);
  if (result.ok) return { spec: result.spec };
  const error: Record<string, unknown> = { code: result.code };
  if (result.field !== undefined) error.field = result.field;
  return { error };
}

test('every case has a golden and every golden has a case', () => {
  const caseNames = new Set(cases.map((c) => c.name));
  const goldenNames = new Set(Object.keys(golden));
  for (const name of caseNames) {
    assert.ok(goldenNames.has(name), `case "${name}" has no golden entry`);
  }
  for (const name of goldenNames) {
    assert.ok(caseNames.has(name), `golden "${name}" has no case`);
  }
  assert.ok(cases.length >= 20, 'the corpus should be reasonably thorough');
});

for (const testCase of cases) {
  test(`into_spec parity: ${testCase.name}`, () => {
    assert.deepEqual(comparable(testCase.input), golden[testCase.name]);
  });
}
