import assert from "node:assert/strict";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  ".."
);
const launcher = path.join(
  repoRoot,
  "npm",
  "aka-agent",
  "bin",
  "aka.js"
);

function cleanLauncherEnv(capture) {
  const env = { ...process.env, AKA_CAPTURE: capture };
  delete env.AKA_BIN;
  delete env.MULTITOOL_BIN;
  delete env.AGENTMFA_BIN;
  return env;
}

function runLauncher(override = "AKA_BIN") {
  const dir = mkdtempSync(path.join(os.tmpdir(), "aka-launcher-"));
  const stub = path.join(dir, "aka-stub");
  const capture = path.join(dir, "capture.json");
  writeFileSync(
    stub,
    `#!/bin/sh
printf '{"args":"%s"}' "$*" > "$AKA_CAPTURE"
`,
  );
  chmodSync(stub, 0o755);

  const env = cleanLauncherEnv(capture);
  env[override] = stub;

  const result = spawnSync(
    process.execPath,
    [launcher, "serve", "--root", "/tmp/aka-test"],
    { env, encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(readFileSync(capture, "utf8"));
}

test("launcher hands arguments to the platform binary", () => {
  const captured = runLauncher();
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});

test("launcher resolves the renamed platform package and aka binary", () => {
  const platforms = {
    "darwin arm64": "aka-agent-darwin-arm64",
    "darwin x64": "aka-agent-darwin-x64",
    "linux arm64": "aka-agent-linux-arm64",
    "linux x64": "aka-agent-linux-x64",
  };
  const platform = platforms[`${process.platform} ${process.arch}`];
  assert.ok(platform, `test host ${process.platform} ${process.arch} must be supported`);

  const dir = mkdtempSync(path.join(os.tmpdir(), "aka-installed-layout-"));
  const packageDir = path.join(dir, "aka-agent");
  const packageBin = path.join(packageDir, "bin");
  const nativeDir = path.join(packageDir, "node_modules", "@aka-com", platform);
  const nativeBin = path.join(nativeDir, "bin");
  mkdirSync(packageBin, { recursive: true });
  mkdirSync(nativeBin, { recursive: true });
  copyFileSync(launcher, path.join(packageBin, "aka.js"));

  const version = "9.8.7-test";
  writeFileSync(
    path.join(packageDir, "package.json"),
    `${JSON.stringify({ name: "aka-agent", version })}\n`
  );
  writeFileSync(
    path.join(nativeDir, "package.json"),
    `${JSON.stringify({ name: `@aka-com/${platform}`, version })}\n`
  );

  const stub = path.join(nativeBin, "aka");
  const capture = path.join(dir, "capture.json");
  writeFileSync(
    stub,
    `#!/bin/sh
printf '{"args":"%s"}' "$*" > "$AKA_CAPTURE"
`
  );
  chmodSync(stub, 0o755);

  const result = spawnSync(
    process.execPath,
    [path.join(packageBin, "aka.js"), "status", "--json"],
    { env: cleanLauncherEnv(capture), encoding: "utf8" }
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(capture, "utf8")).args, "status --json");
});

test("launcher keeps the legacy AGENTMFA_BIN override working", () => {
  const captured = runLauncher("AGENTMFA_BIN");
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});

test("launcher keeps the legacy MULTITOOL_BIN override working", () => {
  const captured = runLauncher("MULTITOOL_BIN");
  assert.equal(captured.args, "serve --root /tmp/aka-test");
});
