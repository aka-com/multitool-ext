#!/usr/bin/env node
"use strict";

// Launcher for the `aka-agent` npm package. The real CLI is the prebuilt Rust
// `aka` binary shipped in the platform-specific package that npm selected via
// optionalDependencies (aka-agent-<os>-<arch>); this script only resolves it
// and hands over argv. There is deliberately no postinstall step and no
// network access here: a credential broker's install should be inert.

const { spawnSync } = require("child_process");

const PLATFORM_PACKAGES = {
  "darwin arm64": "@aka-com/aka-agent-darwin-arm64",
  "darwin x64": "@aka-com/aka-agent-darwin-x64",
  "linux arm64": "@aka-com/aka-agent-linux-arm64",
  "linux x64": "@aka-com/aka-agent-linux-x64",
};

function fail(message) {
  console.error(`aka: ${message}`);
  process.exit(1);
}

function resolveBinary() {
  // Escape hatch for development and unusual layouts: point AKA_BIN at any
  // `aka` binary (e.g. target/release/aka) and the launcher uses it. Keep the
  // former override names as compatibility fallbacks for local release tooling.
  if (process.env.AKA_BIN) return process.env.AKA_BIN;
  if (process.env.MULTITOOL_BIN) return process.env.MULTITOOL_BIN;
  if (process.env.AGENTMFA_BIN) return process.env.AGENTMFA_BIN;

  const key = `${process.platform} ${process.arch}`;
  const pkg = PLATFORM_PACKAGES[key];
  if (!pkg) {
    fail(
      `unsupported platform ${key}; prebuilt binaries exist for ` +
        `${Object.keys(PLATFORM_PACKAGES).join(", ")}. The broker is ` +
        "Unix-only (Unix domain sockets), so Windows is not supported."
    );
  }

  let binPath;
  try {
    binPath = require.resolve(`${pkg}/bin/aka`);
  } catch {
    fail(
      `the ${pkg} package holding the binary for ${key} is not installed.\n` +
        "It is an optionalDependency of aka-agent: reinstall without " +
        "--no-optional/--omit=optional, and make sure your package manager " +
        "installs platform-specific optional dependencies."
    );
  }

  // npm can leave a stale platform package behind across updates (hoisting,
  // lockfile edits); running a binary from another release would be
  // confusing at best for a security tool, so refuse the mismatch.
  const want = require("../package.json").version;
  const got = require(`${pkg}/package.json`).version;
  if (want !== got) {
    fail(
      `version mismatch: aka-agent@${want} resolved ${pkg}@${got}; ` +
        "reinstall aka-agent to repair the pairing."
    );
  }
  return binPath;
}

const result = spawnSync(resolveBinary(), process.argv.slice(2), {
  stdio: "inherit",
});
if (result.error) {
  fail(result.error.message);
}
if (result.signal) {
  // Re-raise so callers observe the same signal-death the CLI had.
  process.kill(process.pid, result.signal);
}
process.exit(result.status === null ? 1 : result.status);
