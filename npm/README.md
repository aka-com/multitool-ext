# aka CLI npm distribution

This directory is the npm distribution of the `aka` CLI, published as
[`aka-agent`](https://www.npmjs.com/package/aka-agent).

This is an open-source package (MIT License) that follows an esbuild-style layout:

- `aka-agent/` — the package users install. It contains a Node launcher
  (`bin/aka.js`, exposed as `aka`). The launcher executes the prebuilt binary. It
  declares one exact-pinned `optionalDependency` per platform; npm installs the
  single matching one.
- `aka-agent-{darwin,linux}-{arm64,x64}/` — per-platform packages whose CLI
  payload is `bin/aka`, published under the `@aka-com` scope for that
  `os`/`cpu` pair. The binaries are staged by `scripts/npm-dist.sh` and are
  gitignored; only the manifests are checked in.

There are no postinstall scripts and no install-time downloads. Node
22 or newer is required, as the MCP host runtime.

## Versioning

The Cargo workspace version in the root `Cargo.toml` is the single source of
truth (it is what `aka --version` reports). All five `package.json` files must
carry the same version, with the launcher's `optionalDependencies` pinned
exactly. After bumping the workspace version, run:

```sh
node scripts/npm/sync-versions.mjs          # stamp the npm manifests
node scripts/npm/sync-versions.mjs --check  # verify only (CI/test mode)
```

`pnpm test` (via `pnpm run npm:check`) and `scripts/npm-dist.sh` both run the
check, so drift fails fast. The launcher also refuses at runtime to execute a
platform package whose version differs from its own.

## Building and local testing

```sh
pnpm run npm:dist    # build, verify, stage, and pack every supported target
```

This runs `scripts/npm-dist.sh --all --pack`, producing all four platform
packages plus the launcher and its single-file MCP host in `dist/npm/`. For
Linux cross-builds it prefers matching GNU tools when installed and otherwise
uses the repo's wrappers with Zig. Explicit Cargo/CC/CXX/AR target variables
are preserved. Use `scripts/npm-dist.sh --target TRIPLE --pack` on native
CI runners when a single cross-build host is not available, then aggregate
the staged `bin/aka` files.

The command keeps its npm cache under `target/npm-cache`; set `AKA_NPM_CACHE`
to override that location.

Smoke-test a native pair from the result in a scratch prefix:

```sh
npm install --global --prefix /tmp/aka-agent-test \
    dist/npm/aka-com-aka-agent-linux-x64-*.tgz \
    dist/npm/aka-agent-[0-9]*.tgz
/tmp/aka-agent-test/bin/aka --version
/tmp/aka-agent-test/bin/aka skill | head
```

## Platform support

Supported today: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`
(glibc). Not covered yet:

- **musl/Alpine**: either add `aka-agent-linux-{x64,arm64}-musl` packages, or
  build the linux binaries as static musl artifacts so one package covers
  both libcs.
- **Windows**: unsupported by the broker itself (Unix-domain-socket
  rendezvous, termios, `std::os::unix`); the launcher and the main package's
  `os` field both say so explicitly.
