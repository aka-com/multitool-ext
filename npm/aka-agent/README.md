# Multitool

Multitool is a credential broker for AI coding agents. Agents make API
calls, open database connections, and reach SSH servers using
unmodified tools like `curl`, `psql`, and `git`.

The broker keeps the raw credentials in a local secret store and
injects them on the upstream leg only, so agents never hold them.
Access is authorized per tool: an enabled connection executes
immediately, a disabled one is refused for every agent at once.

This package installs the broker's command line as `aka`. It includes the headless
broker, store-seeding commands, and the skill-file generator that teaches
agents how to use the broker.

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN plus a short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` that signs only for the
  connection's pinned user and server host key

## Install

```sh
npm install -g aka-agent
```

This requires Node 22 or newer. It installs a prebuilt binary via a
platform-specific optional dependency. There is no postinstall script and no
install-time network access beyond npm itself.

Supported platforms: macOS (Apple silicon and Intel) and Linux
(x64 and arm64, glibc). The broker rendezvous is a Unix domain socket, so
Windows is not supported.

## Quick start

The **desktop app** owns the local production store (`~/.aka` and the
per-user data directory). **`aka serve`** runs a separate headless
broker under `~/.akaserver` by default so it can sit beside the app
without colliding. Override with `--root` or `AKA_SERVER_ROOT` (`--root`
wins). By default it listens on `127.0.0.1:4780` and advertises the
passkey-compatible public URL `http://localhost:4780`, where it serves its
bundled web interface and manage API. Use `--no-web` for API-only TCP
operation, `--no-listen` for Unix-socket-only operation, or override
`--listen` and `--public-url` for a remote/hosted deployment.

```sh
# Headless broker (default root ~/.akaserver). Same machine as the app is fine.
aka serve

# Open http://localhost:4780. First browser sign-in:
aka admin enroll --root ~/.akaserver

# First start writes ~/.akaserver/sock/manage-token (0600). Rotate while live:
aka manage token --root ~/.akaserver

# Seed / manage that root (always pass the same --root, or use --broker):
printf '%s' "$GITHUB_TOKEN" | aka secret add GITHUB_TOKEN --root ~/.akaserver
aka conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}' --root ~/.akaserver
aka conn list --root ~/.akaserver
```

CLI mutations without `--root` still target the **desktop production store**
(online against Multitool, or offline against its files). They do not aim at
`~/.akaserver` unless you pass `--root` (or manage over `--broker <url>`).

```sh
aka conn list --broker https://broker.example.dev   # hosted / remote
aka manage login --broker https://broker.example.dev
```

`aka manage login --broker <url>` stores a token for a remote broker
(macOS: the Keychain; elsewhere a 0600 file), and `AKA_MANAGE_TOKEN`
overrides for CI. `aka manage token --broker <url>` rotates using that
credential. With no broker running, bare commands fall back to editing the
production store offline.

The operator's view is covered by `aka key` (print the shared agent
key; `--rotate` disconnects every agent at once), `aka status` (is a
broker up, and what does it serve), and `aka activity` (the audit
trail, readable while the broker runs). Point them at a headless root with
`--root`.

Open Postgres and SSH sessions from a running broker — each command prints
the one value a stock client needs (the DSN embeds a short-lived session
ticket). Use Multitool for the local store, or `--root` / the headless token:

```sh
psql "$(aka dsn analytics)"                          # local app broker
export SSH_AUTH_SOCK="$(aka ssh production --root ~/.akaserver)"
```

Teach agents about a broker:

```sh
aka skill --write          # production / local Multitool layout
aka skill --write --user
aka skill --write --root ~/.akaserver
aka skill --write --broker https://broker.example.dev
```

Local agents on the desktop broker discover the contract from its socket;
headless / hosted agents use that root's token or the TCP URL:

```sh
curl --unix-socket ~/.aka/broker.sock http://localhost/instructions
curl --unix-socket ~/.akaserver/sock/broker.sock http://localhost/instructions
```

Every command accepts `--root <dir>` for an isolated directory (data and
socket under it). `aka serve` defaults to `~/.akaserver`, its loopback TCP
listener, its localhost public URL, and the bundled web interface; other
commands default to the production layout unless `--root` is set.

## Platform notes

- **macOS** is the fully supported product platform: secrets live in the
  Keychain. Explicit app actions authorize management changes, and copies are
  audited. ABP/0 agents authenticate with the machine's shared broker key; the
  key is not bound to a process or code-signing identity.

  The signed Multitool app reads its Keychain items without any OS approval
  dialog, because it is entitled to the data-protection keychain. This `aka`
  binary is published unsigned, so when it opens the store *offline* (with no
  broker running) it uses the login keychain and macOS asks you to approve
  each item. Working against a running broker — the normal path, and every
  `--broker` command — goes over the socket and never touches the Keychain.
  `aka status` reports which keychain the store is on.
- **Linux** uses a `0600` JSON development vault when no master key is
  configured. That fallback is **not encrypted at rest**, and `aka serve`
  prints a warning. Set `AKA_VAULT_KEY` or `AKA_VAULT_KEY_FILE` to use the
  encrypted XChaCha20-Poly1305 file vault. Never expose a network broker with
  the plaintext fallback; follow the
  [hosted Linux runbook](https://github.com/aka-com/multitool/blob/main/dev/hosted-linux/README.md)
  for deployment.
