# Multitool

Multitool lets your agents make API calls, connect to databases and
servers, and talk to MCPs without exposing credentials.

It combines a secrets vault, connection broker, and tool router into
one application, so your agents can use unmodified CLI tools like
`curl`, `psql`, and `git`, with credentials stored in a secure vault.

Install the CLI on macOS or Linux with:

```sh
npm install -g aka-agent
```

## How it works

Giving an agent real access usually means pasting live credentials
into its environment, whether through a `.env` file or global
environment variables. That means:

- Every agent holds every secret in plaintext, in context.
- A prompt injection can copy those plaintext credentials and use them
  outside the intended service.
- Rotating a key means hunting down every config that copied it.
- Use may leave no central record.

Multitool sits between your agents and everything they reach. Agents
talk to services through a local proxied endpoint to make API calls or
open database connections. The real upstream credential is injected on
the upstream leg only and never enters agent context. Multitool records
brokered use and lets you disable a connection centrally instead of
redistributing its upstream credential.

Multitool is primarily tested locally today, but a hosted version has
been implemented for a shared vault. Hosted mode is one broker per trust
domain, not a multi-user authorization system: see [HOSTING.md](HOSTING.md)
before exposing it to a network. We also support limited audit logging,
and team management is coming soon.

### Security boundary

Multitool keeps the real API token, database password, or SSH private key
out of the agent's files and context. It does not sandbox agents from one
another. Every process running as the same local user can read the shared
0600 broker key (or pair over the private local socket) and can use every
connection currently enabled for agents. Client labels are self-reported
audit attribution, not identities or authorization boundaries.

Connections are enabled for agents by default when added. Turning one off
prevents new calls and closes broker-owned HTTP/Postgres sessions; an SSH
login that already authenticated is between the SSH client and server and
cannot be terminated by the broker. Rotating the broker key is the broad
revocation action: it revokes tickets and standing endpoints and closes
broker-owned sessions, but it still cannot kill an already-authenticated SSH
process.

Direct endpoints deliberately expose a separate broker credential to their
client. Each one expires after 30 days; renewal preserves the address and
secret so long-lived client configuration does not need to change, while
rotation invalidates the old secret immediately. Treat that endpoint secret
like any other standing credential and revoke or rotate it if copied somewhere
untrusted. Response scrubbing removes recognized reflections of injected
credentials, but cannot guarantee that an upstream will not transform or
encode credential material into a new form.

1. **Create a connection.** Select a destination to connect to: an API
   host, Postgres database, SSH server, or MCP server.

2. **Create a secret.** Pin an API token, database password, or SSH key
   inside the application, using the desktop app or `aka secret add`.

3. **Give your agent the endpoint.** Each connection gets its own local
   credential-free endpoint, that you can provide to your agent as a
   DATABASE_URL, SSH endpoint, etc., while MCPs get a unified tool.

   ```sh
   aka run analytics -- psql                       # scoped PG* environment
   aka run production -- ssh production            # scoped signing agent
   aka setup claude-code                           # print MCP client setup
   ```

   `aka run <connection> -- <command>` is the one runner for every kind:
   the connection's kind decides whether the child gets a `PG*`
   environment, a scoped signing agent, temporary cloud credentials, or
   `AKA_URL`/`AKA_TOKEN` for an API endpoint. `aka env <connection>`
   prints the same values as shell exports.

   For each connection type, the broker injects the real credential on
   the upstream connection. Turn the connection off in the app to refuse
   new use; rotate the broker key for broad revocation, subject to the
   already-authenticated SSH limitation above.

## Supported agents

Any agent that uses MCP or the CLI works: Claude Code, Claude Desktop,
Codex, Cursor, your own harness using `curl`.

### Headless CLI

Agent and client onboarding lives under one setup namespace:

```sh
aka setup codex               # print a paste-ready MCP client config
aka setup claude-code --write # apply it: register, write the skill, pin the repo
aka setup skill --write       # install the repo-local agent skill on its own
aka setup instructions        # print the authoritative setup document
```

`--write` registers the MCP server with clients that own their config
through a CLI (Claude Code), writes `.claude/skills/multitool/SKILL.md`,
and pins the working directory to the current context. Clients configured
by editing a file you own (Codex, Claude Desktop) get the stanza printed
and the path named, so nothing rewrites a file holding your other servers.

The former top-level `skill` and `instructions` commands remain hidden
compatibility aliases for existing scripts.

For headless setup, connection creation and updates are grouped by kind so
each command exposes only relevant fields:

```sh
aka serve  # ~/.akaserver, TCP 127.0.0.1:4780, public URL http://localhost:4780
aka conn add pg analytics --host db.example.com --dbname app \
  --user agent --secret DATABASE_PASSWORD
aka conn update pg analytics --sslmode verify-full
```

An add tests itself against the pinned destination as soon as it lands, so
a typo in a host or a stale credential surfaces immediately. The
connection is added either way — a failed test reports and points at
`aka conn test <name>`, it does not roll the add back. Pass `--no-test`
when the destination is not reachable yet.

Per-connection policy is kind-free, so it rides `conn update` by name:

```sh
aka conn update analytics --confirm      # hold traffic for user confirmation
aka conn disable analytics               # refuse every agent's calls
```

Use `aka serve --no-listen` for Unix-socket-only operation. Override
`--listen` and `--public-url` when a proxy, tunnel, or remote deployment needs
different addresses.

The desktop app never attaches to a headless broker directly: "Local
Multitool" in the app runs its own broker on `~/.aka`, while `aka serve` uses
`~/.akaserver`. To point the app at a headless broker, connect it as a hosted
instance — `aka setup desktop` prints the URL and management token to paste
into the app's connect form.

Pass `--json` to bounded reads and mutations for machine-readable output.
Successful mutations return an `ok`, `action`, and `result` envelope; streaming
and format-specific commands such as `serve`, `mcp`, and `completions` do not
offer JSON mode.

### Joining a shared broker

A teammate joins a broker someone else runs with a one-use invite. The
operator mints it on the broker host; `/v1/pair` is never served over TCP,
so an invite is the only way the shared agent key crosses a network:

```sh
aka admin invite --label rae                          # on the broker host
aka login https://broker.example.dev/join#akajoin_…   # on their machine
```

The code rides in the URL fragment, which is never sent to a server, so
joining is one pasted command. An invite expires in 15 minutes and is
spent by the first redemption; what it hands back is the same shared agent
key every agent on that broker holds, so it grants no identity of its own.
`aka login` stores that key and defines a context. Management commands
need their own credential (`aka admin login --broker <url>`); the two
planes stay separate, and `aka logout` forgets only the agent key.

### Broker contexts

Commands point at a broker through one resolution chain, so `--root` and
`--broker` are needed only to override it:

```
--root/--broker  →  AKA_BROKER  →  a repo .aka pin  →  aka use default  →  local
```

```sh
aka use                       # list contexts and show what resolves now
aka use corp --broker https://broker.example.dev
aka use corp --pin            # write ./.aka so this repo's agents inherit it
```

`local` (the desktop app's `~/.aka`) and `server` (the `aka serve` root)
are built in. Usage commands (`run`, `env`, `mcp`) open sessions on this
machine's broker, so a context pointing at a remote broker is refused with
what each kind would need instead.

### Compatibility with pre-rename installs

The `aka-agent` package installs only the `aka` executable. Existing
`AGENTMFA_*` environment variables, `X-AgentMFA-Client` headers,
`agentmfa_*` MCP calls, `agentmfa://` resource URIs, and the former SSH-agent
extension are still accepted as protocol fallbacks. New output and setup
instructions use `aka`.

The application keeps its existing `com.aka.desktop` identity, `~/.aka` data
directory, and Keychain services so upgrading does not create an empty vault
or require users to move local state.

### Direct connection setup

Agents that run shell commands don't need MCP at all: each connection
is automatically exposed as a local endpoint, that automatically
injects the credential on the upstream.

`aka run <connection> -- <command>` covers every kind; the connection's
kind decides what the child process gets.

- **Postgres** — a short-lived `PG*` environment with the ticket in
  `PGPASSWORD`, keeping it out of process-visible argv:

  ```sh
  aka run analytics -- psql
  ```

  The broker-facing Postgres leg does not support TLS and therefore sets
  `PGSSLMODE=disable`; use it only over the trusted path to the broker.
  Upstream TLS from the broker to the database is configured separately on
  the connection. `aka env analytics` prints shell-safe exports instead;
  its `--format uri` embeds the ticket in argv.

- **SSH** — stock `ssh`, `git`, `scp`, `sftp`, or `rsync` with a scoped
  signing agent and the mandatory broker-safe SSH options; the private key
  never leaves the broker:

  ```sh
  aka run production -- ssh production uptime
  aka run production -- git push production main
  aka run production -- scp app.tar.gz production:/srv/app/
  aka run production -- rsync -av build/ production:/srv/app/
  ```

- **Cloud** — temporary AWS/Azure/GCP credentials in the child's
  environment; the vaulted long-lived identity never prints:

  ```sh
  aka run staging-aws -- aws s3 ls
  ```

  For tooling that fetches credentials itself, `aka cloud creds` and
  `aka cloud install` emit `credential_process` forms.

- **HTTP / API** — each API connection gets a loopback endpoint, which
  you can use to directly reach the upstream with `curl` and SDKs. Issue
  the endpoint (`aka endpoint github --issue`, or in the app), then send
  its endpoint secret in place of the real credential; the broker swaps it
  for the real one upstream. `aka run` and `aka env` hand that endpoint to
  a command as `AKA_URL` and `AKA_TOKEN`:

  ```sh
  eval "$(aka env github)"
  curl -H "Authorization: Bearer $AKA_TOKEN" "$AKA_URL/user/repos"
  ```

### Multitool MCP setup

Every connection is also exposed as an MCP tool. API connections are
exposed as `multitool_<name>_request`, and databases/servers as
`multitool_<name>_open`, which returns a ready-to-use local endpoint.

Upstream MCP servers are proxied through the same broker, so their
credentials stay in the vault too. HTTP/Postgres/SSH connections are
registered as one native Multitool tool each. Streamable-HTTP MCP upstreams
contribute their own bounded tool names and may be limited to a curated
subset in the app; upstream stdio servers are not supported. Native
connection changes and upstream provisioning are announced to active sessions;
the agent refreshes its catalog without reconnecting to Multitool.
Use `multitool_status` first when a tool is missing or an upstream failed.

Generate a paste-ready configuration for your client. This is a setup command;
the generated configuration launches the separate `aka mcp` runtime bridge:

```sh
aka setup codex
aka setup claude-code
aka setup claude-desktop
```

**Claude Code** (`aka setup claude-code`):

```sh
claude mcp add multitool -- aka mcp --client claude-code
```

**Claude Desktop** (`aka setup claude-desktop`) in
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "multitool": {
      "command": "aka",
      "args": ["mcp", "--client", "claude-desktop"]
    }
  }
}
```

**Codex** (`aka setup codex`) in `~/.codex/config.toml`:

```toml
[mcp_servers.multitool]
command = "aka"
args = ["mcp", "--client", "codex"]
```

`aka mcp` is the stdio server command launched by the configured client. It
discovers the broker and its key automatically; users normally run
`aka setup <client>` instead of invoking the runtime bridge themselves.

## Contributing

To build the desktop app, run the test suites, or iterate on the UI
against a mock broker, see [DEVELOPING.md](DEVELOPING.md).

## License

Multitool is available under the [MIT License](LICENSE).
