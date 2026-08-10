use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::{json, Value};

#[derive(Clone)]
struct Reply {
    method: &'static str,
    path: &'static str,
    body: Value,
}

fn read_request(mut stream: &TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "client closed before sending a complete request");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "client closed before sending its request body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    String::from_utf8(bytes).unwrap()
}

fn stub(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let handle = thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&stream);
            let first = request.lines().next().unwrap_or_default();
            assert_eq!(first, format!("{} {} HTTP/1.1", reply.method, reply.path));
            captured.lock().unwrap().push(request);
            let body = serde_json::to_string(&reply.body).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    (url, requests, handle)
}

fn whoami() -> Reply {
    Reply {
        method: "GET",
        path: "/v1/manage/whoami",
        body: json!({
            "version": env!("CARGO_PKG_VERSION"),
            "approval_surface_attached": false
        }),
    }
}

fn run(args: &[&str], root: &std::path::Path, broker: Option<&str>, stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aka"));
    command.args(args).env("AKA_MANAGE_TOKEN", "akamgr_test");
    if let Some(broker) = broker {
        command.args(["--broker", broker]);
    }
    command.args(["--root", root.to_str().unwrap()]);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(stdin) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn connection() -> Value {
    json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "github",
        "updated_at": "version-1",
        "type": "api",
        "target": "https://api.github.com",
        "secret_names": ["GITHUB_TOKEN"],
        "oauth": false,
        "agent_access": {
            "enabled": true,
            "confirm": true,
            "allowed_tools": ["search"],
            "endpoint": null
        },
        "host": "api.github.com",
        "scheme": "https",
        "port": null,
        "template": "Authorization: Bearer {{GITHUB_TOKEN}}",
        "last_status": "ok",
        "last_detail": "Signed in",
        "last_checked_at": "2026-07-29T12:00:00Z"
    })
}

#[test]
fn bare_cli_is_contextual_and_help_commands_keep_the_command_reference() {
    let bare = Command::new(env!("CARGO_BIN_EXE_aka")).output().unwrap();
    assert_success(&bare);
    assert!(bare.stderr.is_empty());
    let bare_home = String::from_utf8(bare.stdout).unwrap();
    assert!(bare_home.starts_with(&format!("aka {}\n", env!("CARGO_PKG_VERSION"))));
    assert!(
        bare_home
            .lines()
            .nth(2)
            .is_some_and(|line| line.contains(" - ")),
        "{bare_home}"
    );
    assert!(!bare_home.contains("CONTEXT"), "{bare_home}");
    assert!(!bare_home.contains("STATUS"), "{bare_home}");
    assert!(bare_home.contains("NEXT"), "{bare_home}");
    assert!(bare_home.contains("MORE"), "{bare_home}");
    assert!(
        bare_home.contains("aka -h for common commands\naka --help for full reference"),
        "{bare_home}"
    );
    assert!(!bare_home.contains("https://example.com"), "{bare_home}");
    assert!(!bare_home.contains("USAGE"), "{bare_home}");
    assert!(!bare_home.contains("USE A CONNECTION"), "{bare_home}");
    assert!(!bare_home.contains("RUNTIME"), "{bare_home}");
    assert!(!bare_home.contains("Brokered credentials for AI agents"));

    let short = Command::new(env!("CARGO_BIN_EXE_aka"))
        .arg("-h")
        .output()
        .unwrap();
    assert_success(&short);
    let short_help = String::from_utf8(short.stdout).unwrap();
    assert!(short_help.contains("USE A CONNECTION"));
    assert!(short_help.contains("GET STARTED"));
    assert!(short_help.contains(&format!("aka {}\nUSAGE", env!("CARGO_PKG_VERSION"))));
    assert!(!short_help.contains("Agent access for APIs, MCPs, databases, and servers"));
    assert!(
        short_help.find("USE A CONNECTION") < short_help.find("GET STARTED"),
        "connection commands should come first: {short_help}"
    );
    assert!(short_help.contains("run <conn> -- <cmd>"));
    assert!(short_help.contains("env <conn>"));
    assert!(short_help.contains("Run with brokered credentials"));
    assert!(!short_help.contains("Run a command with brokered credentials"));
    assert!(short_help.contains("aka run <conn> -- psql"));
    assert!(short_help.contains("Run commands after `--` with short-lived credentials:"));
    assert!(!short_help.contains("  skill"), "{short_help}");
    assert!(!short_help.contains("    api <name>"), "{short_help}");
    assert!(!short_help.contains("      aws <name>"), "{short_help}");
    assert!(
        short_help.lines().any(|line| line.starts_with(" logout")),
        "{short_help}"
    );
    assert!(
        !short_help.lines().any(|line| line.starts_with(" skill ")),
        "{short_help}"
    );
    assert!(short_help.contains("setup skill"), "{short_help}");
    assert!(short_help.contains("setup instructions"), "{short_help}");
    assert!(short_help.contains("setup desktop"), "{short_help}");
    assert!(
        short_help.contains("Show desktop connection details"),
        "{short_help}"
    );
    assert!(short_help.contains("conn [add | …]"), "{short_help}");
    assert!(short_help.contains("secret [add | …]"), "{short_help}");
    assert!(!short_help.contains("commands:"), "{short_help}");
    assert!(short_help.contains("cloud creds <conn>"), "{short_help}");
    assert!(short_help.contains("cloud config <conn>"), "{short_help}");
    assert!(!short_help.contains("cloud install <conn>"), "{short_help}");
    assert!(!short_help.contains("settings: get | set"), "{short_help}");
    assert!(short_help.contains("OPERATOR"));
    assert!(short_help.contains("RUNTIME"));
    assert!(!short_help.contains("ADVANCED"));
    assert!(short_help.contains("completions <shell>"));
    assert!(short_help.contains("FULL REFERENCE"));
    assert!(short_help.contains("aka --help"));
    assert!(!short_help.contains("aka --help --help"));
    assert!(!short_help.contains("Run `aka <command> --help`"));
    let description_columns = [
        "Run with brokered credentials",
        "Show broker status",
        "Add and manage connections",
        "Show pending and recent approval requests and questions",
        "Run a headless broker",
        "Run the MCP stdio bridge",
    ]
    .map(|description| {
        short_help
            .lines()
            .find(|line| line.contains(description))
            .and_then(|line| {
                line.find(description)
                    .map(|byte| line[..byte].chars().count())
            })
            .unwrap()
    });
    assert!(
        description_columns
            .windows(2)
            .all(|pair| pair[0] == pair[1]),
        "root command descriptions should share one column: {short_help}"
    );
    assert!(!short_help.contains("NEXT"), "-h stays a pure help page");

    let regular = Command::new(env!("CARGO_BIN_EXE_aka"))
        .arg("--help")
        .output()
        .unwrap();
    assert_success(&regular);
    let regular_help = String::from_utf8(regular.stdout).unwrap();
    assert_ne!(regular_help, short_help);
    assert!(regular_help.contains("    api <name>"), "{regular_help}");
    assert!(regular_help.contains("      aws <name>"), "{regular_help}");

    let full = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--help", "--help"])
        .output()
        .unwrap();
    assert_success(&full);
    let long_help = String::from_utf8(full.stdout).unwrap();
    assert_eq!(long_help, regular_help);
    assert!(long_help.contains("OPERATOR"));
    assert!(long_help.contains("RUNTIME"));
    assert!(!long_help.contains("ADVANCED"));
    assert!(long_help.contains("EXAMPLES"));
    assert!(long_help.contains("aka setup codex --write"));
    assert!(!long_help.contains("Run a headless broker    aka serve"));
    assert!(!long_help.contains("Add a connection         aka conn add pg --help"));
    assert!(long_help.contains("  skill"), "{long_help}");
    assert!(
        !long_help.lines().any(|line| line.starts_with(" skill ")),
        "{long_help}"
    );
    assert!(long_help.contains("    api <name>"), "{long_help}");
    assert!(long_help.contains("      aws <name>"), "{long_help}");
    assert!(
        long_help.contains("List connections available to this agent"),
        "{long_help}"
    );
    assert!(
        long_help.contains("List all configured connections, including disabled connections"),
        "{long_help}"
    );

    for (command, description) in [
        ("status", "Check the broker at this URL"),
        ("activity", "Read activity from this broker URL"),
        ("sessions", "List or close sessions on this broker URL"),
        ("approvals", "Read approval requests from this broker URL"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_aka"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert_success(&output);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains(description), "{command} help:\n{help}");
    }
    for (args, description) in [
        (
            &["use", "--help"][..],
            "Clear the saved default context. Environment and repository",
        ),
        (
            &["admin", "token", "--help"][..],
            "Disable token-based management access. Passkey, device, and",
        ),
        (
            &["approve", "--help"][..],
            "Approve a pending request for the displayed time window",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_aka"))
            .args(args)
            .output()
            .unwrap();
        assert_success(&output);
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(
            help.contains(description),
            "{} help:\n{help}",
            args.join(" ")
        );
    }
    let onboarding_rows =
        [" setup ", " login <url>", " use ", " status ", " logout "].map(|prefix| {
            long_help
                .lines()
                .position(|line| line.starts_with(prefix))
                .unwrap()
        });
    assert!(
        onboarding_rows.windows(2).all(|rows| rows[0] < rows[1]),
        "onboarding commands should follow their lifecycle: {long_help}"
    );
    assert!(
        long_help.lines().any(|line| line.starts_with(" logout")),
        "{long_help}"
    );
    assert!(!long_help.contains("conn [add | …]"), "{long_help}");
    assert!(!long_help.contains("Run `aka <command> --help`"));
    assert!(!long_help.contains("\nOTHER\n"));

    let nested = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["serve", "--help"])
        .output()
        .unwrap();
    assert_success(&nested);
    assert!(
        String::from_utf8(nested.stdout)
            .unwrap()
            .contains("instead of the bundled one"),
        "nested --help should retain its detailed reference"
    );
}

#[test]
fn status_is_machine_readable_and_classifies_a_missing_broker() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("data")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--json", "status", "--root", root.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["running"], false);
    assert!(output.stderr.is_empty());
}

#[test]
fn remote_status_surfaces_structured_recent_ssh_refusals() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/identity",
            body: json!({
                "client_id": "00000000-0000-0000-0000-000000000001",
                "token_path": "/srv/aka/token",
                "socket_path": "/srv/aka/broker.sock",
                "minted_at": "2026-07-30T12:00:00Z",
                "last_used": "2026-07-30T12:00:00Z",
                "legacy_aliases": 0
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([]),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/activity?limit=100",
            body: json!([{
                "icon": "lock",
                "tone": "warning",
                "kind": "denied",
                "text": "SSH agent connection refused: deploy",
                "detail": "agent access is disabled",
                "agent": "endpoint",
                "connection": "deploy",
                "outcome": "denied_by_policy",
                "protocol": "ssh",
                "duration_ms": null,
                "at": "2026-07-30T12:00:00Z"
            }]),
        },
    ]);
    let output = run(&["--json", "status"], root.path(), Some(&url), None);
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["recent_ssh_refusals"][0]["reason"],
        "denied_by_policy"
    );
    assert_eq!(report["recent_ssh_refusals"][0]["connection"], "deploy");
    handle.join().unwrap();
}

#[test]
fn json_mutations_return_a_structured_success_envelope() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "POST",
            path: "/v1/manage/secrets",
            body: Value::Null,
        },
    ]);
    let output = run(
        &["--json", "secret", "add", "TOKEN"],
        root.path(),
        Some(&url),
        Some("value\n"),
    );
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "ok": true,
            "action": "secret.add",
            "result": { "name": "TOKEN" }
        })
    );
    handle.join().unwrap();
}

#[test]
fn json_wraps_bounded_documents_and_is_rejected_for_streaming_commands() {
    let instructions = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--json", "setup", "instructions"])
        .output()
        .unwrap();
    assert_success(&instructions);
    let body: Value = serde_json::from_slice(&instructions.stdout).unwrap();
    assert!(body["content"]
        .as_str()
        .is_some_and(|content| content.contains("Multitool: broker instructions")));

    let mcp = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--json", "mcp"])
        .output()
        .unwrap();
    assert_eq!(mcp.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&mcp.stderr).contains("--json is not supported"));

    let help = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["mcp", "--help"])
        .output()
        .unwrap();
    assert_success(&help);
    assert!(!String::from_utf8_lossy(&help.stdout).contains("--json"));
}

#[test]
fn setup_generates_paste_ready_mcp_client_configuration() {
    let codex = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "codex"])
        .output()
        .unwrap();
    assert_success(&codex);
    assert_eq!(
        String::from_utf8(codex.stdout).unwrap(),
        "codex mcp add multitool -- aka mcp --client codex\n"
    );
    let stderr = String::from_utf8_lossy(&codex.stderr);
    assert!(stderr.contains("Codex setup command"), "{stderr}");
    assert!(stderr.contains("no changes made"), "{stderr}");
    assert!(stderr.contains("aka setup codex --write"), "{stderr}");

    let codex_json = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--json", "setup", "codex"])
        .output()
        .unwrap();
    assert_success(&codex_json);
    let body: Value = serde_json::from_slice(&codex_json.stdout).unwrap();
    assert_eq!(body["target"], "Codex CLI");
    assert_eq!(body["format"], "shell");
    assert_eq!(
        body["content"],
        "codex mcp add multitool -- aka mcp --client codex\n"
    );

    let claude = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "claude-code"])
        .output()
        .unwrap();
    assert_success(&claude);
    assert_eq!(
        String::from_utf8_lossy(&claude.stdout),
        "claude mcp add multitool -- aka mcp --client claude-code\n"
    );
    let stderr = String::from_utf8_lossy(&claude.stderr);
    assert!(stderr.contains("Claude Code setup command"), "{stderr}");
    assert!(stderr.contains("no changes made"), "{stderr}");
    assert!(stderr.contains("aka setup claude-code --write"), "{stderr}");

    let claude_json = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["--json", "setup", "claude-code"])
        .output()
        .unwrap();
    assert_success(&claude_json);
    let body: Value = serde_json::from_slice(&claude_json.stdout).unwrap();
    assert_eq!(body["client"], "claude-code");
    assert_eq!(body["target"], "Claude Code CLI");
    assert_eq!(body["command"], "aka");
    assert_eq!(body["args"], json!(["mcp", "--client", "claude-code"]));
    assert_eq!(
        body["content"],
        "claude mcp add multitool -- aka mcp --client claude-code\n"
    );

    let desktop = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "claude-desktop"])
        .output()
        .unwrap();
    assert_success(&desktop);
    let stdout = String::from_utf8_lossy(&desktop.stdout);
    assert!(stdout.contains("\"mcpServers\""), "{stdout}");
    assert!(stdout.contains("\"claude-desktop\""), "{stdout}");
    let stderr = String::from_utf8_lossy(&desktop.stderr);
    assert!(stderr.contains("requires a manual config edit"), "{stderr}");
    assert!(stderr.contains("--write` only prepares"), "{stderr}");
    assert!(stderr.contains("no changes made"), "{stderr}");

    let help = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "--help"])
        .output()
        .unwrap();
    assert_success(&help);
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("skill"));
    assert!(help.contains("instructions"));
    assert!(help.contains("claude-code"));

    let bare_setup = Command::new(env!("CARGO_BIN_EXE_aka"))
        .arg("setup")
        .output()
        .unwrap();
    assert_eq!(bare_setup.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bare_setup.stderr).contains("claude-code"));
}

#[test]
fn setup_skill_labels_preview_without_polluting_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "skill"])
        .output()
        .unwrap();

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("---\n"), "{stdout}");
    assert!(stdout.contains("name: multitool"), "{stdout}");
    assert!(!stdout.contains("no changes made"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Agent skill preview"), "{stderr}");
    assert!(stderr.contains("no changes made"), "{stderr}");
    assert!(stderr.contains("aka setup skill --write"), "{stderr}");
}

#[test]
fn explicit_missing_roots_are_not_created_by_mutations() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("typo");
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["conn", "rm", "unused", "--root", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is not a broker root"));
    assert!(!stderr.contains("Using broker root"), "{stderr}");
    assert!(!missing.exists(), "a typo must not create broker state");
}

#[test]
fn broker_url_environment_variable_matches_the_broker_flag() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([]),
        },
    ]);
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args([
            "--json",
            "conn",
            "list",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .env("AKA_MANAGE_TOKEN", "akamgr_test")
        .env("AKA_BROKER_URL", &url)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
    handle.join().unwrap();
}

#[test]
fn hosted_instructions_and_skills_fetch_authoritative_agent_setup() {
    let root = tempfile::tempdir().unwrap();
    let setup = "Connect to the selected broker.\n\ncurl https://broker.example.test/instructions";
    let replies = || {
        vec![
            whoami(),
            Reply {
                method: "GET",
                path: "/v1/manage/agent-setup",
                body: json!({ "instructions": setup }),
            },
        ]
    };

    let (url, instruction_requests, instruction_handle) = stub(replies());
    let output = run(&["setup", "instructions"], root.path(), Some(&url), None);
    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), setup);
    instruction_handle.join().unwrap();
    assert_eq!(instruction_requests.lock().unwrap().len(), 2);

    let (url, skill_requests, skill_handle) = stub(replies());
    let output = run(&["setup", "skill"], root.path(), Some(&url), None);
    assert_success(&output);
    let skill = String::from_utf8_lossy(&output.stdout);
    assert!(skill.starts_with("---\nname: multitool"), "{skill}");
    assert!(skill.contains(setup), "{skill}");
    assert!(skill.contains("selected Multitool broker"), "{skill}");
    assert!(!skill.contains("--unix-socket"), "{skill}");
    skill_handle.join().unwrap();
    assert_eq!(skill_requests.lock().unwrap().len(), 2);
}

#[test]
fn broker_url_environment_rotates_the_current_management_token_online() {
    let root = tempfile::tempdir().unwrap();
    let (url, requests, handle) = stub(vec![Reply {
        method: "POST",
        path: "/v1/manage/management-token",
        body: json!({
            "token": "akamgr_rotated",
            "expires_at": "2026-08-29T12:00:00Z"
        }),
    }]);
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args([
            "admin",
            "token",
            "--ttl-days",
            "30",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .env("AKA_MANAGE_TOKEN", "akamgr_test")
        .env("AKA_BROKER_URL", &url)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "akamgr_rotated"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AKA_MANAGE_TOKEN") && stderr.contains("previous token"),
        "{stderr}"
    );
    handle.join().unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "rotation must not make a stale whoami call"
    );
    assert!(requests[0].contains("authorization: Bearer akamgr_test"));
    assert!(requests[0].ends_with(r#"{"ttl_days":30}"#));
}

#[test]
fn broker_url_environment_applies_to_agent_key_reads() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/identity/agent-key",
            body: json!({ "token": "aka_remote_key" }),
        },
    ]);
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args([
            "--json",
            "admin",
            "agent-key",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .env("AKA_MANAGE_TOKEN", "akamgr_test")
        .env("AKA_BROKER_URL", &url)
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["key"],
        "aka_remote_key"
    );
    handle.join().unwrap();
}

#[test]
fn visibility_commands_project_sessions_requests_settings_and_connection_detail() {
    let root = tempfile::tempdir().unwrap();
    let cases = [
        (
            vec!["--json", "sessions"],
            Reply {
                method: "GET",
                path: "/v1/manage/sessions",
                body: json!([{
                    "id": 7, "type": "pg", "agent": "codex", "connection": "db",
                    "detail": "app@db.example/app", "opened_at": "2026-07-29T12:00:00Z"
                }]),
            },
            "7",
        ),
        (
            vec!["--json", "approvals"],
            Reply {
                method: "GET",
                path: "/v1/manage/requests",
                body: json!([{
                    "id": "00000000-0000-0000-0000-000000000002",
                    "kind": "approval", "status": "pending", "connection": "github",
                    "agent": "codex", "summary": "GET /user", "waiting": 1,
                    "requested_at": "2026-07-29T12:00:00Z"
                }]),
            },
            "pending",
        ),
        (
            vec!["--json", "admin", "settings", "get"],
            Reply {
                method: "GET",
                path: "/v1/manage/settings",
                body: json!({
                    "menu_bar_hides_dock": false,
                    "confirm_ssh_host_keys": false
                }),
            },
            "confirm_ssh_host_keys",
        ),
        (
            vec!["--json", "conn", "show", "github"],
            Reply {
                method: "GET",
                path: "/v1/manage/connections",
                body: json!([connection()]),
            },
            "last_status",
        ),
    ];
    for (args, reply, needle) in cases {
        let (url, _, handle) = stub(vec![whoami(), reply]);
        let output = run(&args, root.path(), Some(&url), None);
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains(needle));
        handle.join().unwrap();
    }
}

#[test]
fn requests_can_approve_a_pending_confirmation_with_a_surface_lease() {
    let root = tempfile::tempdir().unwrap();
    let request_id = "00000000-0000-0000-0000-000000000002";
    let surface_id = "00000000-0000-0000-0000-000000000099";
    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "POST",
            path: "/v1/manage/approval-surfaces",
            body: json!({
                "id": surface_id,
                "expires_in_ms": 15000,
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/approvals",
            body: json!([{
                "id": request_id,
                "connection_id": "00000000-0000-0000-0000-000000000003",
                "connection": "github",
                "type": "api",
                "target": "api.github.com",
                "agent": "codex",
                "summary": "GET /user",
                "waiting": 1,
                "requested_at": "2026-07-29T12:00:00Z",
                "expires_at": "2026-07-29T12:01:00Z",
                "window_secs": 300
            }]),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/elicitations",
            body: json!([]),
        },
        Reply {
            method: "POST",
            path: "/v1/manage/approvals/00000000-0000-0000-0000-000000000002",
            body: json!({"answered": true}),
        },
        Reply {
            method: "DELETE",
            path: "/v1/manage/approval-surfaces/00000000-0000-0000-0000-000000000099",
            body: json!({"released": true}),
        },
    ]);
    let output = run(
        &["--json", "approve", request_id],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["decision"], "approved");
    assert_eq!(body["id"], request_id);
    handle.join().unwrap();
    let requests = requests.lock().unwrap();
    assert!(requests[4].contains(r#""decision":"approve_window""#));
}

#[test]
fn session_close_and_setting_updates_use_the_existing_management_contracts() {
    let root = tempfile::tempdir().unwrap();
    let (url, _, handle) = stub(vec![
        whoami(),
        Reply {
            method: "DELETE",
            path: "/v1/manage/sessions/7",
            body: json!({ "closed": true }),
        },
    ]);
    let output = run(
        &["--json", "sessions", "--close", "7"],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["closed"],
        true
    );
    handle.join().unwrap();

    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "PATCH",
            path: "/v1/manage/settings",
            body: json!({
                "menu_bar_hides_dock": false,
                "confirm_ssh_host_keys": false
            }),
        },
        Reply {
            method: "GET",
            path: "/v1/manage/settings",
            body: json!({
                "menu_bar_hides_dock": false,
                "confirm_ssh_host_keys": false
            }),
        },
    ]);
    let output = run(
        &[
            "--json",
            "admin",
            "settings",
            "set",
            "--menu-bar-hides-dock",
            "false",
        ],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    handle.join().unwrap();
    assert!(requests.lock().unwrap()[1].contains(r#""menu_bar_hides_dock":false"#));
}

#[test]
fn conn_update_sends_a_sparse_patch_instead_of_reconstructing_configuration() {
    let root = tempfile::tempdir().unwrap();
    let mut updated = connection();
    updated["host"] = json!("api2.github.com");
    updated["target"] = json!("https://api2.github.com");
    updated["updated_at"] = json!("version-2");
    let (url, requests, handle) = stub(vec![
        whoami(),
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([connection()]),
        },
        Reply {
            method: "PATCH",
            path: "/v1/manage/connections/00000000-0000-0000-0000-000000000001/config",
            body: Value::Null,
        },
        Reply {
            method: "GET",
            path: "/v1/manage/connections",
            body: json!([updated]),
        },
    ]);
    let output = run(
        &[
            "conn",
            "update",
            "api",
            "github",
            "--host",
            "api2.github.com",
        ],
        root.path(),
        Some(&url),
        None,
    );
    assert_success(&output);
    handle.join().unwrap();
    let request = &requests.lock().unwrap()[2];
    let body = request.split_once("\r\n\r\n").unwrap().1;
    let payload: Value = serde_json::from_str(body).unwrap();
    assert_eq!(payload["expected_updated_at"], "version-1");
    assert_eq!(payload["patch"]["host"], "api2.github.com");
    assert!(payload["patch"].get("mcp_path").is_none());
    assert!(payload["patch"].get("oauth").is_none());
    assert!(!body.contains("Authorization: Bearer"));
}

#[test]
fn secret_input_is_normalized_identically_from_stdin_and_environment() {
    let root = tempfile::tempdir().unwrap();
    for (from_env, value) in [(false, "line\n"), (true, "line\n")] {
        let (url, requests, handle) = stub(vec![
            whoami(),
            Reply {
                method: "POST",
                path: "/v1/manage/secrets",
                body: Value::Null,
            },
        ]);
        let mut command = Command::new(env!("CARGO_BIN_EXE_aka"));
        command
            .env("AKA_MANAGE_TOKEN", "akamgr_test")
            .args(["secret", "add", "TOKEN", "--broker", &url, "--root"])
            .arg(root.path());
        if from_env {
            command
                .env("CLI_TEST_SECRET", value)
                .args(["--value-env", "CLI_TEST_SECRET"]);
        } else {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        if !from_env {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(value.as_bytes())
                .unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert_success(&output);
        handle.join().unwrap();
        let body = requests.lock().unwrap()[1]
            .split_once("\r\n\r\n")
            .unwrap()
            .1
            .to_string();
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["value"],
            "line"
        );
    }
}

#[test]
fn remote_commands_fail_with_auth_exit_code_before_network_without_a_token() {
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .env_remove("AKA_MANAGE_TOKEN")
        .args([
            "admin",
            "settings",
            "get",
            "--broker",
            "http://127.0.0.1:9",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Live management requires a token"));
}

/// `aka login` speaks the join protocol: the invite rides in the URL
/// fragment, the client label becomes the agent name, and a refusal is an
/// authentication failure that stores nothing.
#[test]
fn login_redeems_an_invite_over_the_join_endpoint() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&stream);
        captured.lock().unwrap().push(request);
        let body = json!({
            "reason": "pairing_failed",
            "detail": "that invite is unknown, has expired, or has already been redeemed",
        })
        .to_string();
        write!(
            stream,
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });

    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["login", &format!("{url}/join#akajoin_abc123")])
        .args(["--client", "ci-runner"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env_remove("AKA_BROKER")
        .output()
        .unwrap();
    handle.join().unwrap();

    // A refused invite is an authentication failure, not a generic error.
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already been redeemed"), "{stderr}");

    let request = requests.lock().unwrap()[0].clone();
    assert!(
        request.starts_with("POST /v1/join HTTP/1.1"),
        "the fragment must not reach the server as a path: {request}"
    );
    let body: Value = serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["invite"], "akajoin_abc123", "the fragment carries it");
    assert_eq!(body["agent_name"], "ci-runner");

    // Nothing is recorded until a join succeeds.
    assert!(!home.path().join(".config/aka/contexts.json").exists());
}

/// The hot path works against a remote broker: the context supplies the
/// address, the stored agent key authenticates, and `env` renders the same
/// PG* exports it renders locally.
#[test]
fn run_and_env_reach_a_remote_broker_with_the_agent_key() {
    let home = tempfile::tempdir().unwrap();
    let (url, requests, handle) = stub(vec![
        Reply {
            method: "GET",
            path: "/v1/connections",
            body: json!([{
                "name": "analytics", "type": "pg", "target": "db.internal:5432/app",
                "endpoint": "/v1/pg/open", "wired": true, "confirm": false
            }]),
        },
        Reply {
            method: "POST",
            path: "/v1/pg/open",
            body: json!({
                "dsn": "postgres://ticket@127.0.0.1:5599/app?sslmode=disable",
                "ticket": "tkt_remote",
                "expires_in_seconds": 60
            }),
        },
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["env", "analytics", "--client", "ci-runner"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("AKA_BROKER", &url)
        .env("AKA_AGENT_KEY", "aka_remote_key")
        .env_remove("AKA_BROKER_URL")
        .env_remove("AKA_MANAGE_TOKEN")
        .output()
        .unwrap();
    handle.join().unwrap();
    assert_success(&output);

    let exports = String::from_utf8(output.stdout).unwrap();
    assert!(exports.contains("export PGHOST='127.0.0.1'"), "{exports}");
    assert!(exports.contains("export PGDATABASE='app'"), "{exports}");
    assert!(
        exports.contains("export PGPASSWORD='tkt_remote'"),
        "the ticket rides in PGPASSWORD, not argv: {exports}"
    );

    // Both legs carried the stored agent key and the client label.
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert!(
            request.contains("authorization: Bearer aka_remote_key")
                || request.contains("Authorization: Bearer aka_remote_key"),
            "{request}"
        );
        assert!(
            request
                .to_lowercase()
                .contains("x-multitool-client: ci-runner"),
            "{request}"
        );
    }
    assert!(requests[1].contains(r#""connection":"analytics""#));
}

/// A remote broker refuses same-machine capabilities with
/// `not_served_remotely`; the CLI turns that into the kind's actual remote
/// story rather than passing the raw reason through.
#[test]
fn a_remote_broker_explains_which_capabilities_are_same_machine() {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        // The catalog, then the refusal the broker gives for an SSH open.
        for (code, body) in [
            (
                200,
                json!([{ "name": "prod", "type": "ssh", "target": "prod.internal",
                         "endpoint": "/v1/ssh/open", "wired": true, "confirm": false }]),
            ),
            (
                404,
                json!({ "reason": "not_served_remotely",
                        "detail": "ssh opens are not served remotely" }),
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&stream);
            let body = body.to_string();
            let phrase = if code == 200 { "OK" } else { "Not Found" };
            write!(
                stream,
                "HTTP/1.1 {code} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["run", "prod", "--", "ssh", "prod"])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("AKA_BROKER", &url)
        .env("AKA_AGENT_KEY", "aka_remote_key")
        .env_remove("AKA_BROKER_URL")
        .output()
        .unwrap();
    handle.join().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not serve this capability over the network"),
        "{stderr}"
    );
    assert!(
        stderr.contains("SSH sessions are never served over the network"),
        "the refusal must name this kind's remote story: {stderr}"
    );
}

/// The first thing a teammate does after `aka login` is look at the
/// catalog, and at that point they hold only the agent key. `ls` must not
/// demand a management token for that.
#[test]
fn ls_falls_back_to_the_agent_catalog_without_a_management_token() {
    let home = tempfile::tempdir().unwrap();
    let (url, requests, handle) = stub(vec![Reply {
        method: "GET",
        path: "/v1/connections",
        body: json!([
            { "name": "analytics", "type": "pg", "target": "db.internal:5432/app",
              "endpoint": "/v1/pg/open", "wired": true, "confirm": false },
            { "name": "billing", "type": "pg", "target": "db.internal:5432/bill",
              "endpoint": "/v1/pg/open", "wired": false, "confirm": true },
        ]),
    }]);

    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .arg("ls")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("AKA_BROKER", &url)
        .env("AKA_AGENT_KEY", "aka_remote_key")
        .env_remove("AKA_BROKER_URL")
        .env_remove("AKA_MANAGE_TOKEN")
        .output()
        .unwrap();
    handle.join().unwrap();
    assert_success(&output);

    let table = String::from_utf8(output.stdout).unwrap();
    assert!(table.contains("analytics"), "{table}");
    assert!(table.contains("enabled"), "{table}");
    assert!(table.contains("disabled"), "billing is off: {table}");
    assert!(table.contains("confirm: on"), "{table}");
    // The narrower view says so rather than pretending to be the full one.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("agent view"), "{stderr}");

    assert!(requests.lock().unwrap()[0].contains("Bearer aka_remote_key"));
}

/// `setup <client> --write` applies what the printed form describes, reports
/// each step separately, and stays one JSON envelope.
#[test]
fn setup_write_applies_the_skill_and_pin_and_emits_one_envelope() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let codex = bin.join("codex");
    std::fs::write(
        &codex,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CODEX_CALLS\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).unwrap();
    let codex_calls = home.path().join("codex-calls");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let aka = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_aka"))
            .args(args)
            .current_dir(repo.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env("CODEX_CALLS", &codex_calls)
            .env("PATH", &path)
            .env_remove("AKA_BROKER")
            .env_remove("AKA_BROKER_URL")
            .output()
            .unwrap()
    };

    // With no context, the pin step is skipped and says so rather than
    // claiming agents are pointed anywhere.
    let output = aka(&["setup", "codex", "--write"]);
    assert_success(&output);
    assert!(repo
        .path()
        .join(".claude/skills/multitool/SKILL.md")
        .exists());
    assert!(!repo.path().join(".aka").exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("registered MCP server multitool with Codex"),
        "{stderr}"
    );
    assert!(stderr.contains("no broker context pinned"), "{stderr}");

    // With one, the repo is pinned to it.
    assert_success(&aka(&[
        "use",
        "corp",
        "--broker",
        "https://broker.example.dev",
    ]));
    let output = aka(&["setup", "codex", "--write"]);
    assert_success(&output);
    assert_eq!(
        std::fs::read_to_string(repo.path().join(".aka"))
            .unwrap()
            .trim(),
        "corp"
    );

    // One mutation, one envelope — a nested skill write must not emit its own.
    let output = aka(&["--json", "setup", "codex", "--write"]);
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let objects: Vec<Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(objects.len(), 1, "{stdout}");
    assert_eq!(objects[0]["action"], "setup.write");
    let steps = objects[0]["result"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert!(steps
        .iter()
        .any(|s| s["step"] == "skill" && s["applied"] == true));
    assert!(steps
        .iter()
        .any(|s| s["step"] == "mcp" && s["applied"] == true));

    let calls = std::fs::read_to_string(codex_calls).unwrap();
    assert_eq!(
        calls.lines().collect::<Vec<_>>(),
        vec![
            "mcp add multitool -- aka mcp --client codex",
            "mcp add multitool -- aka mcp --client codex",
            "mcp add multitool -- aka mcp --client codex",
        ]
    );
}

#[test]
fn claude_desktop_setup_write_is_explicitly_repo_only() {
    let home = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_aka"))
        .args(["setup", "claude-desktop", "--write"])
        .current_dir(repo.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env_remove("AKA_BROKER")
        .env_remove("AKA_BROKER_URL")
        .output()
        .unwrap();

    assert_success(&output);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a manual edit"), "{stderr}");
    assert!(
        stderr.contains("--write only prepares this repository"),
        "{stderr}"
    );
    assert!(stderr.contains("\"mcpServers\""), "{stderr}");
    assert!(repo
        .path()
        .join(".claude/skills/multitool/SKILL.md")
        .exists());
}
