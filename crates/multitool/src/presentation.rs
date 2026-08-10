//! Human-facing terminal presentation for the CLI.
//!
//! Parsing remains in clap and machine-readable output remains in the command
//! handlers. This module owns the optional terminal polish: generated help,
//! width-aware tables, styled messages, and progress indicators.

use std::fmt::Display;
use std::io::IsTerminal as _;

use anstyle::{AnsiColor, Style};
use clap::{Arg, ColorChoice, Command};
use comfy_table::{
    presets::NOTHING, Cell, ColumnConstraint, ContentArrangement, Row, Table, Width,
};

const ROOT_GROUPS: &[(&str, &[&str])] = &[
    ("USE A CONNECTION", &["run", "env", "ls"]),
    (
        "GET STARTED",
        &["setup", "login", "use", "status", "logout", "skill"],
    ),
    ("ADD & MANAGE", &["conn", "secret", "endpoint"]),
    (
        "APPROVALS & AUDIT",
        &["approvals", "approve", "deny", "sessions", "activity"],
    ),
    ("OPERATOR", &["serve", "admin"]),
    ("RUNTIME", &["mcp", "ssh-agent", "cloud", "completions"]),
];

const ROOT_EXAMPLES: &[(&str, &str)] = &[
    ("Preview Codex setup", "aka setup codex"),
    ("Configure Codex + repo", "aka setup codex --write"),
    ("Preview Claude Code setup", "aka setup claude-code"),
    (
        "Configure Claude Code + repo",
        "aka setup claude-code --write",
    ),
    ("Preview Claude Desktop", "aka setup claude-desktop"),
    (
        "Prepare Claude Desktop repo",
        "aka setup claude-desktop --write",
    ),
    ("Open Postgres", "aka run <conn> -- psql"),
    ("Open SSH", "aka run <conn> -- ssh <destination>"),
    (
        "Open a cloud CLI",
        "aka run <conn> -- aws sts get-caller-identity",
    ),
];

fn terminal_width() -> u16 {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(100)
        .clamp(60, 120)
}

fn style(enabled: bool, style: Style, value: impl Display) -> String {
    if enabled {
        format!("{style}{value}{style:#}")
    } else {
        value.to_string()
    }
}

pub fn bold_red(enabled: bool, value: impl Display) -> String {
    style(
        enabled,
        Style::new().fg_color(Some(AnsiColor::Red.into())).bold(),
        value,
    )
}

pub fn bold_green(enabled: bool, value: impl Display) -> String {
    style(
        enabled,
        Style::new().fg_color(Some(AnsiColor::Green.into())).bold(),
        value,
    )
}

pub fn bold_yellow(enabled: bool, value: impl Display) -> String {
    style(
        enabled,
        Style::new().fg_color(Some(AnsiColor::Yellow.into())).bold(),
        value,
    )
}

pub fn bold_cyan(enabled: bool, value: impl Display) -> String {
    style(
        enabled,
        Style::new().fg_color(Some(AnsiColor::Cyan.into())).bold(),
        value,
    )
}

pub fn dim(enabled: bool, value: impl Display) -> String {
    style(enabled, Style::new().dimmed(), value)
}

pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

pub fn success(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::success(&message).is_ok() {
        return;
    }
    eprintln!("{}", bold_green(color, message));
}

pub fn remark(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::remark(&message).is_ok() {
        return;
    }
    eprintln!("{}", dim(color, message));
}

pub fn info(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::info(&message).is_ok() {
        return;
    }
    eprintln!("{}", bold_cyan(color, message));
}

/// Print an informational row without cliclack's trailing spacer bar so a
/// related row can follow immediately beneath it.
pub fn info_compact(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() {
        let message = cliclack::termwrap(&message, 3);
        let mut lines = message.lines();
        if let Some(first) = lines.next() {
            let symbol = style(
                color,
                Style::new().fg_color(Some(AnsiColor::Blue.into())),
                "●",
            );
            eprintln!("{symbol}  {first}");
            for line in lines {
                eprintln!("{}  {line}", dim(color, "│"));
            }
        }
        return;
    }
    eprintln!("{}", bold_cyan(color, message));
}

pub fn warning(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::warning(&message).is_ok() {
        return;
    }
    eprintln!("{}", bold_yellow(color, message));
}

pub fn error(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() {
        let message = cliclack::termwrap(&message, 3);
        if cliclack::log::error(&message).is_ok() {
            return;
        }
    }
    eprintln!("{} {message}", bold_red(color, "error:"));
}

pub fn password(prompt: impl Display) -> std::io::Result<String> {
    cliclack::password(prompt).mask('•').interact()
}

pub struct Spinner(Option<cliclack::ProgressBar>);

impl Spinner {
    pub fn start(message: impl Display) -> Self {
        if !stderr_is_tty() {
            return Self(None);
        }
        let spinner = cliclack::spinner();
        spinner.start(message);
        Self(Some(spinner))
    }

    pub fn start_if(enabled: bool, message: impl Display) -> Self {
        if enabled {
            Self::start(message)
        } else {
            Self(None)
        }
    }

    pub fn stop(mut self, message: impl Display) {
        if let Some(spinner) = self.0.take() {
            spinner.stop(message);
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(spinner) = self.0.take() {
            spinner.clear();
        }
    }
}

/// Render a restrained, borderless table that wraps to a sensible width.
pub fn table(headers: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(terminal_width())
        .set_header(
            headers
                .iter()
                .map(|header| Cell::new(header.to_uppercase())),
        );
    for row in rows {
        table.add_row(Row::from(row));
    }
    trim_table(table.to_string())
}

fn help_table(rows: Vec<Vec<String>>, color: bool, highlighted_column: usize) -> String {
    help_table_with_first_column_width(rows, color, highlighted_column, None)
}

fn help_table_with_first_column_width(
    rows: Vec<Vec<String>>,
    color: bool,
    highlighted_column: usize,
    first_column_width: Option<u16>,
) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(terminal_width());
    let highlights = rows
        .iter()
        .filter_map(|row| row.get(highlighted_column).cloned())
        .collect::<Vec<_>>();
    for row in rows {
        table.add_row(Row::from(row));
    }
    table.set_constraints([
        first_column_width.map_or(ColumnConstraint::UpperBoundary(Width::Fixed(30)), |width| {
            ColumnConstraint::Absolute(Width::Fixed(width))
        }),
        ColumnConstraint::LowerBoundary(Width::Fixed(24)),
    ]);
    let rendered = trim_table(table.to_string());
    if color {
        colorize_table_column(rendered, &highlights, highlighted_column)
    } else {
        rendered
    }
}

/// Apply color only after comfy-table has measured and wrapped the plain
/// cells. ANSI escape sequences otherwise count toward a cell's visible width
/// when comfy-table is built without its optional styling feature.
fn colorize_table_column(rendered: String, values: &[String], column: usize) -> String {
    if column == 0 {
        return rendered
            .lines()
            .map(|line| {
                let Some(content) = line.strip_prefix(' ') else {
                    return line.to_string();
                };
                for value in values {
                    let Some(suffix) = content.strip_prefix(value) else {
                        continue;
                    };
                    if suffix.is_empty() || suffix.starts_with("  ") {
                        return format!(" {}{suffix}", literal(true, value));
                    }
                }
                line.to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
    }

    let mut rendered = rendered;
    for value in values {
        rendered = rendered.replacen(value, &literal(true, value), 1);
    }
    rendered
}

fn trim_table(rendered: String) -> String {
    rendered
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn heading(color: bool, text: &str) -> String {
    bold_green(color, text)
}

fn literal(color: bool, text: impl Display) -> String {
    bold_cyan(color, text)
}

fn command_about(command: &Command, long: bool) -> String {
    let about = if long {
        command.get_long_about().or_else(|| command.get_about())
    } else {
        command.get_about().or_else(|| command.get_long_about())
    };
    about.map(ToString::to_string).unwrap_or_default()
}

fn command_summary(command: &Command) -> String {
    let summary = command
        .get_about()
        .or_else(|| command.get_long_about())
        .map(ToString::to_string)
        .unwrap_or_default();
    let summary = summary
        .find(". ")
        .map(|end| summary[..=end].to_string())
        .unwrap_or(summary);
    summary.trim_end_matches('.').to_string()
}

fn arg_label(arg: &Arg) -> String {
    let value_name = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map(ToString::to_string)
        .unwrap_or_else(|| arg.get_id().as_str().replace('_', "-").to_uppercase());
    if arg.is_positional() {
        return if arg.is_required_set() {
            format!("<{value_name}>")
        } else {
            format!("[{value_name}]")
        };
    }

    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("--{long}"));
    }
    let mut label = names.join(", ");
    if arg.get_num_args().is_some_and(|range| range.takes_values()) {
        label.push(' ');
        label.push('<');
        label.push_str(&value_name);
        label.push('>');
    }
    label
}

fn arg_help(arg: &Arg, long: bool) -> String {
    let help = if long {
        arg.get_long_help().or_else(|| arg.get_help())
    } else {
        arg.get_help().or_else(|| arg.get_long_help())
    };
    let mut help = help.map(ToString::to_string).unwrap_or_default();
    if !matches!(
        arg.get_action(),
        clap::ArgAction::SetTrue
            | clap::ArgAction::SetFalse
            | clap::ArgAction::Help
            | clap::ArgAction::HelpShort
            | clap::ArgAction::HelpLong
            | clap::ArgAction::Version
    ) && !arg.is_hide_default_value_set()
        && !arg.get_default_values().is_empty()
    {
        let defaults = arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join(", ");
        help.push_str(&format!(" [default: {defaults}]"));
    }
    if !arg.is_hide_possible_values_set() {
        let possible = arg.get_possible_values();
        if (2..=6).contains(&possible.len()) {
            let values = possible
                .iter()
                .filter(|value| !value.is_hide_set())
                .map(|value| value.get_name())
                .collect::<Vec<_>>()
                .join(", ");
            if !values.is_empty() {
                help.push_str(&format!(" [possible: {values}]"));
            }
        }
    }
    help
}

fn render_usage(command: &Command, color: bool) -> String {
    let mut plain = command.clone().color(ColorChoice::Never);
    let usage = plain.render_usage().to_string();
    let usage = usage.strip_prefix("Usage:").unwrap_or(&usage).trim();
    format!("{} {}", heading(color, "USAGE"), literal(color, usage))
}

fn help_command_label(path: &[String]) -> String {
    let key = path.join(" ");
    let leaf = path.last().map(String::as_str).unwrap_or_default();
    match key.as_str() {
        "run" => "run <conn> -- <cmd>".into(),
        "env" => "env <conn>".into(),
        "setup" => "setup".into(),
        "login" => "login <url>".into(),
        "logout" => "logout".into(),
        "use" => "use".into(),
        "endpoint" => "endpoint <conn>".into(),
        "approve" => "approve <id>".into(),
        "deny" => "deny <id>".into(),
        "ssh-agent" => "ssh-agent <conn>".into(),
        "completions" => "completions <shell>".into(),
        "conn add api"
        | "conn add pg"
        | "conn add ssh"
        | "conn add cloud aws"
        | "conn add cloud azure"
        | "conn add cloud gcp" => format!("{leaf} <name>"),
        "conn show" => "show <conn>".into(),
        "conn update" => "update".into(),
        "conn update api" | "conn update pg" | "conn update ssh" => {
            format!("{leaf} <conn>")
        }
        "conn rename" => "rename <conn> <new>".into(),
        "conn rm" => "rm <conn>".into(),
        "conn enable" => "enable <conn>".into(),
        "conn disable" => "disable <conn>".into(),
        "conn test" => "test <conn>".into(),
        "secret add" => "add <name>".into(),
        "secret rename" => "rename <name> <new>".into(),
        "secret rotate" => "rotate <name>".into(),
        "secret rm" => "rm <name>".into(),
        "cloud creds" | "cloud config" => format!("{leaf} <conn>"),
        _ => leaf.into(),
    }
}

fn append_command_tree_rows(
    rows: &mut Vec<Vec<String>>,
    command: &Command,
    path: &mut Vec<String>,
    depth: usize,
    expand_children: bool,
) {
    path.push(command.get_name().to_string());
    if !expand_children && path.as_slice() == ["cloud"] {
        for child in command
            .get_subcommands()
            .filter(|child| child.get_name() != "help" && !child.is_hide_set())
        {
            path.push(child.get_name().to_string());
            rows.push(vec![
                format!("cloud {}", help_command_label(path)),
                command_summary(child),
            ]);
            path.pop();
        }
        path.pop();
        return;
    }
    let command_label = match (expand_children, path.as_slice()) {
        (false, [name]) if matches!(name.as_str(), "conn" | "secret") => {
            format!("{name} [add | …]")
        }
        _ => help_command_label(path),
    };
    let label = format!("{}{}", "  ".repeat(depth), command_label);
    let summary = command_summary(command);
    rows.push(vec![label, summary]);
    if !expand_children && path.as_slice() == ["setup"] {
        for child in command.get_subcommands().filter(|child| {
            matches!(child.get_name(), "skill" | "instructions" | "desktop") && !child.is_hide_set()
        }) {
            path.push(child.get_name().to_string());
            rows.push(vec![
                format!("setup {}", help_command_label(path)),
                command_summary(child),
            ]);
            path.pop();
        }
    }
    if expand_children {
        for child in command
            .get_subcommands()
            .filter(|child| child.get_name() != "help" && !child.is_hide_set())
        {
            append_command_tree_rows(rows, child, path, depth + 1, true);
        }
    }
    path.pop();
}

fn render_root_commands(command: &Command, color: bool, expand_children: bool) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut groups = Vec::new();
    for (group, names) in ROOT_GROUPS {
        let mut rows = Vec::new();
        for subcommand in names.iter().filter_map(|name| {
            command
                .get_subcommands()
                .find(|candidate| candidate.get_name() == *name)
                .filter(|candidate| candidate.get_name() != "skill")
        }) {
            seen.insert(subcommand.get_name());
            append_command_tree_rows(&mut rows, subcommand, &mut Vec::new(), 0, expand_children);
        }
        if !rows.is_empty() {
            groups.push((*group, rows));
        }
    }

    let other = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help" && !subcommand.is_hide_set())
        .filter(|subcommand| !seen.contains(subcommand.get_name()))
        .map(|subcommand| {
            vec![
                help_command_label(&[subcommand.get_name().to_string()]),
                command_summary(subcommand),
            ]
        })
        .collect::<Vec<_>>();
    if !other.is_empty() {
        groups.push(("OTHER", other));
    }

    let first_column_width = groups
        .iter()
        .flat_map(|(_, rows)| rows)
        .filter_map(|row| row.first())
        .map(|label| label.chars().count())
        .max()
        .unwrap_or_default()
        .min(28) as u16
        + 2;

    let mut output = String::new();
    for (group, rows) in groups {
        let table = help_table_with_first_column_width(rows, color, 0, Some(first_column_width));
        output.push_str(&format!("\n{}\n{}\n", heading(color, group), table));
    }
    output
}

fn render_subcommands(command: &Command, color: bool) -> String {
    let rows = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help" && !subcommand.is_hide_set())
        .map(|subcommand| {
            vec![
                subcommand.get_name().to_string(),
                command_summary(subcommand),
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        String::new()
    } else {
        format!(
            "\n{}\n{}\n",
            heading(color, "COMMANDS"),
            help_table(rows, color, 0)
        )
    }
}

fn render_args(command: &Command, color: bool, long: bool) -> String {
    let positionals = command
        .get_positionals()
        .filter(|arg| !arg.is_hide_set() && (!long || !arg.is_hide_long_help_set()))
        .map(|arg| vec![arg_label(arg), arg_help(arg, long)])
        .collect::<Vec<_>>();
    let streaming_command = matches!(
        command.get_bin_name(),
        Some("aka serve" | "aka mcp" | "aka ssh-agent" | "aka completions")
    );
    let options = command
        .get_arguments()
        .filter(|arg| !arg.is_positional())
        .filter(|arg| arg.get_id() != "json" || !streaming_command)
        .filter(|arg| !arg.is_hide_set() && (!long || !arg.is_hide_long_help_set()))
        .map(|arg| vec![arg_label(arg), arg_help(arg, long)])
        .collect::<Vec<_>>();

    let mut output = String::new();
    if !positionals.is_empty() {
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "ARGUMENTS"),
            help_table(positionals, color, 0)
        ));
    }
    if !options.is_empty() {
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "OPTIONS"),
            help_table(options, color, 0)
        ));
    }
    output
}

fn render_help(command: &Command, color: bool, root: bool, long: bool) -> String {
    let title = if root {
        match command.get_version() {
            Some(version) => format!("aka {version}"),
            None => "aka".into(),
        }
    } else {
        command
            .get_bin_name()
            .map(str::to_string)
            .unwrap_or_else(|| command.get_name().to_string())
    };
    let mut output = format!("{}\n", bold_green(color, title));
    if !root {
        let about = command_about(command, long);
        if !about.is_empty() {
            output.push_str(&format!("{about}\n"));
        }
        output.push('\n');
    }
    output.push_str(&render_usage(command, color));
    output.push('\n');
    if root {
        output.push_str(&render_root_commands(command, color, long));
    } else {
        output.push_str(&render_subcommands(command, color));
    }
    output.push_str(&render_args(command, color, long));

    if root && !long {
        let examples = [
            ("Postgres", "aka run <conn> -- psql"),
            ("SSH", "aka run <conn> -- ssh <destination>"),
            ("Cloud CLI", "aka run <conn> -- aws sts get-caller-identity"),
        ];
        let rows = examples
            .iter()
            .map(|(name, invocation)| vec![name.to_string(), invocation.to_string()])
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "\n{}\n{}\n{}\n",
            heading(color, "EXAMPLES"),
            " Run commands after `--` with short-lived credentials:",
            help_table(rows, color, 1)
        ));
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "FULL REFERENCE"),
            help_table(
                vec![vec![
                    "aka --help".into(),
                    "Show every command and subcommand".into(),
                ]],
                color,
                0,
            )
        ));
    } else if root {
        let rows = ROOT_EXAMPLES
            .iter()
            .map(|(name, invocation)| vec![name.to_string(), invocation.to_string()])
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "EXAMPLES"),
            help_table(rows, color, 1)
        ));
    } else if let Some(after) = command
        .get_after_long_help()
        .or_else(|| command.get_after_help())
    {
        output.push('\n');
        for line in after.to_string().lines() {
            // After-help blocks carry their own section titles (e.g.
            // EXAMPLES); style them like the generated headings.
            if line == "EXAMPLES" {
                output.push_str(&heading(color, line));
            } else {
                output.push_str(line);
            }
            output.push('\n');
        }
    }
    output
}

fn install_help_recursive(command: &mut Command, color: bool, root: bool, long: bool) {
    for subcommand in command.get_subcommands_mut() {
        if subcommand.get_name() != "help" {
            install_help_recursive(subcommand, color, false, long);
        }
    }
    let help = render_help(command, color, root, long);
    *command = command.clone().override_help(help);
}

/// Replace clap's help printer while retaining clap's parser, validation,
/// suggestions, exit codes, and command metadata as the source of truth.
pub fn install_help(command: &mut Command, color: bool, long: bool) {
    command.build();
    install_help_recursive(command, color, true, long);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_borderless_and_keeps_headers() {
        let output = table(
            &["name", "state"],
            [vec!["github".into(), "enabled".into()]],
        );
        assert!(output.contains("NAME"));
        assert!(output.contains("github"));
        assert!(!output.contains('|'));
        assert!(!output.contains('+'));
    }

    #[test]
    fn help_table_color_does_not_affect_cell_widths() {
        let rows = vec![
            vec!["setup".into(), "Connect an agent or app".into()],
            vec!["      aws <name>".into(), "Add an AWS connection".into()],
        ];
        let plain = help_table(rows.clone(), false, 0);
        let colored = help_table(rows, true, 0);
        let decolored = colored
            .replace("\u{1b}[1m\u{1b}[36m", "")
            .replace("\u{1b}[0m", "");

        assert_eq!(decolored, plain);
        assert_eq!(colored.lines().count(), 2);
    }

    #[test]
    fn compact_root_choices_are_part_of_command_labels() {
        let mut command = Command::new("aka")
            .version("test")
            .subcommand(
                Command::new("setup")
                    .about("Connect an agent or app")
                    .subcommand(Command::new("skill").about("Install the agent skill"))
                    .subcommand(Command::new("instructions").about("Print setup instructions"))
                    .subcommand(Command::new("desktop").about("Show desktop connection details")),
            )
            .subcommand(Command::new("conn").about("Add and manage connections"))
            .subcommand(Command::new("secret").about("Add and manage vault secrets"))
            .subcommand(Command::new("admin").about("Manage broker access and settings"))
            .subcommand(
                Command::new("cloud")
                    .about("Credential-process integration")
                    .subcommand(Command::new("creds").about("Print temporary cloud credentials"))
                    .subcommand(Command::new("config").about("Print cloud CLI configuration")),
            );
        command.build();

        let output = render_help(&command, true, true, false);
        assert!(output.contains(&literal(true, "setup skill")));
        assert!(output.contains(&literal(true, "setup instructions")));
        assert!(output.contains(&literal(true, "setup desktop")));
        assert!(output.contains(&literal(true, "conn [add | …]")));
        assert!(output.contains(&literal(true, "secret [add | …]")));
        assert!(!output.contains("commands:"));
        assert!(!output.contains("commands: invite"));
        assert!(output.contains(&literal(true, "cloud creds <conn>")));
        assert!(output.contains(&literal(true, "cloud config <conn>")));
        assert!(output.contains(&literal(true, "aka --help")));
    }
}
