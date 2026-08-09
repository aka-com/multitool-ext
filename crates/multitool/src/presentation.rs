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
    ("GET STARTED", &["status", "setup", "login", "logout", "use"]),
    ("ADD & MANAGE", &["conn", "secret", "endpoint"]),
    (
        "APPROVALS & AUDIT",
        &["approvals", "approve", "deny", "sessions", "activity"],
    ),
    ("OPERATOR", &["serve", "admin"]),
    ("RUNTIME", &["mcp", "ssh-agent", "cloud", "completions"]),
];

const ROOT_WORKFLOWS: &[(&str, &str)] = &[
    ("Install the agent skill", "aka setup skill --write"),
    ("Configure an MCP client", "aka setup <client>"),
    ("Run a headless broker", "aka serve"),
    ("Add a connection", "aka conn add pg --help"),
    ("Open Postgres", "aka run <conn> -- psql"),
    ("Open SSH", "aka run <conn> -- ssh <destination>"),
    ("Open a cloud CLI", "aka run <conn> -- <cmd>"),
    ("Print scoped exports", "aka env <conn>"),
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

pub fn warning(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::warning(&message).is_ok() {
        return;
    }
    eprintln!("{}", bold_yellow(color, message));
}

pub fn error(message: impl Display, color: bool) {
    let message = message.to_string();
    if stderr_is_tty() && cliclack::log::error(&message).is_ok() {
        return;
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

fn help_table(rows: Vec<Vec<String>>) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(terminal_width());
    for row in rows {
        table.add_row(Row::from(row));
    }
    table.set_constraints([
        ColumnConstraint::UpperBoundary(Width::Fixed(30)),
        ColumnConstraint::LowerBoundary(Width::Fixed(24)),
    ]);
    trim_table(table.to_string())
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
    summary
        .find(". ")
        .map(|end| summary[..=end].to_string())
        .unwrap_or(summary)
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
        "setup" => "setup [<client>]".into(),
        "login" => "login <url>".into(),
        "logout" => "logout [<context>]".into(),
        "use" => "use [<context>]".into(),
        "endpoint" => "endpoint <conn>".into(),
        "approve" => "approve <id>".into(),
        "deny" => "deny <id>".into(),
        "ssh-agent" => "ssh-agent <conn>".into(),
        "completions" => "completions <shell>".into(),
        "conn add api" | "conn add pg" | "conn add ssh" | "conn add cloud aws"
        | "conn add cloud azure" | "conn add cloud gcp" => format!("{leaf} <name>"),
        "conn show" => "show <conn>".into(),
        "conn update" => "update [<conn>]".into(),
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
        "cloud creds" | "cloud install" => format!("{leaf} <conn>"),
        _ => leaf.into(),
    }
}

fn append_command_tree_rows(
    rows: &mut Vec<Vec<String>>,
    command: &Command,
    path: &mut Vec<String>,
    depth: usize,
    color: bool,
) {
    path.push(command.get_name().to_string());
    let label = format!("{}{}", "  ".repeat(depth), help_command_label(path));
    rows.push(vec![literal(color, label), command_summary(command)]);
    for child in command
        .get_subcommands()
        .filter(|child| child.get_name() != "help" && !child.is_hide_set())
    {
        append_command_tree_rows(rows, child, path, depth + 1, color);
    }
    path.pop();
}

fn render_root_commands(command: &Command, color: bool) -> String {
    let mut output = String::new();
    let mut seen = std::collections::HashSet::new();
    for (group, names) in ROOT_GROUPS {
        let mut rows = Vec::new();
        for subcommand in names.iter().filter_map(|name| {
            command
                .get_subcommands()
                .find(|candidate| candidate.get_name() == *name)
        }) {
            seen.insert(subcommand.get_name());
            append_command_tree_rows(&mut rows, subcommand, &mut Vec::new(), 0, color);
        }
        if !rows.is_empty() {
            output.push_str(&format!(
                "\n{}\n{}\n",
                heading(color, group),
                help_table(rows)
            ));
        }
    }

    let other = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help" && !subcommand.is_hide_set())
        .filter(|subcommand| !seen.contains(subcommand.get_name()))
        .map(|subcommand| {
            vec![
                literal(
                    color,
                    help_command_label(&[subcommand.get_name().to_string()]),
                ),
                command_summary(subcommand),
            ]
        })
        .collect::<Vec<_>>();
    if !other.is_empty() {
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "OTHER"),
            help_table(other)
        ));
    }
    output
}

fn render_subcommands(command: &Command, color: bool) -> String {
    let rows = command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help" && !subcommand.is_hide_set())
        .map(|subcommand| {
            vec![
                literal(color, subcommand.get_name()),
                command_summary(subcommand),
            ]
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        String::new()
    } else {
        format!("\n{}\n{}\n", heading(color, "COMMANDS"), help_table(rows))
    }
}

fn render_args(command: &Command, color: bool, long: bool) -> String {
    let positionals = command
        .get_positionals()
        .filter(|arg| !arg.is_hide_set() && (!long || !arg.is_hide_long_help_set()))
        .map(|arg| vec![literal(color, arg_label(arg)), arg_help(arg, long)])
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
        .map(|arg| vec![literal(color, arg_label(arg)), arg_help(arg, long)])
        .collect::<Vec<_>>();

    let mut output = String::new();
    if !positionals.is_empty() {
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "ARGUMENTS"),
            help_table(positionals)
        ));
    }
    if !options.is_empty() {
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "OPTIONS"),
            help_table(options)
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
    let about = command_about(command, long);
    if !about.is_empty() {
        output.push_str(&format!("{about}\n"));
    }
    output.push('\n');
    output.push_str(&render_usage(command, color));
    output.push('\n');
    if root {
        output.push_str(&render_root_commands(command, color));
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
            .map(|(name, invocation)| vec![name.to_string(), literal(color, invocation)])
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "\n{}\n{}\n{}\n",
            heading(color, "EXAMPLES"),
            " Put your command after `--` to run it with short-lived credentials:",
            help_table(rows)
        ));
    } else if root {
        let rows = ROOT_WORKFLOWS
            .iter()
            .map(|(name, invocation)| vec![name.to_string(), literal(color, invocation)])
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "COMMON WORKFLOWS"),
            help_table(rows)
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
}
