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
    ("AGENT", &["skill", "instructions", "mcp"]),
    ("OPEN", &["dsn", "ssh", "cloud", "ssh-agent"]),
    ("VAULT", &["secret", "conn"]),
    (
        "BROKER",
        &[
            "serve", "status", "sessions", "requests", "settings", "key", "activity", "manage",
        ],
    ),
    ("SHELL", &["completions"]),
];

const ROOT_WORKFLOWS: &[(&str, &str)] = &[
    ("Set up an agent", "multitool skill --write"),
    ("Connect an MCP client", "multitool mcp"),
    ("Run a headless broker", "multitool serve [--listen …]"),
    ("Open Postgres", "eval \"$(multitool dsn <conn>)\" && psql"),
    (
        "Open SSH",
        "export SSH_AUTH_SOCK=\"$(multitool ssh <conn>)\"",
    ),
    ("Open a cloud CLI", "eval \"$(multitool cloud env <conn>)\""),
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

fn command_about(command: &Command) -> String {
    command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(ToString::to_string)
        .unwrap_or_default()
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

fn arg_help(arg: &Arg) -> String {
    let mut help = arg
        .get_long_help()
        .or_else(|| arg.get_help())
        .map(ToString::to_string)
        .unwrap_or_default();
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

fn render_root_commands(command: &Command, color: bool) -> String {
    let mut output = String::new();
    let mut seen = std::collections::HashSet::new();
    for (group, names) in ROOT_GROUPS {
        let rows = names
            .iter()
            .filter_map(|name| {
                let subcommand = command
                    .get_subcommands()
                    .find(|candidate| candidate.get_name() == *name)?;
                seen.insert(*name);
                Some(vec![
                    literal(color, subcommand.get_name()),
                    command_summary(subcommand),
                ])
            })
            .collect::<Vec<_>>();
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
        .filter(|subcommand| subcommand.get_name() != "help")
        .filter(|subcommand| !seen.contains(subcommand.get_name()))
        .map(|subcommand| {
            vec![
                literal(color, subcommand.get_name()),
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

fn render_args(command: &Command, color: bool) -> String {
    let positionals = command
        .get_positionals()
        .filter(|arg| !arg.is_hide_set() && !arg.is_hide_long_help_set())
        .map(|arg| vec![literal(color, arg_label(arg)), arg_help(arg)])
        .collect::<Vec<_>>();
    let options = command
        .get_arguments()
        .filter(|arg| !arg.is_positional())
        .filter(|arg| !arg.is_hide_set() && !arg.is_hide_long_help_set())
        .map(|arg| vec![literal(color, arg_label(arg)), arg_help(arg)])
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

fn render_help(command: &Command, color: bool, root: bool) -> String {
    let title = if root {
        match command.get_version() {
            Some(version) => format!("multitool {version}"),
            None => "multitool".into(),
        }
    } else {
        command
            .get_bin_name()
            .map(str::to_string)
            .unwrap_or_else(|| command.get_name().to_string())
    };
    let mut output = format!("{}\n", bold_green(color, title));
    let about = command_about(command);
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
    output.push_str(&render_args(command, color));

    if root {
        let rows = ROOT_WORKFLOWS
            .iter()
            .map(|(name, invocation)| vec![name.to_string(), literal(color, invocation)])
            .collect::<Vec<_>>();
        output.push_str(&format!(
            "\n{}\n{}\n",
            heading(color, "COMMON WORKFLOWS"),
            help_table(rows)
        ));
        output.push_str(&dim(
            color,
            "Run `multitool <command> --help` for command-specific options.",
        ));
        output.push('\n');
    } else if let Some(after) = command
        .get_after_long_help()
        .or_else(|| command.get_after_help())
    {
        output.push('\n');
        output.push_str(&after.to_string());
        output.push('\n');
    }
    output
}

fn install_help_recursive(command: &mut Command, color: bool, root: bool) {
    for subcommand in command.get_subcommands_mut() {
        if subcommand.get_name() != "help" {
            install_help_recursive(subcommand, color, false);
        }
    }
    let help = render_help(command, color, root);
    *command = command.clone().override_help(help);
}

/// Replace clap's help printer while retaining clap's parser, validation,
/// suggestions, exit codes, and command metadata as the source of truth.
pub fn install_help(command: &mut Command, color: bool) {
    command.build();
    install_help_recursive(command, color, true);
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
