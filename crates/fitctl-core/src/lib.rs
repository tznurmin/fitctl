// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Core library for fitctl.
//!
//! The crate is organised around the tool's main pipeline:
//!
//! - survey collects raw host evidence from live Linux sources or replay fixtures,
//! - contract derives a policy-shaped host promise from that evidence,
//! - validate compares a service profile against the derived host promise,
//! - supporting modules handle typed artifacts, presentation, redaction, export, signing,
//!   verification, and optional extension namespaces.

pub mod artifacts;
pub mod bundle;
pub mod classify;
pub mod config;
pub mod config_bundle;
pub mod contract;
pub mod diff;
pub mod error;
pub mod export;
pub mod extensions;
pub mod fixtures;
pub mod identity;
pub mod inspect;
pub mod policy;
pub mod recommendation;
pub mod redact;
pub mod service_profile;
pub mod sign;
pub mod state;
pub mod survey;
pub mod validate;
pub mod verify;

/// Public command summary used by CLI help rendering.
pub struct CommandSpec {
    pub name: &'static str,
    pub summary: &'static str,
    pub tier: CommandTier,
}

/// Support tiers keep the top-level help output aligned with the public release contract.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CommandTier {
    StableCore,
    Experimental,
}

/// Alias metadata for commands that intentionally share one implementation path.
pub struct CommandAliasSpec {
    pub alias: &'static str,
    pub target: &'static str,
}

/// Successful execution.
pub const EXIT_CODE_SUCCESS: u8 = 0;
/// A policy or trust decision rejected the input without a usage error.
pub const EXIT_CODE_POLICY_REJECTION: u8 = 1;
/// Command-line usage or invocation shape was invalid.
pub const EXIT_CODE_USAGE_ERROR: u8 = 2;

pub const COMMANDS: [CommandSpec; 17] = [
    CommandSpec {
        name: "survey",
        summary: "Collect raw host evidence",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "contract",
        summary: "Derive a host contract from survey plus policy",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "classify",
        summary: "Classify contracts against explicit profiles or catalogue selections",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "bundle",
        summary: "Assemble one local decision bundle from validated artifacts",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "bundle-config",
        summary: "Assemble one local config bundle from advanced selections",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "state",
        summary: "Emit live runtime state",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "validate",
        summary: "Validate a service profile against a contract",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "diff",
        summary: "Compare artifacts semantically",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "redact",
        summary: "Apply a named redaction profile",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "export",
        summary: "Emit derived adapter outputs",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "sign",
        summary: "Attach a signature envelope",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "verify",
        summary: "Verify signatures and evaluate local trust policy",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "completion",
        summary: "Emit a shell completion script",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "inspect",
        summary: "Render a human-readable artifact summary",
        tier: CommandTier::StableCore,
    },
    CommandSpec {
        name: "inspect-config",
        summary: "Render one resolved local config selection",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "lock-policy-pack",
        summary: "Emit a locked selection for one policy-pack entry",
        tier: CommandTier::Experimental,
    },
    CommandSpec {
        name: "recommend",
        summary: "Emit one advisory recommendation report from validation",
        tier: CommandTier::Experimental,
    },
];

pub const COMMAND_ALIASES: [CommandAliasSpec; 1] = [CommandAliasSpec {
    alias: "resolve-config",
    target: "inspect-config",
}];

/// Render the top-level CLI help text from the pinned public command registry.
pub fn render_help(program_name: &str) -> String {
    let mut lines = vec![
        format!("{program_name} - host capability contract tool"),
        String::new(),
        "Usage:".to_string(),
        format!("  {program_name} <command>"),
        String::new(),
        "Commands:".to_string(),
    ];

    lines.push("Stable core:".to_string());
    for command in COMMANDS
        .iter()
        .filter(|command| command.tier == CommandTier::StableCore)
    {
        lines.push(format!("  {:<16} {}", command.name, command.summary));
    }

    lines.push(String::new());
    lines.push("Experimental:".to_string());
    for command in COMMANDS
        .iter()
        .filter(|command| command.tier == CommandTier::Experimental)
    {
        lines.push(format!("  {:<16} {}", command.name, command.summary));
    }

    lines.join("\n") + "\n"
}

pub fn is_known_command(name: &str) -> bool {
    COMMANDS.iter().any(|command| command.name == name)
}

pub fn resolve_command_alias(name: &str) -> Option<&'static str> {
    COMMAND_ALIASES
        .iter()
        .find(|alias| alias.alias == name)
        .map(|alias| alias.target)
}

pub fn is_known_command_or_alias(name: &str) -> bool {
    is_known_command(name) || resolve_command_alias(name).is_some()
}
