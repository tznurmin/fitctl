// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for human-readable artifact inspection.

use std::env;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::inspect::{
    load_artifact_record_for_inspect, load_artifact_record_for_inspect_from_value,
    render_inspect_artifact_summary_with_options_v1, InspectPaletteV1, InspectRenderOptionsV1,
    InspectStyleOptionsV1, InspectViewV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut input_path: Option<PathBuf> = None;
    let mut verbose = false;
    let mut show_identifiers = false;
    let mut color_mode = ColorModeV1::Auto;
    let mut view = InspectViewV1::Summary;
    let mut explicit_view: Option<InspectViewV1> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--verbose" => {
                verbose = true;
                index += 1;
            }
            "--show-identifiers" => {
                show_identifiers = true;
                index += 1;
            }
            "--color" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect: --color requires a value");
                    return ExitCode::from(2);
                };
                color_mode = match parse_color_mode(value) {
                    Ok(mode) => mode,
                    Err(error) => {
                        eprintln!("fitctl inspect: {error}");
                        return ExitCode::from(2);
                    }
                };
                index += 2;
            }
            "--view" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect: --view requires a value");
                    return ExitCode::from(2);
                };
                let requested_view = match parse_inspect_view(value) {
                    Ok(view) => view,
                    Err(error) => {
                        eprintln!("fitctl inspect: {error}");
                        return ExitCode::from(2);
                    }
                };
                if let Err(error) = record_explicit_view(&mut explicit_view, requested_view) {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
                view = requested_view;
                index += 2;
            }
            "--matrix" => {
                if let Err(error) = record_explicit_view(&mut explicit_view, InspectViewV1::Matrix)
                {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
                view = InspectViewV1::Matrix;
                index += 1;
            }
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl inspect: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let artifact = if let Some(input_path) = input_path {
        if input_path.as_os_str() == "-" {
            match load_artifact_record_from_stdin() {
                Ok(artifact) => artifact,
                Err(error) => {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
            }
        } else {
            match load_artifact_record_for_inspect(&input_path) {
                Ok(artifact) => artifact,
                Err(error) => {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    } else if io::stdin().is_terminal() {
        eprintln!("fitctl inspect: --input is required when stdin is interactive");
        return ExitCode::from(2);
    } else {
        match load_artifact_record_from_stdin() {
            Ok(artifact) => artifact,
            Err(error) => {
                eprintln!("fitctl inspect: {error}");
                return ExitCode::from(2);
            }
        }
    };

    match render_inspect_artifact_summary_with_options_v1(
        &artifact,
        InspectRenderOptionsV1 {
            verbose,
            show_identifiers,
            style: InspectStyleOptionsV1 {
                color_enabled: resolve_use_color(
                    color_mode,
                    io::stdout().is_terminal(),
                    env::var_os("NO_COLOR").is_some(),
                ),
                palette: InspectPaletteV1::Default,
            },
            view,
        },
    ) {
        Ok(summary) => {
            print!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fitctl inspect: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl inspect [--input <path>] [--verbose] [--show-identifiers] [--color <auto|always|never>] [--view <summary|matrix>] [--matrix]\n\nNotes:\n  - when --input is omitted and stdin is piped, inspect reads the artifact from stdin\n  - pass --input - to force stdin explicitly\n  - pass --verbose to include provenance-heavy metadata and hidden diagnostic fields\n  - pass --show-identifiers to reveal full stable identifiers, digests, and fingerprints without the full verbose surface\n  - pass --color auto|always|never to control ANSI colour in terminal output\n  - pass --view matrix or --matrix to render the explicit batch-classification matrix view\n  - matrix view is supported only for batch-classification reports\n  - NO_COLOR disables colour in auto mode\n"
}

fn load_artifact_record_from_stdin() -> Result<fitctl_core::inspect::InspectArtifactV1, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin artifact input: {error}"))?;

    if input.trim().is_empty() {
        return Err("stdin artifact input must not be empty".to_string());
    }

    let raw: serde_json::Value = serde_json::from_str(&input)
        .map_err(|error| format!("failed to decode stdin artifact JSON: {error}"))?;

    load_artifact_record_for_inspect_from_value(raw).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorModeV1 {
    Auto,
    Always,
    Never,
}

fn parse_inspect_view(value: &str) -> Result<InspectViewV1, &'static str> {
    match value {
        "summary" => Ok(InspectViewV1::Summary),
        "matrix" => Ok(InspectViewV1::Matrix),
        _ => Err("--view must be one of: summary, matrix"),
    }
}

fn record_explicit_view(
    current: &mut Option<InspectViewV1>,
    requested: InspectViewV1,
) -> Result<(), &'static str> {
    if let Some(existing) = current {
        if *existing != requested {
            return Err("conflicting inspect views are not allowed");
        }
        return Ok(());
    }

    *current = Some(requested);
    Ok(())
}

fn parse_color_mode(value: &str) -> Result<ColorModeV1, &'static str> {
    match value {
        "auto" => Ok(ColorModeV1::Auto),
        "always" => Ok(ColorModeV1::Always),
        "never" => Ok(ColorModeV1::Never),
        _ => Err("--color must be one of: auto, always, never"),
    }
}

fn resolve_use_color(mode: ColorModeV1, stdout_is_terminal: bool, no_color_present: bool) -> bool {
    match mode {
        ColorModeV1::Auto => stdout_is_terminal && !no_color_present,
        ColorModeV1::Always => true,
        ColorModeV1::Never => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_color_mode, parse_inspect_view, record_explicit_view, resolve_use_color, ColorModeV1,
    };
    use fitctl_core::inspect::InspectViewV1;

    #[test]
    fn parse_color_mode_accepts_supported_values_only() {
        assert_eq!(parse_color_mode("auto"), Ok(ColorModeV1::Auto));
        assert_eq!(parse_color_mode("always"), Ok(ColorModeV1::Always));
        assert_eq!(parse_color_mode("never"), Ok(ColorModeV1::Never));
        assert!(parse_color_mode("sometimes").is_err());
    }

    #[test]
    fn resolve_use_color_respects_auto_terminal_and_no_color() {
        assert!(resolve_use_color(ColorModeV1::Auto, true, false));
        assert!(!resolve_use_color(ColorModeV1::Auto, false, false));
        assert!(!resolve_use_color(ColorModeV1::Auto, true, true));
        assert!(resolve_use_color(ColorModeV1::Always, false, true));
        assert!(!resolve_use_color(ColorModeV1::Never, true, false));
    }

    #[test]
    fn parse_inspect_view_accepts_summary_and_matrix_only() {
        assert_eq!(parse_inspect_view("summary"), Ok(InspectViewV1::Summary));
        assert_eq!(parse_inspect_view("matrix"), Ok(InspectViewV1::Matrix));
        assert!(parse_inspect_view("rows").is_err());
    }

    #[test]
    fn explicit_view_selection_rejects_conflicting_values() {
        let mut current = None;
        assert!(record_explicit_view(&mut current, InspectViewV1::Matrix).is_ok());
        assert_eq!(current, Some(InspectViewV1::Matrix));
        assert!(record_explicit_view(&mut current, InspectViewV1::Matrix).is_ok());
        assert!(record_explicit_view(&mut current, InspectViewV1::Summary).is_err());
    }
}
