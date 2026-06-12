// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for listing and exporting bundled configuration assets.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::config::built_in_config_assets_v1;

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let Some(subcommand) = args.first().map(String::as_str) else {
        eprintln!("fitctl config: expected 'list' or 'export'");
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    };

    match subcommand {
        "list" => run_list(&args[1..]),
        "export" => run_export(&args[1..]),
        unknown => {
            eprintln!("fitctl config: unknown config subcommand '{unknown}'");
            ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
        }
    }
}

fn run_list(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("fitctl config list: unexpected arguments");
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    }

    println!("Category | Id | Path");
    println!("---------+----+-----");
    for asset in built_in_config_assets_v1() {
        println!(
            "{} | {} | {}",
            asset.category, asset.id, asset.relative_path
        );
    }
    ExitCode::SUCCESS
}

fn run_export(args: &[String]) -> ExitCode {
    let mut out_dir: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--out-dir" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl config export: --out-dir requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl config export: unknown option '{unknown}'");
                return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
            }
        }
    }

    let Some(out_dir) = out_dir else {
        eprintln!("fitctl config export: --out-dir is required");
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    };

    for asset in built_in_config_assets_v1() {
        let path = out_dir.join(asset.relative_path);
        let Some(parent) = path.parent() else {
            eprintln!(
                "fitctl config export: invalid bundled config path {}",
                asset.relative_path
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        };
        if let Err(error) = fs::create_dir_all(parent) {
            eprintln!(
                "fitctl config export: failed to create {}: {error}",
                parent.display()
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
        if let Err(error) = fs::write(&path, asset.contents) {
            eprintln!(
                "fitctl config export: failed to write {}: {error}",
                path.display()
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    }

    println!(
        "Exported {} bundled config files to {}",
        built_in_config_assets_v1().len(),
        out_dir.display()
    );
    ExitCode::SUCCESS
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl config list\n  fitctl config export --out-dir <dir>\n\nNotes:\n  - exported files keep the same configs/... paths used in repository examples\n"
}
