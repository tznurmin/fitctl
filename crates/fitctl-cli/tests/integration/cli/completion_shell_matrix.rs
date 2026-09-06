// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
pub(crate) fn completion_execution_zsh_dispatch_and_nested_options() {
    let generated = Command::new(cli::fitctl_bin())
        .args(["completion", "zsh"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    // Real Zsh executes the generated dispatch. These are only completion-editor output adapters.
    let mut script = String::from("compdef() { :; }\ncompadd() { printf '%s\\n' \"${@:#--}\"; }\n");
    script.push_str(std::str::from_utf8(&generated.stdout).unwrap());
    script.push_str("\nfor cmd in state validate; do words=(fitctl $cmd --collect ''); CURRENT=4; _fitctl_completion; done\nwords=(fitctl storage profile init ''); CURRENT=5; _fitctl_completion\nwords=(fitctl resolve-config ''); CURRENT=3; _fitctl_completion\nwords=(fitctl config export ''); CURRENT=4; _fitctl_completion\nwords=(fitctl thermal collect ''); CURRENT=4; _fitctl_completion\nfor cmd in validate classify; do words=(fitctl $cmd --validation-mode ''); CURRENT=4; _fitctl_completion; done\n");
    let out = run("FITCTL_TEST_ZSH", "zsh", &["-f"], &script);
    for c in [
        "thermal",
        "memory-reliability",
        "gpu-reliability",
        "cuda-runtime",
        "hardware-sensors",
    ] {
        assert_eq!(out.lines().filter(|s| *s == c).count(), 2, "{c}: {out}");
    }
    assert!(out.contains("--min-available-bytes"));
    assert!(out.lines().any(|s| s == "--profile-id"));
    assert!(out.contains("--out-dir"));
    assert!(out.contains("--require-target-host-id"));
    assert_eq!(out.lines().filter(|s| *s == "state_required").count(), 2);
}

#[test]
pub(crate) fn completion_execution_fish_dispatch_and_nested_options() {
    let generated = Command::new(cli::fitctl_bin())
        .args(["completion", "fish"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut script = String::from_utf8(generated.stdout).unwrap();
    script.push_str("\ncomplete --do-complete 'fitctl state --collect '\ncomplete --do-complete 'fitctl validate --collect '\ncomplete --do-complete 'fitctl storage profile init --min-'\ncomplete --do-complete 'fitctl thermal collect --require-target-'\n");
    script.push_str("complete --do-complete 'fitctl config export --out-'\ncomplete --do-complete 'fitctl resolve-config --profile-'\ncomplete --do-complete 'fitctl validate --validation-mode '\ncomplete --do-complete 'fitctl classify --validation-mode '\n");
    let out = run("FITCTL_TEST_FISH", "fish", &["--no-config"], &script);
    for c in [
        "thermal",
        "memory-reliability",
        "gpu-reliability",
        "cuda-runtime",
        "hardware-sensors",
    ] {
        assert_eq!(
            out.lines()
                .filter(|s| s.split('\t').next() == Some(c))
                .count(),
            2,
            "{c}: {out}"
        );
    }
    assert!(out.contains("--min-available-bytes"));
    assert!(out.contains("--require-target-host-id"));
    assert!(out.contains("--out-dir"));
    assert!(out.contains("--profile-id"));
    assert_eq!(
        out.lines()
            .filter(|s| s.split('\t').next() == Some("state_required"))
            .count(),
        2
    );
}

fn run(variable: &str, default: &str, args: &[&str], script: &str) -> String {
    let shell = std::env::var_os(variable).unwrap_or_else(|| default.into());
    let mut child = Command::new(shell)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("required completion shell {variable} unavailable: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
