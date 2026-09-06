// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use crate::common::{self, fixture_command};
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        Self(common::unique_temp_dir("provider-command-contract"))
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn provider_fixture_command_preserves_process_contract() {
    let root = Root::new();
    let command = fixture_command::write(
        &common::repo_root(), &root.0, "command with spaces",
        "printf '%s\\n' \"$$\" \"$#\" \"$1\" \"$2\" \"$FIXTURE_VALUE\"\nprintf 'diagnostic' >&2\nexit 9",
        0o700,
    ).unwrap();
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(fixture_command::body_path(&command))
        .unwrap();
    let child = Command::new(&command)
        .args(["arg with spaces", "literal;$value"])
        .env("FIXTURE_VALUE", "environment value")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    drop(writer);
    assert_eq!(output.status.code(), Some(9));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{pid}\n2\narg with spaces\nliteral;$value\nenvironment value\n")
    );
    assert_eq!(output.stderr, b"diagnostic");
}

#[test]
fn provider_fixture_command_rejects_replacement_and_path_escape() {
    let root = Root::new();
    let repo = common::repo_root();
    let command = fixture_command::write(&repo, &root.0, "provider", "exit 9", 0o700).unwrap();
    let shim = fs::read_link(&command).unwrap();
    let original = fs::read(&shim).unwrap();
    assert_eq!(
        fixture_command::write(&repo, &root.0, "provider", "exit 0", 0o600)
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs::read_to_string(fixture_command::body_path(&command)).unwrap(),
        "exit 9\n"
    );
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "child/command",
        "provider/",
    ] {
        assert_eq!(
            fixture_command::write(&repo, &root.0, name, "exit 0", 0o700)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput,
            "{name}"
        );
    }
    let retained = root.0.join("retained.body");
    fs::write(&retained, "retained data").unwrap();
    assert_eq!(
        fixture_command::write(&repo, &root.0, "retained", "exit 0", 0o700)
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read_to_string(retained).unwrap(), "retained data");
    assert_eq!(fs::read(shim).unwrap(), original);
    assert_eq!(Command::new(command).status().unwrap().code(), Some(9));
}

#[test]
fn provider_fixture_command_permission_failure_is_real() {
    let root = Root::new();
    let command =
        fixture_command::write(&common::repo_root(), &root.0, "denied", "exit 0", 0o600).unwrap();
    assert!(command.symlink_metadata().unwrap().file_type().is_file());
    assert_eq!(
        Command::new(command).spawn().unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}
