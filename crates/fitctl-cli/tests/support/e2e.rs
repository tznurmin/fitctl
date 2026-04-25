// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::de::DeserializeOwned;

use crate::cli;
use crate::common;

pub fn run_fitctl<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(cli::fitctl_bin())
        .current_dir(common::repo_root())
        .args(args)
        .output()
        .expect("fitctl should execute")
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn decode_json_stdout<T: DeserializeOwned>(output: &Output) -> T {
    serde_json::from_slice(&output.stdout).expect("fitctl should emit valid JSON")
}

pub fn write_stdout(path: &Path, output: &Output) {
    fs::write(path, &output.stdout).expect("fitctl stdout should be writable");
}

pub fn emit_survey_fixture(root: &Path, fixture_id: &str) -> PathBuf {
    let output = run_fitctl(["survey", "--fixture", fixture_id]);
    assert_success(&output);

    let path = root.join(format!("{fixture_id}.survey.json"));
    write_stdout(&path, &output);
    path
}

pub fn emit_state_fixture(root: &Path, fixture_id: &str) -> PathBuf {
    let output = run_fitctl(["state", "--fixture", fixture_id]);
    assert_success(&output);

    let path = root.join(format!("{fixture_id}.state.json"));
    write_stdout(&path, &output);
    path
}

pub fn derive_contract(root: &Path, survey_path: &Path, policy_file_name: &str) -> PathBuf {
    let output = run_fitctl([
        "contract",
        "--survey",
        survey_path
            .to_str()
            .expect("survey path should be valid UTF-8"),
        "--policy",
        common::repo_policy_file_path(policy_file_name)
            .to_str()
            .expect("policy path should be valid UTF-8"),
        "--derived-at",
        common::FIXED_TIMESTAMP,
    ]);
    assert_success(&output);

    let survey_stem = survey_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("survey");
    let path = root.join(format!("{survey_stem}.{policy_file_name}.contract.json"));
    write_stdout(&path, &output);
    path
}

pub fn emit_config_bundle(
    root: &Path,
    policy_file_name: &str,
    service_profile_file_name: Option<&str>,
) -> PathBuf {
    let mut args = vec![
        "bundle-config".to_string(),
        "--policy".to_string(),
        common::repo_policy_file_path(policy_file_name)
            .to_str()
            .expect("policy path should be valid UTF-8")
            .to_string(),
    ];
    if let Some(file_name) = service_profile_file_name {
        args.push("--profile".to_string());
        args.push(
            common::repo_service_profile_path(file_name)
                .to_str()
                .expect("service-profile path should be valid UTF-8")
                .to_string(),
        );
    }
    args.push("--bundled-at".to_string());
    args.push(common::FIXED_TIMESTAMP.to_string());

    let output = run_fitctl(args);
    assert_success(&output);

    let stem = service_profile_file_name.unwrap_or("policy-only");
    let path = root.join(format!("{policy_file_name}.{stem}.config-bundle.json"));
    write_stdout(&path, &output);
    path
}

pub fn sign_artifact(root: &Path, input_path: &Path, key_path: &Path, file_stem: &str) -> PathBuf {
    let output = run_fitctl([
        "sign",
        "--key",
        key_path.to_str().expect("key path should be valid UTF-8"),
        "--input",
        input_path
            .to_str()
            .expect("artifact path should be valid UTF-8"),
    ]);
    assert_success(&output);

    let path = root.join(format!("{file_stem}.signed.json"));
    write_stdout(&path, &output);
    path
}
