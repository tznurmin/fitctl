// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn dependency_paths(dependencies: &Path, host: &str) -> Vec<PathBuf> {
    assert_eq!(dependencies.file_name(), Some(OsStr::new("deps")));
    let profile = dependencies.parent().unwrap();
    let root_or_target = profile.parent().unwrap();
    let mut paths = vec![dependencies.to_owned()];
    // Explicit native targets separate host procedural macros from target libraries.
    if root_or_target.file_name() == Some(OsStr::new(host)) {
        paths.push(
            root_or_target
                .parent()
                .unwrap()
                .join(profile.file_name().unwrap())
                .join("deps"),
        );
    }
    paths
}

fn is_missing_hardware_field(stderr: &[u8]) -> bool {
    let mut found = false;
    for line in String::from_utf8_lossy(stderr).lines() {
        let Ok(diagnostic) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        if diagnostic["level"] != "error" {
            continue;
        }
        if diagnostic["code"].is_null()
            && diagnostic["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("aborting due to "))
        {
            continue;
        }
        if diagnostic["code"]["code"] != "E0063"
            || !diagnostic["message"]
                .as_str()
                .is_some_and(|message| message.contains("hardware_sensor_resources"))
        {
            return false;
        }
        found = true;
    }
    found
}

#[test]
pub(crate) fn hardware_sensor_public_rust_addition_requires_next_minor_not_patch_release() {
    let root = Root(common::unique_temp_dir("hardware-sensor-rust-client"));
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(&compiler).arg("-vV").output().unwrap();
    assert!(
        version.status.success(),
        "rustc context unavailable: {version:?}"
    );
    let version = String::from_utf8(version.stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc must report the native host triple");
    let dependencies = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let search_paths = dependency_paths(&dependencies, host);
    for path in &search_paths {
        assert!(
            path.is_dir(),
            "missing compiler dependency directory: {path:?}"
        );
    }
    let clients = common::repo_root().join("crates/fitctl-core/tests/fixtures/rust_clients");
    let mut libraries: Vec<_> = fs::read_dir(&dependencies)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libfitctl_core-")
                && path.extension().is_some_and(|v| v == "rlib")
        })
        .collect();
    libraries.sort();
    assert!(
        !libraries.is_empty(),
        "no fitctl_core rlib in {dependencies:?}"
    );
    let mut evidence = Vec::new();
    for library in libraries {
        let compile = |client: &str| {
            let mut command = Command::new(&compiler);
            command
                .args([
                    "--edition=2021",
                    "--crate-type=lib",
                    "--emit=metadata",
                    "--error-format=json",
                    "--target",
                    host,
                ])
                .arg(clients.join(client))
                .arg("--out-dir")
                .arg(&root.0)
                .arg("--extern")
                .arg(format!("fitctl_core={}", library.display()));
            for path in &search_paths {
                command
                    .arg("-L")
                    .arg(format!("dependency={}", path.display()));
            }
            command.output().unwrap()
        };
        let positive = compile("host_state_core_current.rs");
        if !positive.status.success() {
            evidence.push(format!(
                "current client: {}",
                String::from_utf8_lossy(&positive.stderr)
            ));
            continue;
        }
        let negative = compile("host_state_core_0_6.rs");
        evidence.push(String::from_utf8_lossy(&negative.stderr).into_owned());
        if !negative.status.success() && is_missing_hardware_field(&negative.stderr) {
            let mut version =
                fitctl_core::artifacts::envelope_v1::LOCAL_FITCTL_VERSION_V1.split('.');
            let major = version.next().unwrap().parse::<u64>().unwrap();
            let minor = version.next().unwrap().parse::<u64>().unwrap();
            assert!(
                (major, minor) >= (0, 7),
                "the struct addition is not a 0.6.x patch"
            );
            return;
        }
    }
    panic!("expected the precise exhaustive struct compatibility break, not an unrelated compiler error: {evidence:?}");
}

#[test]
fn hardware_sensor_compiler_context_covers_native_and_explicit_target_profiles() {
    let host = "x86_64-unknown-linux-gnu";
    for profile in ["debug", "release", "custom-profile"] {
        let root = Path::new("owned-cache");
        let ordinary = root.join(profile).join("deps");
        assert_eq!(dependency_paths(&ordinary, host), vec![ordinary.clone()]);
        let explicit = root.join(host).join(profile).join("deps");
        assert_eq!(dependency_paths(&explicit, host), vec![explicit, ordinary]);
    }
}

#[test]
#[should_panic(expected = "assertion")]
fn hardware_sensor_compiler_context_rejects_unrecognized_dependency_layout() {
    dependency_paths(
        Path::new("cache/debug/relocated"),
        "x86_64-unknown-linux-gnu",
    );
}

#[test]
fn hardware_sensor_compatibility_does_not_accept_unrelated_compiler_errors() {
    let missing = serde_json::json!({"level": "error", "code": {"code": "E0063"},
        "message": "missing field `hardware_sensor_resources`"})
    .to_string();
    let unrelated = serde_json::json!({"level": "error", "code": {"code": "E0463"},
        "message": "cannot find crate fitctl_core"})
    .to_string();
    assert!(is_missing_hardware_field(missing.as_bytes()));
    assert!(!is_missing_hardware_field(unrelated.as_bytes()));
    assert!(!is_missing_hardware_field(
        format!("{missing}\n{unrelated}").as_bytes()
    ));
    let uncoded = serde_json::json!({"level": "error", "code": null,
        "message": "extern location for fitctl_core does not exist"})
    .to_string();
    assert!(!is_missing_hardware_field(
        format!("{missing}\n{uncoded}").as_bytes()
    ));
    assert!(!is_missing_hardware_field(b"not compiler JSON"));
}
