// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fitctl_core::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1, HostStateThermalResourcesV1,
    ThermalCollectionPathV1, ThermalEvidenceTargetKindV1, ThermalProviderKindV1,
    ThermalProviderOutcomeV1,
};
use fitctl_core::state::thermal_v1::{collect_thermal_resources_v1, ThermalProviderConfigEntryV1};

use crate::common;

const READING: &str = "GPU-fixture, Fixture GPU, 42\n";

#[test]
fn thermal_provider_fixture_body_writer_does_not_block_execution() {
    let fixture = ProviderFixture::new(&format!("printf '{READING}'\n"));
    // Reproduce a writable descriptor surviving in a concurrently spawned test process.
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(fixture.body_path())
        .expect("retain fixture body writer");
    let resources = fixture.collect(3);
    drop(writer);
    assert_eq!(
        resources.providers[0].outcome,
        ThermalProviderOutcomeV1::Success,
        "{:?}",
        resources.providers[0]
    );
    assert_eq!(resources.readings.len(), 1);
}

#[test]
fn thermal_provider_fixture_plain_stdout_is_accepted() {
    assert_large_success("");
}

#[test]
fn thermal_provider_large_stdout_does_not_deadlock() {
    assert_large_success("printf '%262144s' ''\n");
}

#[test]
fn thermal_provider_exact_stdout_limit_is_accepted() {
    assert_large_success(&format!("printf '%{}s' ''\n", 1_048_576 - READING.len()));
}

#[test]
fn thermal_provider_large_stderr_does_not_deadlock() {
    assert_large_success("printf '%262144s' '' >&2\n");
}

#[test]
fn thermal_provider_both_large_streams_do_not_deadlock() {
    assert_large_success(concat!(
        "printf '%262144s' ''\n",
        "printf '%262144s' '' >&2\n",
    ));
}

#[test]
fn thermal_provider_overflow_is_not_a_timeout_or_truncated_success() {
    let fixture = ProviderFixture::new(&format!("printf '%1048577s' ''\nprintf '{READING}'\n"));
    let resources = fixture.collect(3);
    let provider = &resources.providers[0];
    assert_eq!(provider.outcome, ThermalProviderOutcomeV1::Malformed);
    assert_eq!(
        provider.error_code.as_deref(),
        Some("thermal_provider_output_too_large")
    );
    assert!(resources.readings.is_empty());
}

#[test]
fn thermal_provider_large_failure_keeps_exit_status_and_bounded_diagnostics() {
    let fixture = ProviderFixture::new(concat!(
        "printf 'stdout-prefix'\nprintf '%262144s' ''\n",
        "printf 'stderr-prefix' >&2\nprintf '%262144s' '' >&2\nexit 9\n",
    ));
    let resources = fixture.collect(3);
    let provider = &resources.providers[0];
    assert_eq!(provider.outcome, ThermalProviderOutcomeV1::CommandFailed);
    assert_eq!(
        provider.error_code.as_deref(),
        Some("thermal_provider_command_failed")
    );
    let diagnostics = provider
        .diagnostics
        .as_deref()
        .expect("failure diagnostics");
    assert!(diagnostics.contains("exit status: 9"), "{diagnostics}");
    assert!(diagnostics.contains("stderr-prefix"), "{diagnostics}");
    assert!(diagnostics.contains("stdout-prefix"), "{diagnostics}");
    assert!(diagnostics.len() <= 240);
    assert!(resources.readings.is_empty());
}

#[test]
fn thermal_provider_timeout_reaps_direct_child() {
    let fixture = ProviderFixture::new("printf '%s' $$ > \"$1\"\nexec sleep 10\n");
    let started = Instant::now();
    let resources = fixture.collect(1);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(
        resources.providers[0].error_code.as_deref(),
        Some("thermal_provider_command_timeout")
    );
    assert!(resources.readings.is_empty());
    let pid: libc::pid_t = fs::read_to_string(fixture.root.join("pid"))
        .expect("provider PID")
        .parse()
        .expect("numeric PID");
    // The collector must already have waited on this exact direct child, not leave a zombie.
    assert_eq!(
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn thermal_provider_inherited_pipe_respects_collection_deadline() {
    let fixture = ProviderFixture::new(&format!("sleep 3 &\nprintf '{READING}'\nexit 0\n"));
    let started = Instant::now();
    let resources = fixture.collect(1);
    let elapsed = started.elapsed();
    // This helper has a finite lifetime even on the old broken runner. Let it finish before
    // assertions so a failing red test does not leave a live fixture process behind.
    std::thread::sleep(Duration::from_secs(4).saturating_sub(started.elapsed()));
    assert!(
        elapsed < Duration::from_millis(2500),
        "collection took {elapsed:?}"
    );
    assert_eq!(
        resources.providers[0].error_code.as_deref(),
        Some("thermal_provider_command_timeout")
    );
    assert!(resources.readings.is_empty());
}

fn assert_large_success(body: &str) {
    let fixture = ProviderFixture::new(&format!("{body}printf '{READING}'\n"));
    let resources = fixture.collect(3);
    assert_eq!(
        resources.providers[0].outcome,
        ThermalProviderOutcomeV1::Success,
        "{:?}",
        resources.providers[0]
    );
    assert_eq!(resources.readings.len(), 1);
    assert_eq!(
        resources.readings[0].temperature_millidegrees_celsius,
        42_000
    );
}

struct ProviderFixture {
    root: PathBuf,
}

impl ProviderFixture {
    fn body_path(&self) -> PathBuf {
        common::fixture_command::body_path(&self.root.join("provider"))
    }

    fn new(body: &str) -> Self {
        let root = common::unique_temp_dir("thermal-provider-process");
        common::fixture_command::write(&common::repo_root(), &root, "provider", body, 0o700)
            .expect("create provider fixture");
        Self { root }
    }

    fn collect(&self, timeout_seconds: u64) -> HostStateThermalResourcesV1 {
        let provider = ThermalProviderConfigEntryV1 {
            provider_id: "process-fixture".to_string(),
            provider_kind: ThermalProviderKindV1::NvidiaSmiQuery,
            command: vec![
                self.root.join("provider").display().to_string(),
                self.root.join("pid").display().to_string(),
            ],
            timeout_seconds: Some(timeout_seconds),
            evidence_target: HostStateThermalEvidenceTargetV1 {
                target_kind: ThermalEvidenceTargetKindV1::CurrentHost,
                host_id: None,
                collection_path: ThermalCollectionPathV1::LocalProcess,
            },
            sensor_mappings: Vec::new(),
        };
        collect_thermal_resources_v1(
            &[provider],
            common::FIXED_TIMESTAMP,
            HostStateThermalCollectorHostV1 {
                host_alias: None,
                local_stable_id: None,
            },
        )
        .expect("provider results")
    }
}

impl Drop for ProviderFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
