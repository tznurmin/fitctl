// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::hardware_sensor_support::Fixture;
use serde_json::Value;
use std::{
    fs,
    time::{Duration, Instant},
};

fn combined(f: &Fixture) -> Value {
    f.script("nvidia-smi", "exit 0");
    let out = f
        .command()
        .args([
            "state",
            "--live",
            "--collect",
            "thermal",
            "--collect",
            "hardware-sensors",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
pub(crate) fn hardware_sensor_capture_permission_and_overflow_are_explicit() {
    for (body, mode, outcome, reason, thermal_reason) in [
        (
            "exit 0",
            0o600,
            "permission_denied",
            "hardware_sensor_permission_denied",
            "thermal_provider_permission_denied",
        ),
        (
            "printf '%1048577s' ''",
            0o700,
            "malformed",
            "hardware_sensor_output_limit",
            "thermal_provider_output_too_large",
        ),
    ] {
        let f = Fixture::new();
        f.script_with_mode("sensors", body, mode);
        let state = combined(&f);
        let core = &state["state"]["core_state"];
        let hardware = &core["hardware_sensor_resources"];
        assert_eq!(hardware["providers"][0]["outcome"], outcome);
        assert_eq!(hardware["providers"][0]["reason_code"], reason);
        assert_eq!(hardware["readings"], serde_json::json!([]));
        assert_eq!(
            core["thermal_resources"]["providers"][0]["error_code"],
            thermal_reason
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_capture_drains_both_pipes_without_truncating_valid_json() {
    let f = Fixture::new();
    f.script("sensors", "printf '%262144s' '' >&2\nprintf '%262144s' ''\nprintf '%s' '{\"chip\":{\"power\":{\"power1_input\":3}}}'");
    let state = combined(&f);
    let hardware = &state["state"]["core_state"]["hardware_sensor_resources"];
    assert_eq!(hardware["providers"][0]["outcome"], "success");
    assert_eq!(hardware["readings"][0]["value"], 3_000_000);
}

#[test]
pub(crate) fn hardware_sensor_capture_timeout_is_shared_and_reaps_owned_child() {
    let f = Fixture::new();
    let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|p| p.join("sleep"))
        .find(|p| p.is_file())
        .expect("test sleep executable");
    f.script(
        "sensors",
        &format!(
            "echo sample >> \"$SENSOR_COUNT\"\nprintf '%s' $$ > '{}'/pid\nexec '{}' 10",
            f.0.display(),
            sleep.display()
        ),
    );
    let started = Instant::now();
    let state = combined(&f);
    assert!(started.elapsed() < Duration::from_secs(9));
    let core = &state["state"]["core_state"];
    assert_eq!(
        core["hardware_sensor_resources"]["providers"][0]["reason_code"],
        "hardware_sensor_timeout"
    );
    assert_eq!(
        core["thermal_resources"]["providers"][0]["error_code"],
        "thermal_provider_command_timeout"
    );
    assert_eq!(
        fs::read_to_string(f.0.join("count"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    let pid: u32 = fs::read_to_string(f.0.join("pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "owned provider must be reaped"
    );
}
