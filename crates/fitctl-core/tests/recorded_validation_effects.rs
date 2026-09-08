// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

#[path = "support/recorded_validation_cases.rs"]
mod cases;
#[path = "support/common.rs"]
mod common;
#[path = "support/thread_effect_guard.rs"]
mod guard;

#[test]
fn effect_guard_controls() {
    let modes = ["noop", "entropy", "file", "socket", "exec", "random-state"];
    let selected = guard::selected_mode();
    assert!(selected.as_deref().is_none_or(|mode| modes.contains(&mode)));
    for mode in modes {
        if selected.as_deref().is_some_and(|value| value != mode) {
            continue;
        }
        let status = guard::exercise("effect_guard_controls", mode, move || match mode {
            "noop" => {}
            "random-state" => {
                std::hint::black_box(std::collections::HashSet::<u8>::new());
            }
            "entropy" => {
                let mut byte = 0_u8;
                unsafe {
                    libc::syscall(libc::SYS_getrandom, &mut byte, 1_usize, 0);
                }
            }
            "file" => unsafe {
                libc::syscall(libc::SYS_openat, libc::AT_FDCWD, c"".as_ptr(), 0);
            },
            "socket" => unsafe {
                libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
            },
            "exec" => unsafe {
                libc::syscall(
                    libc::SYS_execve,
                    std::ptr::null::<libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                    std::ptr::null::<*const libc::c_char>(),
                );
            },
            _ => unreachable!(),
        });
        if mode == "noop" {
            assert!(status.success(), "guarded no-op: {status}");
        } else {
            guard::expect_trap(status);
        }
    }
}

#[test]
fn core_envelope_thread_effects() {
    let cases = cases::signature_cases(false);
    cases::check(&cases);
    let status = guard::exercise("core_envelope_thread_effects", "core", move || {
        cases::check(&cases)
    });
    assert!(
        status.success(),
        "core envelope call acquired an external effect or failed: {status}"
    );
}

#[test]
fn auxiliary_envelope_thread_effects() {
    let cases = cases::signature_cases(true);
    cases::check(&cases);
    let status = guard::exercise(
        "auxiliary_envelope_thread_effects",
        "auxiliary",
        move || cases::check(&cases),
    );
    assert!(
        status.success(),
        "auxiliary call acquired an external effect or failed: {status}"
    );
}

#[test]
fn collector_thread_effects() {
    let cases = cases::collector_cases();
    cases::check(&cases);
    let status = guard::exercise("collector_thread_effects", "collectors", move || {
        cases::check(&cases)
    });
    assert!(
        status.success(),
        "collector call acquired an external effect or failed: {status}"
    );
}

#[test]
fn recorded_decision_thread_effects() {
    let cases = cases::decision_cases();
    let status = guard::exercise("recorded_decision_thread_effects", "decisions", move || {
        for _ in 0..4 {
            for (request, expected) in &cases {
                let report = fitctl_core::validate::validate_request_v1(request.clone()).unwrap();
                assert_eq!(&report, expected);
                let actual =
                    fitctl_core::artifacts::record_v1::ArtifactRecordV1::ValidationReport(report);
                let expected =
                    fitctl_core::artifacts::record_v1::ArtifactRecordV1::ValidationReport(
                        expected.clone(),
                    );
                assert_eq!(
                    actual.full_artifact_json().unwrap(),
                    expected.full_artifact_json().unwrap()
                );
                assert_eq!(
                    actual.semantic_bytes().unwrap(),
                    expected.semantic_bytes().unwrap()
                );
                assert_eq!(
                    actual.semantic_hash_hex().unwrap(),
                    expected.semantic_hash_hex().unwrap()
                );
            }
        }
    });
    assert!(
        status.success(),
        "recorded call acquired an external effect or failed: {status}"
    );
}
