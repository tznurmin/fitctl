// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn storage_profile_init_emits_valid_service_profile() {
    let root = common::unique_temp_dir("storage-profile-init-valid");
    let scratch = root.join("scratch");
    std::fs::create_dir_all(&scratch).expect("scratch path should be created");

    let output = e2e::run_fitctl([
        "storage",
        "profile",
        "init",
        "--path",
        &format!(
            "scratch={}",
            scratch.to_str().expect("scratch path should be UTF-8")
        ),
        "--profile-id",
        "generated-storage-profile-test-v1",
        "--display-name",
        "Generated storage profile test",
        "--short-display-name",
        "Generated storage",
    ]);
    e2e::assert_success(&output);
    let profile: Value = e2e::decode_json_stdout(&output);
    assert_eq!(profile["envelope"]["schema_id"], "service-profile.v2");
    assert_eq!(
        profile["profile"]["profile_id"],
        "generated-storage-profile-test-v1"
    );
    assert_eq!(
        profile["profile"]["core_requirements"]["required_paths"][0]["path_id"],
        "scratch"
    );
    let core_requirements = profile["profile"]["core_requirements"]
        .as_object()
        .expect("core requirements should encode as an object");
    assert!(
        !core_requirements.contains_key("min_allocatable_cpu_logical_cores"),
        "generated profile should omit absent optional requirements instead of serializing null"
    );
}

#[test]
fn storage_profile_init_writes_out_file() {
    let root = common::unique_temp_dir("storage-profile-init-out");
    let scratch = root.join("scratch");
    let out = root.join("profile.json");
    std::fs::create_dir_all(&scratch).expect("scratch path should be created");

    let output = e2e::run_fitctl([
        "storage",
        "profile",
        "init",
        "--path",
        &format!(
            "scratch={}",
            scratch.to_str().expect("scratch path should be UTF-8")
        ),
        "--out",
        out.to_str().expect("out path should be UTF-8"),
    ]);
    e2e::assert_success(&output);
    assert!(out.is_file(), "profile output file should exist");
    let profile: Value = serde_json::from_slice(&std::fs::read(&out).expect("profile should read"))
        .expect("profile should decode");
    assert_eq!(profile["envelope"]["schema_id"], "service-profile.v2");
}

#[test]
fn storage_profile_init_rejects_duplicate_path_id() {
    let root = common::unique_temp_dir("storage-profile-init-duplicate");
    let scratch = root.join("scratch");
    let other = root.join("other");
    std::fs::create_dir_all(&scratch).expect("scratch path should be created");
    std::fs::create_dir_all(&other).expect("other path should be created");

    let output = e2e::run_fitctl([
        "storage",
        "profile",
        "init",
        "--path",
        &format!(
            "scratch={}",
            scratch.to_str().expect("scratch path should be UTF-8")
        ),
        "--path",
        &format!(
            "scratch={}",
            other.to_str().expect("other path should be UTF-8")
        ),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate path id"));
}

#[test]
fn storage_profile_init_rejects_unknown_pair_path_id() {
    let root = common::unique_temp_dir("storage-profile-init-pair-invalid");
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).expect("cache path should be created");

    let output = e2e::run_fitctl([
        "storage",
        "profile",
        "init",
        "--path",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--probe-path-link-pair",
        "cache:workspace",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--probe-path-link-pair"));
    assert!(stderr.contains("workspace"));
}
