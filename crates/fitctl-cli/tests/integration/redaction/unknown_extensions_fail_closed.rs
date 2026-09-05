// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};
use std::fs;

use crate::{common, e2e};

#[test]
fn unknown_extension_rejects_external_cli_output() {
    let root = common::unique_temp_dir("unknown-extension-redaction");
    let source = common::repo_root()
        .join("fixtures/conformance/valid/host-survey.local-stable-identity-v2.v2.json");
    let mut artifact: Value =
        serde_json::from_str(&fs::read_to_string(source).expect("survey fixture should read"))
            .expect("survey fixture should decode");
    artifact["survey"]["extension_evidence"]["example.site.runtime"] = json!({
        "host": "sensitive-host",
        "configuration_path": "/sensitive/site/runtime.json"
    });
    let input = root.join("survey.json");
    common::write_json_file(&input, &artifact);

    let output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        input.to_str().expect("input path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "failed redaction must emit no artifact"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extension_redactor_unavailable"),
        "{stderr}"
    );
    assert!(stderr.contains("example.site.runtime"), "{stderr}");
}

#[test]
fn unknown_contract_extension_basis_rejects_without_partial_output() {
    let root = common::unique_temp_dir("unknown-extension-basis-redaction");
    let source = common::repo_root()
        .join("fixtures/conformance/valid/host-contract.cuda-default-view-version-split.v2.json");
    let mut artifact: Value =
        serde_json::from_str(&fs::read_to_string(source).expect("contract fixture should read"))
            .expect("contract fixture should decode");
    artifact["contract_basis"]["extension_basis"]["enabled_extension_namespaces"]
        .as_array_mut()
        .expect("enabled namespaces should be an array")
        .push(Value::String("com.example.private.runtime".to_string()));
    artifact["contract_basis"]["extension_basis"]["extension_semantic_hashes"]
        ["com.example.private.runtime"] = Value::String(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
    );
    let input = root.join("contract.json");
    common::write_json_file(&input, &artifact);

    let output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        input.to_str().expect("input path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "failure must emit no artifact");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extension_redactor_unavailable"),
        "{stderr}"
    );
    assert!(stderr.contains("com.example.private.runtime"), "{stderr}");
}
