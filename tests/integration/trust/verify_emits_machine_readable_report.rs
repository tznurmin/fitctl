// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use crate::common;
use serde_json::Value;
use std::process::Command;

#[test]
fn verify_emits_machine_readable_report() {
    let fitctl_bin = cli::ensure_fitctl_built();
    let temp_dir = common::unique_temp_dir("integration-verify");
    let key_path = common::generate_ed25519_keypair(&temp_dir, "trusted-signer");
    let signed = common::sign_survey_fixture("linux-bare-metal-like-v1", &key_path);
    let key_id = signed.envelope().signatures[0].key_id.clone();
    let policy = common::trust_policy_for_signer(&key_id);

    let artifact_path = temp_dir.join("signed-survey.json");
    let policy_path = temp_dir.join("trust-policy.json");
    common::write_json_file(&artifact_path, &signed);
    common::write_json_file(&policy_path, &policy);

    let output = Command::new(&fitctl_bin)
        .args([
            "verify",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid UTF-8"),
            "--policy",
            policy_path
                .to_str()
                .expect("policy path should be valid UTF-8"),
        ])
        .output()
        .expect("fitctl verify should execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value =
        serde_json::from_slice(&output.stdout).expect("verify command should emit JSON");
    assert_eq!(report["schema_id"], "fitctl.verify.report.v1");
    assert_eq!(report["outcome"], "verified_and_trusted");
    assert_eq!(report["accepted_by_policy"], true);
    assert_eq!(report["artifact_schema_id"], "host-survey.v2");
}
