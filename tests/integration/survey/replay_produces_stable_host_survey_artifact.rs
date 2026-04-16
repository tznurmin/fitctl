// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::validation_v1::validate_host_survey;

#[test]
fn replay_produces_stable_host_survey_artifact() {
    let left = common::collect_survey_fixture("linux-bare-metal-like-v1");
    let right = common::collect_survey_fixture("linux-bare-metal-like-v1");

    assert_eq!(left, right);
    assert!(validate_host_survey(&left).is_ok());
}
