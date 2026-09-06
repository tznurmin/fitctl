// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::registry::CompletionValuesV1;

pub(super) const COMPLETION_SHELL_VALUES: &[&str] = &["bash", "zsh", "fish"];
pub(super) const COLOR_VALUES: &[&str] = &["auto", "always", "never"];
pub(super) const INSPECT_VIEW_VALUES: &[&str] = &["summary", "coverage", "matrix"];
pub(super) const VALIDATION_MODE_VALUES: &[&str] =
    &["contract_only", "state_advisory", "state_required"];
pub(super) const LEGACY_MODE_VALUES: &[&str] = &["contract_only", "state_aware"];
pub(super) const DRIFT_VIEW_VALUES: &[&str] = &["compact_json"];
pub(super) const EXPORT_TARGET_VALUES: &[&str] = &[
    "kubernetes_labels",
    "nomad_attributes",
    "gating_summary",
    "identity_summary",
];
pub(super) const CLASSIFY_EXPORT_VIEW_VALUES: &[&str] = &[
    "rows_csv",
    "contract_summary_csv",
    "service_profile_summary_csv",
];
pub(super) const REDACT_PROFILE_VALUES: &[&str] = &["local", "fleet", "auditor", "external"];
pub(super) const STATE_COLLECT_FEATURE_VALUES: &[&str] = &[
    "thermal",
    "memory-reliability",
    "gpu-reliability",
    "cuda-runtime",
    "hardware-sensors",
];

pub(super) const VALUE_COMPLETIONS: &[CompletionValuesV1] = &[
    CompletionValuesV1 {
        command: "completion",
        previous: "completion",
        values: COMPLETION_SHELL_VALUES,
    },
    CompletionValuesV1 {
        command: "inspect",
        previous: "--color",
        values: COLOR_VALUES,
    },
    CompletionValuesV1 {
        command: "inspect",
        previous: "--view",
        values: INSPECT_VIEW_VALUES,
    },
    CompletionValuesV1 {
        command: "validate",
        previous: "--validation-mode",
        values: VALIDATION_MODE_VALUES,
    },
    CompletionValuesV1 {
        command: "classify",
        previous: "--validation-mode",
        values: VALIDATION_MODE_VALUES,
    },
    CompletionValuesV1 {
        command: "validate",
        previous: "--mode",
        values: LEGACY_MODE_VALUES,
    },
    CompletionValuesV1 {
        command: "state",
        previous: "--collect",
        values: STATE_COLLECT_FEATURE_VALUES,
    },
    CompletionValuesV1 {
        command: "validate",
        previous: "--collect",
        values: STATE_COLLECT_FEATURE_VALUES,
    },
    CompletionValuesV1 {
        command: "diff",
        previous: "--drift-view",
        values: DRIFT_VIEW_VALUES,
    },
    CompletionValuesV1 {
        command: "export",
        previous: "--target",
        values: EXPORT_TARGET_VALUES,
    },
    CompletionValuesV1 {
        command: "classify",
        previous: "--export-view",
        values: CLASSIFY_EXPORT_VIEW_VALUES,
    },
    CompletionValuesV1 {
        command: "redact",
        previous: "--profile",
        values: REDACT_PROFILE_VALUES,
    },
];
