// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

pub(super) struct CompletionOptionsV1 {
    pub(super) command: &'static str,
    pub(super) options: &'static [&'static str],
}

pub(super) struct CompletionValuesV1 {
    pub(super) command: &'static str,
    pub(super) previous: &'static str,
    pub(super) values: &'static [&'static str],
}

pub(super) const SURVEY_OPTIONS: &[&str] = &[
    "--live",
    "--fixture",
    "--fixtures-root",
    "--extension-pack",
    "--invocation-context",
    "--enable-extension",
    "--cuda-environment-catalogue",
    "--cuda-environment-id",
    "--cuda-selected-environment-input",
    "--help",
    "-h",
];
pub(super) const CONTRACT_OPTIONS: &[&str] = &[
    "--survey",
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--config-bundle",
    "--extension-pack",
    "--invocation-context",
    "--enable-extension",
    "--derived-at",
    "--note",
    "--help",
    "-h",
];
pub(super) const CLASSIFY_OPTIONS: &[&str] = &[
    "--contract",
    "--state",
    "--profile",
    "--service-profile-catalogue",
    "--profile-id",
    "--invocation-context",
    "--validation-mode",
    "--max-state-age",
    "--validated-at",
    "--export-view",
    "--help",
    "-h",
];
pub(super) const BUNDLE_OPTIONS: &[&str] = &[
    "--validation-report",
    "--contract",
    "--state",
    "--resolved-config",
    "--config-bundle",
    "--verification-bundle",
    "--recommendation-report",
    "--bundled-at",
    "--note",
    "--help",
    "-h",
];
pub(super) const BUNDLE_CONFIG_OPTIONS: &[&str] = &[
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--profile",
    "--profile-id",
    "--service-profile-catalogue",
    "--trust-policy",
    "--extension-pack",
    "--recommendation-pack",
    "--invocation-context",
    "--bundled-at",
    "--note",
    "--help",
    "-h",
];
pub(super) const STATE_OPTIONS: &[&str] = &[
    "--live",
    "--fixture",
    "--fixtures-root",
    "--collect",
    "--path-check",
    "--probe-path-links",
    "--probe-path-link-pair",
    "--probe-path-health",
    "--thermal-provider-config",
    "--extension-pack",
    "--invocation-context",
    "--enable-extension",
    "--cuda-environment-catalogue",
    "--cuda-environment-id",
    "--cuda-selected-environment-input",
    "--help",
    "-h",
];
pub(super) const VALIDATE_OPTIONS: &[&str] = &[
    "--contract",
    "--survey",
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--config-bundle",
    "--profile",
    "--service-profile-catalogue",
    "--profile-id",
    "--invocation-context",
    "--validation-mode",
    "--mode",
    "--state",
    "--thermal-evidence",
    "--live-state",
    "--collect",
    "--path-check",
    "--probe-path-links",
    "--probe-path-link-pair",
    "--probe-path-health",
    "--thermal-provider-config",
    "--extension-pack",
    "--enable-extension",
    "--state-out",
    "--validation-out",
    "--max-state-age",
    "--validated-at",
    "--note",
    "--fail-on-unfit",
    "--require-fit",
    "--help",
    "-h",
];
pub(super) const DIFF_OPTIONS: &[&str] = &["--left", "--right", "--drift-view", "--help", "-h"];
pub(super) const EXPORT_OPTIONS: &[&str] = &[
    "--target",
    "--input",
    "--trust-domain",
    "--pseudonym-secret",
    "--help",
    "-h",
];
pub(super) const REDACT_OPTIONS: &[&str] = &["--profile", "--input", "--help", "-h"];
pub(super) const SIGN_OPTIONS: &[&str] = &["--key", "--input", "--help", "-h"];
pub(super) const VERIFY_OPTIONS: &[&str] = &[
    "--input",
    "--policy",
    "--trust-evidence",
    "--bundle-out",
    "--help",
    "-h",
];
pub(super) const COMPLETION_OPTIONS: &[&str] = &["--help", "-h"];
pub(super) const CONFIG_OPTIONS: &[&str] = &[];
pub(super) const CONFIG_ROOT_COMPLETIONS: &[&str] = &["list", "export", "--help", "-h"];
pub(super) const CONFIG_LIST_OPTIONS: &[&str] = &["--help", "-h"];
pub(super) const CONFIG_EXPORT_OPTIONS: &[&str] = &["--out-dir", "--help", "-h"];
pub(super) const STORAGE_OPTIONS: &[&str] = &[];
pub(super) const STORAGE_ROOT_COMPLETIONS: &[&str] = &["profile", "--help", "-h"];
pub(super) const STORAGE_PROFILE_COMPLETIONS: &[&str] = &["init", "--help", "-h"];
pub(super) const STORAGE_PROFILE_INIT_OPTIONS: &[&str] = &[
    "--path",
    "--probe-path-links",
    "--probe-path-link-pair",
    "--min-available-bytes",
    "--profile-id",
    "--display-name",
    "--short-display-name",
    "--primary-capability-class",
    "--out",
    "--help",
    "-h",
];
pub(super) const THERMAL_OPTIONS: &[&str] = &[];
pub(super) const THERMAL_ROOT_COMPLETIONS: &[&str] = &["collect", "profile", "--help", "-h"];
pub(super) const THERMAL_COLLECT_OPTIONS: &[&str] = &[
    "--thermal-provider-config",
    "--require-target-host-id",
    "--out",
    "--help",
    "-h",
];
pub(super) const THERMAL_PROFILE_COMPLETIONS: &[&str] = &["init", "--help", "-h"];
pub(super) const THERMAL_PROFILE_INIT_OPTIONS: &[&str] = &[
    "--state",
    "--thermal-evidence",
    "--profile-id",
    "--display-name",
    "--short-display-name",
    "--primary-capability-class",
    "--margin-mc",
    "--out",
    "--help",
    "-h",
];
pub(super) const INSPECT_OPTIONS: &[&str] = &[
    "--input",
    "--verbose",
    "--show-identifiers",
    "--color",
    "--view",
    "--matrix",
    "--help",
    "-h",
];
pub(super) const INSPECT_CONFIG_OPTIONS: &[&str] = &[
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--service-profile-catalogue",
    "--profile-id",
    "--trust-policy",
    "--extension-pack",
    "--recommendation-pack",
    "--invocation-context",
    "--help",
    "-h",
];
pub(super) const LOCK_POLICY_PACK_OPTIONS: &[&str] = &[
    "--policy-pack",
    "--policy-id",
    "--key",
    "--signed-at",
    "--help",
    "-h",
];
pub(super) const RECOMMEND_OPTIONS: &[&str] = &[
    "--validation-report",
    "--recommendation-pack",
    "--recommendation-pack-id",
    "--invocation-context",
    "--recommended-at",
    "--help",
    "-h",
];

pub(super) const COMMAND_OPTIONS: &[CompletionOptionsV1] = &[
    CompletionOptionsV1 {
        command: "survey",
        options: SURVEY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "contract",
        options: CONTRACT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "classify",
        options: CLASSIFY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "bundle",
        options: BUNDLE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "bundle-config",
        options: BUNDLE_CONFIG_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "state",
        options: STATE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "validate",
        options: VALIDATE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "diff",
        options: DIFF_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "export",
        options: EXPORT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "redact",
        options: REDACT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "sign",
        options: SIGN_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "verify",
        options: VERIFY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "completion",
        options: COMPLETION_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "config",
        options: CONFIG_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "storage",
        options: STORAGE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "thermal",
        options: THERMAL_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "inspect",
        options: INSPECT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "inspect-config",
        options: INSPECT_CONFIG_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "lock-policy-pack",
        options: LOCK_POLICY_PACK_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "recommend",
        options: RECOMMEND_OPTIONS,
    },
];
