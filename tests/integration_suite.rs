// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/cli.rs"]
mod cli;
#[path = "support/common.rs"]
mod common;
#[path = "support/e2e.rs"]
mod e2e;

#[path = "integration/e2e/classification/batch_classification_proves_profile_matrix_use_case.rs"]
mod batch_classification_proves_profile_matrix_use_case;
#[path = "integration/e2e/deployment_gating/contract_only_gate_drives_machine_decision.rs"]
mod contract_only_gate_drives_machine_decision;
#[path = "integration/contract/derivation_uses_survey_and_policy_only.rs"]
mod derivation_uses_survey_and_policy_only;
#[path = "integration/redaction/external_profile_redacts_sensitive_fields.rs"]
mod external_profile_redacts_sensitive_fields;
#[path = "integration/e2e/preflight/local_preflight_reports_go_no_go_without_scraping_prose.rs"]
mod local_preflight_reports_go_no_go_without_scraping_prose;
#[path = "integration/extensions/python_runtime_end_to_end.rs"]
mod python_runtime_end_to_end;
#[path = "integration/inspect/renders_host_survey_summary.rs"]
mod renders_host_survey_summary;
#[path = "integration/state/replay_produces_stable_host_state_artifact.rs"]
mod replay_produces_stable_host_state_artifact;
#[path = "integration/survey/replay_produces_stable_host_survey_artifact.rs"]
mod replay_produces_stable_host_survey_artifact;
#[path = "integration/artifacts/ring_split_uses_core_and_extension_sections.rs"]
mod ring_split_uses_core_and_extension_sections;
#[path = "integration/e2e/deployment_gating/state_required_gate_respects_freshness_and_drives_machine_decision.rs"]
mod state_required_gate_respects_freshness_and_drives_machine_decision;
#[path = "integration/validation/contract_only/uses_contract_and_service_profile_only.rs"]
mod uses_contract_and_service_profile_only;
#[path = "integration/e2e/deployment_gating/verified_gate_requires_trust_success_before_decision.rs"]
mod verified_gate_requires_trust_success_before_decision;
#[path = "integration/trust/verify_emits_machine_readable_report.rs"]
mod verify_emits_machine_readable_report;
