// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/cli.rs"]
mod cli;
#[path = "support/common.rs"]
mod common;
#[path = "support/e2e.rs"]
mod e2e;

#[path = "integration/inspect/batch_classification_matrix_view_renders_verdict_grid.rs"]
mod batch_classification_matrix_view_renders_verdict_grid;
#[path = "integration/e2e/classification/batch_classification_proves_profile_matrix_use_case.rs"]
mod batch_classification_proves_profile_matrix_use_case;
#[path = "integration/redaction/bundle_artifacts_accept_builtin_redaction_profiles.rs"]
mod bundle_artifacts_accept_builtin_redaction_profiles;
#[path = "integration/inspect/color_modes_control_ansi_output.rs"]
mod color_modes_control_ansi_output;
#[path = "integration/cli/completion_outputs_supported_shell_scripts.rs"]
mod completion_outputs_supported_shell_scripts;
#[path = "integration/config/config_bundle_assembles_selected_policy_profile_and_resolved_config.rs"]
mod config_bundle_assembles_selected_policy_profile_and_resolved_config;
#[path = "integration/config/config_bundle_consumer_rejects_conflicting_cli_config_inputs.rs"]
mod config_bundle_consumer_rejects_conflicting_cli_config_inputs;
#[path = "integration/e2e/deployment_gating/contract_only_gate_drives_machine_decision.rs"]
mod contract_only_gate_drives_machine_decision;
#[path = "integration/inspect/contract_summary_surfaces_host_alias_and_display_labels.rs"]
mod contract_summary_surfaces_host_alias_and_display_labels;
#[path = "integration/config/contract_uses_embedded_policy_from_config_bundle.rs"]
mod contract_uses_embedded_policy_from_config_bundle;
#[path = "integration/validation/convenience_chain_matches_explicit_contract_flow.rs"]
mod convenience_chain_matches_explicit_contract_flow;
#[path = "integration/extensions/cuda_runtime_end_to_end.rs"]
mod cuda_runtime_end_to_end;
#[path = "integration/bundle/decision_bundle_accepts_config_bundle_handoff.rs"]
mod decision_bundle_accepts_config_bundle_handoff;
#[path = "integration/bundle/decision_bundle_accepts_recommendation_report_handoff.rs"]
mod decision_bundle_accepts_recommendation_report_handoff;
#[path = "integration/bundle/decision_bundle_accepts_verification_bundle_handoff.rs"]
mod decision_bundle_accepts_verification_bundle_handoff;
#[path = "integration/bundle/decision_bundle_contract_only_assembles_local_artifact.rs"]
mod decision_bundle_contract_only_assembles_local_artifact;
#[path = "integration/bundle/decision_bundle_includes_state_and_resolved_config.rs"]
mod decision_bundle_includes_state_and_resolved_config;
#[path = "integration/bundle/decision_bundle_rejects_conflicting_config_bundle_and_resolved_config_inputs.rs"]
mod decision_bundle_rejects_conflicting_config_bundle_and_resolved_config_inputs;
#[path = "integration/bundle/decision_bundle_rejects_contract_lineage_mismatch.rs"]
mod decision_bundle_rejects_contract_lineage_mismatch;
#[path = "integration/config/inspect_config_reports_selection_provenance.rs"]
mod inspect_config_reports_selection_provenance;
#[path = "integration/config/invocation_context_selects_pack_and_catalogue_entries.rs"]
mod invocation_context_selects_pack_and_catalogue_entries;
#[path = "integration/classification/invocation_context_selects_single_catalogue_profile.rs"]
mod invocation_context_selects_single_catalogue_profile;
#[path = "integration/e2e/preflight/local_preflight_reports_go_no_go_without_scraping_prose.rs"]
mod local_preflight_reports_go_no_go_without_scraping_prose;
#[path = "integration/inspect/operator_views_surface_validation_posture_and_classification_summary.rs"]
mod operator_views_surface_validation_posture_and_classification_summary;
#[path = "integration/extensions/python_runtime_end_to_end.rs"]
mod python_runtime_end_to_end;
#[path = "integration/recommendation/recommendation_pack_selection_accepts_cli_and_invocation_ids.rs"]
mod recommendation_pack_selection_accepts_cli_and_invocation_ids;
#[path = "integration/inspect/renders_host_survey_summary.rs"]
mod renders_host_survey_summary;
#[path = "integration/classification/same_survey_multi_policy_contracts_classify_cleanly.rs"]
mod same_survey_multi_policy_contracts_classify_cleanly;
#[path = "integration/e2e/deployment_gating/state_required_gate_respects_freshness_and_drives_machine_decision.rs"]
mod state_required_gate_respects_freshness_and_drives_machine_decision;
#[path = "integration/config/validate_config_bundle_rejects_missing_profile_section.rs"]
mod validate_config_bundle_rejects_missing_profile_section;
#[path = "integration/cli/validate_help_routes_and_explains_state_freshness.rs"]
mod validate_help_routes_and_explains_state_freshness;
#[path = "integration/config/validate_uses_embedded_profile_and_controls_from_config_bundle.rs"]
mod validate_uses_embedded_profile_and_controls_from_config_bundle;
#[path = "integration/e2e/deployment_gating/verified_gate_requires_trust_success_before_decision.rs"]
mod verified_gate_requires_trust_success_before_decision;
#[path = "integration/trust/verify_emits_machine_readable_report.rs"]
mod verify_emits_machine_readable_report;
#[path = "integration/cli/version_flags_report_package_version.rs"]
mod version_flags_report_package_version;
