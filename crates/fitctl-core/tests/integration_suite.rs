// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/common.rs"]
mod common;

#[path = "support/sharing_time_fixtures.rs"]
mod sharing_time_fixtures;
#[path = "integration/redaction/sharing_times.rs"]
mod sharing_times;
#[path = "integration/redaction/sharing_times_edges.rs"]
mod sharing_times_edges;

#[path = "integration/contract/accelerator_contract_summary_surfaces_richer_details.rs"]
mod accelerator_contract_summary_surfaces_richer_details;
#[path = "integration/survey/accelerator_inventory_depth_surfaces_richer_details.rs"]
mod accelerator_inventory_depth_surfaces_richer_details;
#[path = "integration/validation/accelerator_locality_constraints_are_explicit.rs"]
mod accelerator_locality_constraints_are_explicit;
#[path = "integration/contract/accelerator_locality_summary_surfaces_known_numa_nodes.rs"]
mod accelerator_locality_summary_surfaces_known_numa_nodes;
#[path = "integration/validation/accelerator_present_but_not_locally_usable_is_explicit.rs"]
mod accelerator_present_but_not_locally_usable_is_explicit;
#[path = "integration/survey/accelerator_visibility_detail_surfaces_hidden_node_access.rs"]
mod accelerator_visibility_detail_surfaces_hidden_node_access;
#[path = "integration/config/bundled_config_assets_match_public_configs.rs"]
mod bundled_config_assets_match_public_configs;
#[path = "integration/redaction/categorical_values_fail_closed.rs"]
mod categorical_values_fail_closed;
#[path = "integration/redaction/complete_payload_redaction.rs"]
mod complete_payload_redaction;
#[path = "integration/redaction/complete_provenance_redaction.rs"]
mod complete_provenance_redaction;
#[path = "integration/artifacts/contract_extension_integrity.rs"]
mod contract_extension_integrity;
#[path = "integration/artifacts/core_extension_split_uses_core_and_extension_sections.rs"]
mod core_extension_split_uses_core_and_extension_sections;
#[path = "integration/redaction/core_sharing_view_redaction.rs"]
mod core_sharing_view_redaction;
#[path = "integration/contract/derivation_uses_survey_and_policy_only.rs"]
mod derivation_uses_survey_and_policy_only;
#[path = "integration/redaction/extension_basis_fail_closed.rs"]
mod extension_basis_fail_closed;
#[path = "integration/redaction/extension_sections_fail_closed.rs"]
mod extension_sections_fail_closed;
#[path = "integration/redaction/external_profile_redacts_sensitive_fields.rs"]
mod external_profile_redacts_sensitive_fields;
#[path = "integration/validation/general_compute_no_gpu_rejects_gpu_contract.rs"]
mod general_compute_no_gpu_rejects_gpu_contract;
#[path = "integration/validation/gpu_contract_satisfies_general_compute_by_subsumption.rs"]
mod gpu_contract_satisfies_general_compute_by_subsumption;
#[path = "integration/state/hardware_sensor_compatibility.rs"]
mod hardware_sensor_compatibility;
#[path = "integration/state/hardware_sensor_contract.rs"]
mod hardware_sensor_contract;
#[path = "integration/redaction/hardware_sensor_input.rs"]
mod hardware_sensor_input;
#[path = "integration/state/hardware_sensor_quantities.rs"]
mod hardware_sensor_quantities;
#[path = "integration/state/hardware_sensor_replay.rs"]
mod hardware_sensor_replay;
#[path = "integration/state/hardware_sensor_roundtrip.rs"]
mod hardware_sensor_roundtrip;
#[path = "integration/state/hardware_sensor_validation.rs"]
mod hardware_sensor_validation;
#[path = "integration/redaction/imported_bundle_provenance.rs"]
mod imported_bundle_provenance;
#[path = "integration/redaction/imported_core_provenance.rs"]
mod imported_core_provenance;
#[path = "integration/state/thermal_lm_sensors_units.rs"]
mod lm_sensors_units;
#[path = "integration/state/path_storage_evidence_enrichment.rs"]
mod path_storage_evidence_enrichment;
#[path = "integration/state/provider_fixture_command.rs"]
mod provider_fixture_command;
#[path = "integration/validation/reliability_and_storage_health_requirements.rs"]
mod reliability_and_storage_health_requirements;
#[path = "integration/state/replay_produces_stable_host_state_artifact.rs"]
mod replay_produces_stable_host_state_artifact;
#[path = "integration/survey/replay_produces_stable_host_survey_artifact.rs"]
mod replay_produces_stable_host_survey_artifact;
#[path = "integration/redaction/service_profile_sharing_view_redaction.rs"]
mod service_profile_sharing_view_redaction;
#[path = "integration/redaction/standalone_auxiliary_reports.rs"]
mod standalone_auxiliary_reports;
#[path = "integration/redaction/state_path_sharing_view_redaction.rs"]
mod state_path_sharing_view_redaction;
#[path = "integration/validation/storage_requirements_use_path_evidence.rs"]
mod storage_requirements_use_path_evidence;
#[path = "integration/thermal_evidence/target_bound_thermal_evidence.rs"]
mod target_bound_thermal_evidence;
#[path = "integration/validation/thermal_evidence_requirements_use_target_bound_evidence.rs"]
mod thermal_evidence_requirements_use_target_bound_evidence;
#[path = "integration/state/thermal_provider_evidence.rs"]
mod thermal_provider_evidence;
#[path = "integration/state/thermal_provider_process_lifecycle.rs"]
mod thermal_provider_process_lifecycle;
#[path = "integration/validation/thermal_requirements_use_state_evidence.rs"]
mod thermal_requirements_use_state_evidence;
#[path = "integration/validation/contract_only/uses_contract_and_service_profile_only.rs"]
mod uses_contract_and_service_profile_only;
