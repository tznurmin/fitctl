// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/common.rs"]
mod common;

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
#[path = "integration/artifacts/core_extension_split_uses_core_and_extension_sections.rs"]
mod core_extension_split_uses_core_and_extension_sections;
#[path = "integration/contract/derivation_uses_survey_and_policy_only.rs"]
mod derivation_uses_survey_and_policy_only;
#[path = "integration/redaction/external_profile_redacts_sensitive_fields.rs"]
mod external_profile_redacts_sensitive_fields;
#[path = "integration/validation/general_compute_no_gpu_rejects_gpu_contract.rs"]
mod general_compute_no_gpu_rejects_gpu_contract;
#[path = "integration/validation/gpu_contract_satisfies_general_compute_by_subsumption.rs"]
mod gpu_contract_satisfies_general_compute_by_subsumption;
#[path = "integration/state/replay_produces_stable_host_state_artifact.rs"]
mod replay_produces_stable_host_state_artifact;
#[path = "integration/survey/replay_produces_stable_host_survey_artifact.rs"]
mod replay_produces_stable_host_survey_artifact;
#[path = "integration/validation/contract_only/uses_contract_and_service_profile_only.rs"]
mod uses_contract_and_service_profile_only;
