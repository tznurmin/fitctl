// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};

use super::support::{assert_case, profile, Family};

#[test]
fn profile_semantics_value_path_matrix() {
    for scopes in [json!([]), json!(["bare_metal_like", "bare_metal_like"])] {
        let mut raw = profile();
        raw["profile"]["core_requirements"]["allowed_visibility_scopes"] = scopes;
        invalid("visibility", raw, "service_profile_requirement_invalid");
    }
    for field in [
        "min_allocatable_cpu_logical_cores",
        "min_allocatable_memory_bytes",
        "min_non_loopback_interfaces",
        "min_network_link_speed_mbps",
        "min_numa_nodes",
        "max_numa_nodes",
        "min_cpu_packages",
        "min_policy_scoped_accelerators",
        "max_accelerator_numa_nodes",
    ] {
        let mut raw = profile();
        raw["profile"]["core_requirements"][field] = json!(0);
        invalid(field, raw, "service_profile_requirement_invalid");
    }
    let mut numa = profile();
    numa["profile"]["core_requirements"]["min_numa_nodes"] = json!(2);
    numa["profile"]["core_requirements"]["max_numa_nodes"] = json!(1);
    invalid(
        "NUMA cross-field",
        numa,
        "service_profile_requirement_invalid",
    );

    let tier = json!({"tier_id":"fallback", "acceptable_capability_class":"light_compute", "rationale":"lower capacity"});
    for ladder in [
        json!([tier.clone(), tier.clone()]),
        json!([{ "tier_id":"", "acceptable_capability_class":"light_compute", "rationale":"lower capacity" }]),
        json!([{ "tier_id":"fallback", "acceptable_capability_class":"general_compute", "rationale":"duplicate primary" }]),
    ] {
        let mut raw = profile();
        raw["profile"]["degradation_ladder"] = ladder;
        invalid("ladder", raw, "degradation_ladder_invalid");
    }
    for classes in [json!([""]), json!(["x", "x"])] {
        let mut raw = profile();
        raw["profile"]["exclusions"]["forbidden_capability_classes"] = classes;
        invalid("exclusions", raw, "service_profile_requirement_invalid");
    }
    let mut assurance = profile();
    assurance["profile"]["assurance_predicates"] =
        json!(["locally_verified_required", "locally_verified_required"]);
    invalid(
        "duplicate assurance",
        assurance,
        "assurance_predicate_invalid",
    );
    let mut unknown = profile();
    unknown["profile"]["assurance_predicates"] = json!(["unknown"]);
    assert_case(
        Family::Profile,
        "unknown assurance",
        unknown,
        Some(("assurance_predicate_invalid", "profile_validate")),
    );

    let mut cuda = profile();
    cuda["profile"]["extension_requirements"]["fitctl.runtime.cuda"] = json!({
        "schema_id":"fitctl.extension.runtime.cuda.requirement.v1", "schema_version":1,
        "required_runtime":"cuda", "require_presence":true,
        "minimum_qualifying_device_aggregate_allocatable_memory_bytes":1024
    });
    invalid(
        "CUDA aggregate needs per-device threshold",
        cuda.clone(),
        "service_profile_artifact_invalid",
    );
    cuda["profile"]["extension_requirements"]["fitctl.runtime.cuda"]
        ["minimum_device_allocatable_memory_bytes"] = json!(512);
    invalid(
        "CUDA cross-field",
        cuda.clone(),
        "service_profile_requirement_invalid",
    );
    cuda["profile"]["core_requirements"]["min_policy_scoped_accelerators"] = json!(1);
    assert_case(
        Family::Profile,
        "CUDA cross-field valid",
        cuda.clone(),
        None,
    );
    cuda["profile"]["extension_requirements"]["fitctl.runtime.cuda"]["require_presence"] =
        json!(false);
    invalid(
        "CUDA typed requirement",
        cuda,
        "service_profile_artifact_invalid",
    );

    let mut envelope = profile();
    envelope["envelope"]["artifact_id"] = json!("");
    invalid(
        "canonical envelope",
        envelope,
        "service_profile_artifact_invalid",
    );
}

fn invalid(name: &str, raw: Value, code: &str) {
    assert_case(Family::Profile, name, raw, Some((code, "profile_validate")));
}
