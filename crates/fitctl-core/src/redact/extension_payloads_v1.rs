// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Field-level transforms for typed extension payloads.

use crate::artifacts::field_diagnostic_v1::FieldDiagnosticV1;
use crate::extensions::cuda_runtime_v1::{
    CudaDefaultViewProbeDiagnosticsV1, CudaRuntimeContractV1, CudaRuntimeEvidenceV1,
    CudaRuntimeStateV1, CudaRuntimeValidationDiagnosticV1,
    CudaSelectedEnvironmentProbeDiagnosticsV1, CudaSelectedEnvironmentV1,
};
use crate::extensions::{
    NodeRuntimeContractV1, NodeRuntimeEvidenceV1, PythonRuntimeContractV1, PythonRuntimeEvidenceV1,
};
use crate::redact::core_metadata_v1::redact_claim_metadata_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;

pub(crate) fn redact_cuda_evidence_v1(
    evidence: &mut CudaRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() {
        evidence.executable_path = None;
    }
    if !profile.applies_auditor_redactions() {
        return;
    }
    redact_claim_metadata_v1(&mut evidence.claim_metadata, profile, "extension");
    redact_cuda_common_v1(
        &mut evidence.installed_toolkits,
        evidence.default_view_probe_diagnostics.as_mut(),
        evidence.selected_environment.as_mut(),
        evidence.selected_environment_probe_diagnostics.as_mut(),
        profile,
    );
}

pub(crate) fn redact_cuda_contract_v1(
    contract: &mut CudaRuntimeContractV1,
    profile: BuiltInRedactionProfileV1,
) {
    if !profile.applies_auditor_redactions() {
        return;
    }
    redact_claim_metadata_v1(&mut contract.claim_metadata, profile, "extension");
    redact_cuda_common_v1(
        &mut contract.installed_toolkits,
        contract.default_view_probe_diagnostics.as_mut(),
        contract.selected_environment.as_mut(),
        contract.selected_environment_probe_diagnostics.as_mut(),
        profile,
    );
}

pub(crate) fn redact_cuda_state_v1(
    state: &mut CudaRuntimeStateV1,
    profile: BuiltInRedactionProfileV1,
) {
    if !profile.applies_auditor_redactions() {
        return;
    }
    redact_claim_metadata_v1(&mut state.claim_metadata, profile, "extension");
    redact_default_diagnostics_v1(state.default_view_probe_diagnostics.as_mut(), profile);
    redact_selected_environment_v1(state.selected_environment.as_mut(), profile);
    redact_selected_diagnostics_v1(
        state.selected_environment_probe_diagnostics.as_mut(),
        profile,
    );
    if state.probe_path.is_some() {
        state.probe_path = Some(profile.absolute_path_placeholder("cuda_probe", 0));
    }
    for (index, device) in state.devices.iter_mut().enumerate() {
        device.device_uuid = profile.indexed_placeholder("cuda_device", index);
    }
}

pub(crate) fn redact_cuda_diagnostic_v1(
    diagnostic: &mut CudaRuntimeValidationDiagnosticV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_auditor_redactions() {
        replace_indexed(
            &mut diagnostic.evidence_refs,
            profile,
            "extension_evidence_ref",
        );
    }
    if profile.applies_auditor_redactions() {
        replace_indexed(
            &mut diagnostic.related_requirements,
            profile,
            "extension_requirement",
        );
    }
}

pub(crate) fn redact_python_evidence_v1(
    evidence: &mut PythonRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() {
        evidence.executable_path = None;
    }
    if profile.applies_auditor_redactions() {
        redact_claim_metadata_v1(&mut evidence.claim_metadata, profile, "extension");
    }
}

pub(crate) fn redact_python_contract_v1(
    contract: &mut PythonRuntimeContractV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_auditor_redactions() {
        redact_claim_metadata_v1(&mut contract.claim_metadata, profile, "extension");
    }
}

pub(crate) fn redact_node_evidence_v1(
    evidence: &mut NodeRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() {
        evidence.executable_path = None;
    }
    if profile.applies_auditor_redactions() {
        redact_claim_metadata_v1(&mut evidence.claim_metadata, profile, "extension");
    }
}

pub(crate) fn redact_node_contract_v1(
    contract: &mut NodeRuntimeContractV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_auditor_redactions() {
        redact_claim_metadata_v1(&mut contract.claim_metadata, profile, "extension");
    }
}

fn redact_cuda_common_v1(
    toolkits: &mut [crate::extensions::cuda_runtime_v1::CudaInstalledToolkitV1],
    default_diagnostics: Option<&mut CudaDefaultViewProbeDiagnosticsV1>,
    selected_environment: Option<&mut CudaSelectedEnvironmentV1>,
    selected_diagnostics: Option<&mut CudaSelectedEnvironmentProbeDiagnosticsV1>,
    profile: BuiltInRedactionProfileV1,
) {
    for (index, toolkit) in toolkits.iter_mut().enumerate() {
        toolkit.install_root = profile.absolute_path_placeholder("cuda_toolkit", index);
    }
    redact_default_diagnostics_v1(default_diagnostics, profile);
    redact_selected_environment_v1(selected_environment, profile);
    redact_selected_diagnostics_v1(selected_diagnostics, profile);
}

fn redact_default_diagnostics_v1(
    diagnostics: Option<&mut CudaDefaultViewProbeDiagnosticsV1>,
    profile: BuiltInRedactionProfileV1,
) {
    let Some(diagnostics) = diagnostics else {
        return;
    };
    for (index, diagnostic) in [
        &mut diagnostics.default_toolkit_version,
        &mut diagnostics.driver_version,
        &mut diagnostics.driver_supported_cuda_version,
        &mut diagnostics.default_runtime_version,
    ]
    .into_iter()
    .enumerate()
    {
        redact_field_diagnostic_v1(diagnostic, profile, index);
    }
}

fn redact_selected_environment_v1(
    selected: Option<&mut CudaSelectedEnvironmentV1>,
    profile: BuiltInRedactionProfileV1,
) {
    let Some(selected) = selected else {
        return;
    };
    selected.environment_id = profile.indexed_placeholder("cuda_environment", 0);
    if selected.selection.install_root.is_some() {
        selected.selection.install_root =
            Some(profile.absolute_path_placeholder("cuda_selected_environment", 0));
    }
}

fn redact_selected_diagnostics_v1(
    diagnostics: Option<&mut CudaSelectedEnvironmentProbeDiagnosticsV1>,
    profile: BuiltInRedactionProfileV1,
) {
    let Some(diagnostics) = diagnostics else {
        return;
    };
    redact_field_diagnostic_v1(&mut diagnostics.toolkit_version, profile, 0);
    redact_field_diagnostic_v1(&mut diagnostics.runtime_version, profile, 1);
}

fn redact_field_diagnostic_v1(
    diagnostic: &mut FieldDiagnosticV1,
    profile: BuiltInRedactionProfileV1,
    index: usize,
) {
    diagnostic.source_ref = profile.indexed_placeholder("extension_source_ref", index);
}

fn replace_indexed(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}
