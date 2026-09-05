// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Sharing-view treatment for common core metadata and topology structures.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifacts::metadata_v1::{ClaimMetadataV1, IdentityClassV1, IdentitySummaryV1};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::survey::AcceleratorOperabilityV1;

pub(crate) fn redact_claim_metadata_v1(
    metadata: &mut ClaimMetadataV1,
    profile: BuiltInRedactionProfileV1,
    scope: &str,
) {
    replace_indexed(
        &mut metadata.source_collectors,
        profile,
        &format!("{scope}_source_collector"),
    );
    for (index, value) in metadata.evidence_paths.iter_mut().enumerate() {
        *value = profile.absolute_path_placeholder(&format!("{scope}_evidence"), index);
    }
    if metadata.policy_rule_id.is_some() {
        metadata.policy_rule_id = Some(profile.indexed_placeholder(&format!("{scope}_rule"), 0));
    }
    replace_indexed(
        &mut metadata.trust_evidence_refs,
        profile,
        &format!("{scope}_trust_evidence"),
    );
}

pub(crate) fn redact_identity_summary_v1(
    identity: &mut IdentitySummaryV1,
    profile: BuiltInRedactionProfileV1,
) {
    identity.identity_class = IdentityClassV1::Redacted;
    identity.local_stable_id = profile.local_stable_identity_placeholder();
    identity.local_stable_id_version = 0;
    identity.local_stable_anchor_family = None;
    identity.local_stable_anchor_source = None;
    identity.local_stable_stability_class = None;
    identity.local_stable_id_degraded = false;
    identity.local_stable_id_degraded_reason = None;
    identity.composition_digest = profile.composition_digest_placeholder();
    identity.provenance_fingerprint = profile.provenance_fingerprint_placeholder();
}

pub(crate) fn redact_accelerator_operability_v1(
    operability: &mut AcceleratorOperabilityV1,
    profile: BuiltInRedactionProfileV1,
) {
    let render_nodes = operability
        .visible_render_nodes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let all_nodes = operability
        .visible_device_nodes
        .iter()
        .chain(operability.visible_render_nodes.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut render_index = 0;
    let mut device_index = 0;
    let mut replacements = BTreeMap::new();
    for node in all_nodes {
        let replacement = if render_nodes.contains(&node) {
            let value = format!(
                "/dev/dri/renderD-redacted-{}-{render_index:08}",
                profile.as_str()
            );
            render_index += 1;
            value
        } else {
            let value = format!(
                "/dev/redacted/{}/accelerator/{device_index:08}",
                profile.as_str()
            );
            device_index += 1;
            value
        };
        replacements.insert(node, replacement);
    }

    replace_nodes(&mut operability.visible_device_nodes, &replacements);
    replace_nodes(&mut operability.visible_render_nodes, &replacements);
}

fn replace_nodes(values: &mut Vec<String>, replacements: &BTreeMap<String, String>) {
    for value in values.iter_mut() {
        if let Some(replacement) = replacements.get(value) {
            *value = replacement.clone();
        }
    }
    values.sort();
    values.dedup();
}

fn replace_indexed(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}
