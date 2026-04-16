// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Deterministic local identity helpers.
//!
//! These hashes summarise host identity and composition for local tracking and export-safe
//! pseudonyms without turning raw local identifiers into the only interoperability surface.

use sha2::{Digest, Sha256};

use crate::survey::VisibilityScopeV1;

pub fn derive_local_stable_id_v1(host_alias: &str, source_ref: &str) -> String {
    hash_hex(&format!(
        "fitctl.local_stable_id.v1\0{}\0{}",
        host_alias.trim(),
        source_ref.trim()
    ))
}

pub fn derive_composition_digest_v1(
    logical_cores: Option<u32>,
    memory_total_bytes: Option<u64>,
    block_device_count: usize,
    mount_count: usize,
    interface_count: usize,
    accelerator_count: usize,
    visibility_scope: VisibilityScopeV1,
) -> String {
    hash_hex(&format!(
        "fitctl.composition_digest.v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        logical_cores.unwrap_or_default(),
        memory_total_bytes.unwrap_or_default(),
        block_device_count,
        mount_count,
        interface_count,
        accelerator_count,
        visibility_scope_label(visibility_scope)
    ))
}

pub fn derive_provenance_fingerprint_v1(
    local_stable_id: &str,
    collector_ids: &[String],
    visibility_scope: VisibilityScopeV1,
    container_runtime: Option<&str>,
) -> String {
    let mut collectors = collector_ids.to_vec();
    collectors.sort();
    collectors.dedup();

    hash_hex(&format!(
        "fitctl.provenance_fingerprint.v1\0{}\0{}\0{}\0{}",
        local_stable_id,
        visibility_scope_label(visibility_scope),
        container_runtime.unwrap_or_default(),
        collectors.join(",")
    ))
}

pub fn derive_export_pseudonym_v1(
    local_stable_id: &str,
    trust_domain: &str,
    pseudonym_secret: &str,
) -> String {
    hash_hex(&format!(
        "fitctl.export_pseudonym.v1\0{}\0{}\0{}",
        local_stable_id.trim(),
        trust_domain.trim(),
        pseudonym_secret.trim()
    ))
}

fn hash_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn visibility_scope_label(scope: VisibilityScopeV1) -> &'static str {
    match scope {
        VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        VisibilityScopeV1::VmLike => "vm_like",
        VisibilityScopeV1::ContainerRestricted => "container_restricted",
        VisibilityScopeV1::Unknown => "unknown",
    }
}
