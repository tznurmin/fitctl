// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Deterministic local identity helpers.
//!
//! These hashes summarise host identity and composition for local tracking and export-safe
//! pseudonyms without turning raw local identifiers into the only interoperability surface.

use sha2::{Digest, Sha256};

use crate::artifacts::metadata_v1::{
    IdentityClassV1, IdentitySummaryV1, LocalStableAnchorFamilyV1, LocalStableAnchorSourceV1,
    LocalStableIdDegradedReasonV1, LocalStableStabilityClassV1,
};
use crate::artifacts::state_v1::StateLocalIdentityV1;
use crate::survey::VisibilityScopeV1;

pub const LOCAL_STABLE_ID_V2_VERSION: u32 = 2;

const HMAC_BLOCK_SIZE_SHA256: usize = 64;
const LOCAL_STABLE_ID_V2_DERIVATION_KEY: &[u8] = b"fitctl.local_stable_id.v2.app_key.2026-04-19";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalStableIdentityInputV2 {
    pub anchor_family: LocalStableAnchorFamilyV1,
    pub anchor_source: LocalStableAnchorSourceV1,
    pub stability_class: LocalStableStabilityClassV1,
    pub degraded: bool,
    pub degraded_reason: Option<LocalStableIdDegradedReasonV1>,
    canonical_anchor: Vec<u8>,
}

impl LocalStableIdentityInputV2 {
    pub fn derive_summary(
        &self,
        composition_digest: String,
        provenance_fingerprint: String,
    ) -> IdentitySummaryV1 {
        IdentitySummaryV1 {
            identity_class: IdentityClassV1::LocalStable,
            local_stable_id: derive_local_stable_id_v2(self),
            local_stable_id_version: LOCAL_STABLE_ID_V2_VERSION,
            local_stable_anchor_family: Some(self.anchor_family),
            local_stable_anchor_source: Some(self.anchor_source),
            local_stable_stability_class: Some(self.stability_class),
            local_stable_id_degraded: self.degraded,
            local_stable_id_degraded_reason: self.degraded_reason,
            composition_digest,
            provenance_fingerprint,
        }
    }

    pub fn derive_state_local_identity(&self) -> StateLocalIdentityV1 {
        StateLocalIdentityV1 {
            local_stable_id: derive_local_stable_id_v2(self),
            local_stable_id_version: LOCAL_STABLE_ID_V2_VERSION,
            local_stable_anchor_family: self.anchor_family,
            local_stable_anchor_source: self.anchor_source,
            local_stable_stability_class: self.stability_class,
            local_stable_id_degraded: self.degraded,
            local_stable_id_degraded_reason: self.degraded_reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLinuxIdentitySelectionV2 {
    pub input: LocalStableIdentityInputV2,
    pub notes: Vec<String>,
}

pub fn derive_local_stable_id_v1(host_alias: &str, source_ref: &str) -> String {
    hash_hex(&format!(
        "fitctl.local_stable_id.v1\0{}\0{}",
        host_alias.trim(),
        source_ref.trim()
    ))
}

pub fn derive_local_stable_id_v2(input: &LocalStableIdentityInputV2) -> String {
    let mut message = Vec::new();
    message.extend_from_slice(b"fitctl.local_stable_id.v2\0");
    message.extend_from_slice(b"anchor_family=");
    message.extend_from_slice(input.anchor_family.as_str().as_bytes());
    message.extend_from_slice(b"\0");
    message.extend_from_slice(&input.canonical_anchor);
    hmac_sha256_hex(LOCAL_STABLE_ID_V2_DERIVATION_KEY, &message)
}

pub fn select_live_linux_identity_input_v2(
    etc_machine_id: Option<&str>,
    dbus_machine_id: Option<&str>,
    dmi_product_uuid: Option<&str>,
    kernel_hostname: Option<&str>,
) -> LiveLinuxIdentitySelectionV2 {
    let valid_etc_machine_id = etc_machine_id.and_then(normalize_machine_id_v2);
    let valid_dbus_machine_id = dbus_machine_id.and_then(normalize_machine_id_v2);
    let valid_dmi_product_uuid = dmi_product_uuid.and_then(normalize_dmi_product_uuid_v2);
    let valid_kernel_hostname = normalize_kernel_hostname_v2(kernel_hostname);
    let mut notes = Vec::new();

    if let Some(machine_id) = valid_etc_machine_id.as_ref() {
        if let Some(dbus_machine_id) = valid_dbus_machine_id.as_ref() {
            if machine_id != dbus_machine_id {
                notes.push(
                    "machine-id disagreement between /etc/machine-id and /var/lib/dbus/machine-id; preferring /etc/machine-id"
                        .to_string(),
                );
            }
        }
        return LiveLinuxIdentitySelectionV2 {
            input: LocalStableIdentityInputV2 {
                anchor_family: LocalStableAnchorFamilyV1::MachineId,
                anchor_source: LocalStableAnchorSourceV1::EtcMachineId,
                stability_class: LocalStableStabilityClassV1::OsInstanceLike,
                degraded: false,
                degraded_reason: None,
                canonical_anchor: machine_id.as_bytes().to_vec(),
            },
            notes,
        };
    }

    if let Some(machine_id) = valid_dbus_machine_id {
        return LiveLinuxIdentitySelectionV2 {
            input: LocalStableIdentityInputV2 {
                anchor_family: LocalStableAnchorFamilyV1::MachineId,
                anchor_source: LocalStableAnchorSourceV1::DbusMachineId,
                stability_class: LocalStableStabilityClassV1::OsInstanceLike,
                degraded: false,
                degraded_reason: None,
                canonical_anchor: machine_id.as_bytes().to_vec(),
            },
            notes,
        };
    }

    if let Some(product_uuid) = valid_dmi_product_uuid {
        return LiveLinuxIdentitySelectionV2 {
            input: LocalStableIdentityInputV2 {
                anchor_family: LocalStableAnchorFamilyV1::DmiProductUuid,
                anchor_source: LocalStableAnchorSourceV1::SysfsDmiProductUuid,
                stability_class: LocalStableStabilityClassV1::FirmwareOrVmLike,
                degraded: false,
                degraded_reason: None,
                canonical_anchor: product_uuid.as_bytes().to_vec(),
            },
            notes,
        };
    }

    let canonical_hostname = valid_kernel_hostname.unwrap_or_else(|| "localhost".to_string());
    LiveLinuxIdentitySelectionV2 {
        input: LocalStableIdentityInputV2 {
            anchor_family: LocalStableAnchorFamilyV1::Hostname,
            anchor_source: LocalStableAnchorSourceV1::KernelHostname,
            stability_class: LocalStableStabilityClassV1::AliasOnly,
            degraded: true,
            degraded_reason: Some(LocalStableIdDegradedReasonV1::HostnameFallback),
            canonical_anchor: canonical_hostname.into_bytes(),
        },
        notes,
    }
}

pub fn fixture_identity_input_v2(corpus_id: &str, host_alias: &str) -> LocalStableIdentityInputV2 {
    let mut canonical_anchor = Vec::new();
    canonical_anchor.extend_from_slice(corpus_id.trim().as_bytes());
    canonical_anchor.extend_from_slice(b"\0");
    canonical_anchor.extend_from_slice(host_alias.trim().as_bytes());

    LocalStableIdentityInputV2 {
        anchor_family: LocalStableAnchorFamilyV1::Fixture,
        anchor_source: LocalStableAnchorSourceV1::FixtureAlias,
        stability_class: LocalStableStabilityClassV1::Fixture,
        degraded: false,
        degraded_reason: None,
        canonical_anchor,
    }
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

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut key_block = [0u8; HMAC_BLOCK_SIZE_SHA256];
    if key.len() > HMAC_BLOCK_SIZE_SHA256 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hashed_key = hasher.finalize();
        key_block[..hashed_key.len()].copy_from_slice(&hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; HMAC_BLOCK_SIZE_SHA256];
    let mut outer_pad = [0x5cu8; HMAC_BLOCK_SIZE_SHA256];
    for (slot, key_byte) in inner_pad.iter_mut().zip(key_block.iter()) {
        *slot ^= *key_byte;
    }
    for (slot, key_byte) in outer_pad.iter_mut().zip(key_block.iter()) {
        *slot ^= *key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    format!("{:x}", outer.finalize())
}

fn normalize_machine_id_v2(raw: &str) -> Option<String> {
    let canonical = raw.trim_end_matches('\n').trim_end_matches('\r');
    if canonical.is_empty() || canonical == "uninitialized" || canonical.len() != 32 {
        return None;
    }
    if canonical == "00000000000000000000000000000000" {
        return None;
    }
    if !canonical
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(canonical.to_string())
}

fn normalize_dmi_product_uuid_v2(raw: &str) -> Option<String> {
    let canonical = raw.trim().to_ascii_lowercase();
    if canonical.is_empty()
        || canonical == "00000000-0000-0000-0000-000000000000"
        || canonical.len() != 36
    {
        return None;
    }

    for (index, byte) in canonical.as_bytes().iter().enumerate() {
        let is_dash = matches!(index, 8 | 13 | 18 | 23);
        if is_dash {
            if *byte != b'-' {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }

    Some(canonical)
}

fn normalize_kernel_hostname_v2(raw: Option<&str>) -> Option<String> {
    let canonical = raw?.trim();
    if canonical.is_empty() {
        return None;
    }
    Some(canonical.to_string())
}

fn visibility_scope_label(scope: VisibilityScopeV1) -> &'static str {
    match scope {
        VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        VisibilityScopeV1::VmLike => "vm_like",
        VisibilityScopeV1::ContainerRestricted => "container_restricted",
        VisibilityScopeV1::Unknown => "unknown",
    }
}
