// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical configuration semantic hashes.

use super::schema_v1::{
    ConfigError, ConfigErrorCode, ExtensionFailureSemanticsV1, ExtensionFreshnessModelV1,
    ExtensionPackPrivilegeV1, ExtensionPackV1, ExtensionSectionKindV1, ResolvedConfigV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Hash an extension-pack manifest on its canonical semantic content.
pub fn semantic_hash_hex_for_extension_pack(pack: &ExtensionPackV1) -> Result<String, ConfigError> {
    #[derive(Serialize)]
    struct ExtensionSectionProjection<'a> {
        section_kind: ExtensionSectionKindV1,
        schema_id: &'a str,
        schema_version: u32,
    }

    #[derive(Serialize)]
    struct ExtensionPackSemanticProjection<'a> {
        pack_id: &'a str,
        namespace: &'a str,
        namespace_owner: &'a str,
        pack_version: &'a str,
        collector_ids: Vec<&'a str>,
        emitted_sections: Vec<ExtensionSectionProjection<'a>>,
        required_privilege: ExtensionPackPrivilegeV1,
        freshness_model: ExtensionFreshnessModelV1,
        failure_semantics: ExtensionFailureSemanticsV1,
    }

    let mut collector_ids = pack
        .collector_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    collector_ids.sort_unstable();

    let mut emitted_sections = pack
        .emitted_sections
        .iter()
        .map(|section| ExtensionSectionProjection {
            section_kind: section.section_kind,
            schema_id: section.schema_id.as_str(),
            schema_version: section.schema_version,
        })
        .collect::<Vec<_>>();
    emitted_sections.sort_by(|left, right| {
        left.section_kind
            .cmp(&right.section_kind)
            .then_with(|| left.schema_id.cmp(right.schema_id))
            .then_with(|| left.schema_version.cmp(&right.schema_version))
    });

    let bytes = crate::artifacts::canonical_cbor_v2::to_vec(&ExtensionPackSemanticProjection {
        pack_id: &pack.pack_id,
        namespace: &pack.namespace,
        namespace_owner: &pack.namespace_owner,
        pack_version: &pack.pack_version,
        collector_ids,
        emitted_sections,
        required_privilege: pack.required_privilege,
        freshness_model: pack.freshness_model,
        failure_semantics: pack.failure_semantics,
    })
    .map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            format!("failed to encode extension-pack semantic projection: {error}"),
        )
    })?;

    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Hash a resolved-config document on its canonical semantic content.
pub fn semantic_hash_hex_for_resolved_config(
    config: &ResolvedConfigV1,
) -> Result<String, ConfigError> {
    let bytes = crate::artifacts::canonical_cbor_v2::to_vec(config).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            format!("failed to encode resolved-config semantic projection: {error}"),
        )
    })?;

    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
