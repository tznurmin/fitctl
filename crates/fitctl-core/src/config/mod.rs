// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed configuration documents and precedence resolution.
//!
//! This module owns policy packs, service-profile catalogues, extension packs, invocation context,
//! and the logic that resolves them into one effective configuration view.

pub mod catalogue_v1;
pub mod resolve_v1;
pub mod schema_v1;

pub use catalogue_v1::{
    create_policy_pack_lock_from_path, load_policy_pack_from_path, load_policy_pack_lock_from_path,
    load_service_profile_catalogue_from_path, resolve_policy_from_pack_path,
    resolve_policy_from_pack_with_lock_path, resolve_service_profile_from_catalogue_path,
    sign_policy_pack_lock_v1, CatalogueError, CatalogueErrorCode, PolicyPackEntryV1,
    PolicyPackLockCompatibilityModeV1, PolicyPackLockV1, PolicyPackV1,
    ServiceProfileCatalogueEntryV1, ServiceProfileCatalogueV1, CATALOGUE_ERROR_MODEL_ID,
    CATALOGUE_ERROR_MODEL_VERSION, POLICY_PACK_LOCK_PAYLOAD_ENCODING_V1,
    POLICY_PACK_LOCK_SCHEMA_ID, POLICY_PACK_LOCK_SIGNATURE_NAMESPACE_V1, POLICY_PACK_SCHEMA_ID,
    SERVICE_PROFILE_CATALOGUE_SCHEMA_ID,
};
pub use resolve_v1::{
    build_extension_basis_v1, resolve_configuration_v1, ResolveConfigurationRequestV1,
};
pub use schema_v1::{
    load_extension_pack_from_path, load_invocation_context_from_path,
    load_recommendation_pack_from_path, semantic_hash_hex_for_extension_pack, ConfigError,
    ConfigErrorCode, DisabledExtensionNamespaceV1, DisabledExtensionReasonV1,
    ExtensionFailureSemanticsV1, ExtensionFreshnessModelV1, ExtensionPackPrivilegeV1,
    ExtensionPackV1, ExtensionSectionKindV1, ExtensionSectionSchemaV1, InvocationContextV1,
    RecommendationPackV1, ResolvedConfigV1, CONFIG_ERROR_MODEL_ID, CONFIG_ERROR_MODEL_VERSION,
    EXTENSION_PACK_SCHEMA_ID, INVOCATION_CONTEXT_SCHEMA_ID, RECOMMENDATION_PACK_SCHEMA_ID,
    RESOLVED_CONFIG_SCHEMA_ID,
};
