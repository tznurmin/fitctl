// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Loading, validating, and resolving policy packs, locks, and service-profile catalogues.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::envelope_v1::SignatureEnvelopeV1;
use crate::policy::{load_policy_document_from_path, merge_policy_document_v1, PolicyDocumentV1};
use crate::service_profile::{load_service_profile_from_path, ServiceProfileError};
use crate::sign::{
    sign_detached_semantic_payload_v1, verify_detached_semantic_payload_signature_v1,
    DetachedSignatureRequestV1, SIGNATURE_FORMAT_V1,
};
use crate::{artifacts::service_profile_v1::ServiceProfileV1, contract::ContractDerivationError};

pub const CATALOGUE_ERROR_MODEL_ID: &str = "fitctl.catalogue.v1";
pub const CATALOGUE_ERROR_MODEL_VERSION: u32 = 1;
pub const POLICY_PACK_SCHEMA_ID: &str = "fitctl.policy-pack.v1";
pub const POLICY_PACK_LOCK_SCHEMA_ID: &str = "fitctl.policy-pack-lock.v1";
pub const SERVICE_PROFILE_CATALOGUE_SCHEMA_ID: &str = "fitctl.service-profile-catalogue.v1";
pub const POLICY_PACK_LOCK_SIGNATURE_NAMESPACE_V1: &str = "fitctl-policy-pack-lock-v1";
pub const POLICY_PACK_LOCK_PAYLOAD_ENCODING_V1: &str = "fitctl.policy-pack-lock.semantic_cbor.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogueErrorCode {
    ManifestInputInvalid,
    ManifestSelectionInvalid,
    ManifestCompatibilityInvalid,
    ManifestSignatureInvalid,
}

impl CatalogueErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManifestInputInvalid => "manifest_input_invalid",
            Self::ManifestSelectionInvalid => "manifest_selection_invalid",
            Self::ManifestCompatibilityInvalid => "manifest_compatibility_invalid",
            Self::ManifestSignatureInvalid => "manifest_signature_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogueError {
    pub code: CatalogueErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl CatalogueError {
    fn new(
        code: CatalogueErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: CATALOGUE_ERROR_MODEL_ID,
            error_model_version: CATALOGUE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{} at {}]",
            self.message,
            self.code.as_str(),
            self.checkpoint_id
        )
    }
}

impl std::error::Error for CatalogueError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One selectable policy entry inside a policy pack.
pub struct PolicyPackEntryV1 {
    pub policy_id: String,
    pub summary: String,
    pub policy_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Reusable bundle of policies exposed through stable ids.
pub struct PolicyPackV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub summary: String,
    pub policies: Vec<PolicyPackEntryV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Lock mode that binds both the selected pack entry and the resolved policy content.
pub enum PolicyPackLockCompatibilityModeV1 {
    StrictEntryAndPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Signed selection record for one policy-pack entry.
///
/// The lock freezes which entry was chosen and which semantic hashes the pack entry and resolved
/// policy must still match.
pub struct PolicyPackLockV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub lock_id: String,
    pub pack_id: String,
    pub pack_version: String,
    pub policy_id: String,
    pub policy_summary: String,
    pub policy_path: String,
    pub compatibility_mode: PolicyPackLockCompatibilityModeV1,
    pub policy_pack_entry_semantic_hash: String,
    pub policy_semantic_hash: String,
    #[serde(default)]
    pub signatures: Vec<SignatureEnvelopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One selectable profile entry inside a service-profile catalogue.
pub struct ServiceProfileCatalogueEntryV1 {
    pub profile_id: String,
    pub summary: String,
    pub profile_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Reusable list of service profiles exposed through stable ids.
pub struct ServiceProfileCatalogueV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub catalogue_id: String,
    pub catalogue_version: String,
    pub summary: String,
    pub profiles: Vec<ServiceProfileCatalogueEntryV1>,
}

pub fn load_policy_pack_from_path(path: &Path) -> Result<PolicyPackV1, CatalogueError> {
    let raw = load_json_value_from_path(path, "policy pack")?;
    validate_policy_pack_json(&raw)?;
    let pack: PolicyPackV1 = serde_json::from_value(raw).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_load",
            format!("failed to decode policy pack {}: {error}", path.display()),
        )
    })?;
    validate_policy_pack(&pack)?;
    Ok(pack)
}

pub fn load_policy_pack_lock_from_path(path: &Path) -> Result<PolicyPackLockV1, CatalogueError> {
    let raw = load_json_value_from_path(path, "policy-pack lock")?;
    validate_policy_pack_lock_json(&raw)?;
    let lock: PolicyPackLockV1 = serde_json::from_value(raw).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_load",
            format!(
                "failed to decode policy-pack lock {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_policy_pack_lock(&lock)?;
    verify_policy_pack_lock_signatures(&lock)?;
    Ok(lock)
}

pub fn load_service_profile_catalogue_from_path(
    path: &Path,
) -> Result<ServiceProfileCatalogueV1, CatalogueError> {
    let raw = load_json_value_from_path(path, "service-profile catalogue")?;
    validate_service_profile_catalogue_json(&raw)?;
    let catalogue: ServiceProfileCatalogueV1 = serde_json::from_value(raw).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "service_profile_catalogue_load",
            format!(
                "failed to decode service-profile catalogue {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_service_profile_catalogue(&catalogue)?;
    Ok(catalogue)
}

pub fn create_policy_pack_lock_from_path(
    pack_path: &Path,
    policy_id: &str,
) -> Result<PolicyPackLockV1, CatalogueError> {
    let (pack, entry, policy) = resolve_policy_from_pack_path(pack_path, policy_id)?;
    let policy_pack_entry_semantic_hash = policy_pack_entry_semantic_hash_hex(&entry)?;
    let policy_semantic_hash = policy_document_semantic_hash_hex(&policy)?;

    Ok(PolicyPackLockV1 {
        schema_id: POLICY_PACK_LOCK_SCHEMA_ID.to_string(),
        schema_version: 1,
        lock_id: format!("{}--{}--lock-v1", pack.pack_id, entry.policy_id),
        pack_id: pack.pack_id,
        pack_version: pack.pack_version,
        policy_id: entry.policy_id,
        policy_summary: entry.summary,
        policy_path: entry.policy_path,
        compatibility_mode: PolicyPackLockCompatibilityModeV1::StrictEntryAndPolicy,
        policy_pack_entry_semantic_hash,
        policy_semantic_hash,
        signatures: vec![],
    })
}

pub fn sign_policy_pack_lock_v1(
    lock: &PolicyPackLockV1,
    private_key_path: &Path,
    signed_at: &str,
) -> Result<PolicyPackLockV1, CatalogueError> {
    validate_policy_pack_lock(lock)?;
    let semantic_bytes = policy_pack_lock_semantic_bytes(lock)?;
    let semantic_hash = policy_pack_lock_semantic_hash_hex(lock)?;
    let signature = sign_detached_semantic_payload_v1(DetachedSignatureRequestV1 {
        payload_bytes: semantic_bytes,
        payload_semantic_hash: semantic_hash,
        private_key_path: private_key_path.to_path_buf(),
        signature_namespace: POLICY_PACK_LOCK_SIGNATURE_NAMESPACE_V1.to_string(),
        payload_encoding: POLICY_PACK_LOCK_PAYLOAD_ENCODING_V1.to_string(),
        signed_at: signed_at.to_string(),
    })
    .map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestSignatureInvalid,
            "policy_pack_lock_sign",
            error.message,
        )
    })?;

    let mut signed = lock.clone();
    signed.signatures.push(signature);
    validate_policy_pack_lock(&signed)?;
    verify_policy_pack_lock_signatures(&signed)?;
    Ok(signed)
}

pub fn resolve_policy_from_pack_path(
    pack_path: &Path,
    policy_id: &str,
) -> Result<(PolicyPackV1, PolicyPackEntryV1, PolicyDocumentV1), CatalogueError> {
    if policy_id.trim().is_empty() {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_entry_select",
            "policy selection requires a non-blank policy id",
        ));
    }

    let pack = load_policy_pack_from_path(pack_path)?;
    let entry = pack
        .policies
        .iter()
        .find(|entry| entry.policy_id == policy_id)
        .cloned()
        .ok_or_else(|| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestSelectionInvalid,
                "manifest_entry_select",
                format!(
                    "policy pack {} does not define policy id {}",
                    pack.pack_id, policy_id
                ),
            )
        })?;
    let resolved_path = resolve_manifest_entry_path(pack_path, &entry.policy_path)?;
    let policy = load_policy_document_from_path(&resolved_path).map_err(|error| {
        contract_error_to_catalogue_error(error, resolved_path.as_path(), "policy pack entry")
    })?;

    Ok((pack, entry, policy))
}

pub fn resolve_policy_from_pack_with_lock_path(
    pack_path: &Path,
    lock_path: &Path,
) -> Result<
    (
        PolicyPackV1,
        PolicyPackLockV1,
        PolicyPackEntryV1,
        PolicyDocumentV1,
    ),
    CatalogueError,
> {
    let lock = load_policy_pack_lock_from_path(lock_path)?;
    let (pack, entry, policy) = resolve_policy_from_pack_path(pack_path, &lock.policy_id)?;

    if pack.pack_id != lock.pack_id || pack.pack_version != lock.pack_version {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestCompatibilityInvalid,
            "policy_pack_lock_compatibility",
            format!(
                "policy-pack lock {} expects pack {} version {} but {} version {} was provided",
                lock.lock_id, lock.pack_id, lock.pack_version, pack.pack_id, pack.pack_version
            ),
        ));
    }

    if lock.compatibility_mode != PolicyPackLockCompatibilityModeV1::StrictEntryAndPolicy {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestCompatibilityInvalid,
            "policy_pack_lock_compatibility",
            "policy-pack lock compatibility mode must be supported",
        ));
    }

    let entry_hash = policy_pack_entry_semantic_hash_hex(&entry)?;
    if entry_hash != lock.policy_pack_entry_semantic_hash {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestCompatibilityInvalid,
            "policy_pack_lock_compatibility",
            "policy-pack entry drifted from the locked selection",
        ));
    }
    let policy_hash = policy_document_semantic_hash_hex(&policy)?;
    if policy_hash != lock.policy_semantic_hash {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestCompatibilityInvalid,
            "policy_pack_lock_compatibility",
            "selected policy semantics drifted from the locked selection",
        ));
    }

    Ok((pack, lock, entry, policy))
}

pub fn resolve_service_profile_from_catalogue_path(
    catalogue_path: &Path,
    profile_id: &str,
) -> Result<
    (
        ServiceProfileCatalogueV1,
        ServiceProfileCatalogueEntryV1,
        ServiceProfileV1,
    ),
    CatalogueError,
> {
    if profile_id.trim().is_empty() {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_entry_select",
            "service-profile selection requires a non-blank profile id",
        ));
    }

    let catalogue = load_service_profile_catalogue_from_path(catalogue_path)?;
    let entry = catalogue
        .profiles
        .iter()
        .find(|entry| entry.profile_id == profile_id)
        .cloned()
        .ok_or_else(|| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestSelectionInvalid,
                "manifest_entry_select",
                format!(
                    "service-profile catalogue {} does not define profile id {}",
                    catalogue.catalogue_id, profile_id
                ),
            )
        })?;
    let resolved_path = resolve_manifest_entry_path(catalogue_path, &entry.profile_path)?;
    let profile = load_service_profile_from_path(&resolved_path).map_err(|error| {
        service_profile_error_to_catalogue_error(
            error,
            resolved_path.as_path(),
            "service-profile catalogue entry",
        )
    })?;

    Ok((catalogue, entry, profile))
}

fn contract_error_to_catalogue_error(
    error: ContractDerivationError,
    resolved_path: &Path,
    label: &str,
) -> CatalogueError {
    CatalogueError::new(
        CatalogueErrorCode::ManifestSelectionInvalid,
        "manifest_entry_select",
        format!(
            "failed to load {} {}: {}",
            label,
            resolved_path.display(),
            error.message
        ),
    )
}

fn service_profile_error_to_catalogue_error(
    error: ServiceProfileError,
    resolved_path: &Path,
    label: &str,
) -> CatalogueError {
    CatalogueError::new(
        CatalogueErrorCode::ManifestSelectionInvalid,
        "manifest_entry_select",
        format!(
            "failed to load {} {}: {}",
            label,
            resolved_path.display(),
            error.message
        ),
    )
}

fn load_json_value_from_path(path: &Path, label: &str) -> Result<Value, CatalogueError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "manifest_path_resolve",
            format!("failed to read {label} {}: {error}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "manifest_path_resolve",
            format!("failed to decode {label} {}: {error}", path.display()),
        )
    })
}

fn validate_policy_pack_json(raw: &Value) -> Result<(), CatalogueError> {
    let root = require_object(raw, "policy pack root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "pack_version",
            "summary",
            "policies",
        ],
        "policy pack contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "pack_version",
            "summary",
            "policies",
        ],
        "policy pack field",
    )?;

    let entries = root
        .get("policies")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "policy_pack_load",
                "policy pack policies must be an array",
            )
        })?;
    for entry in entries {
        let entry = require_object(entry, "policy pack entry")?;
        reject_unknown_keys(
            entry,
            &["policy_id", "summary", "policy_path"],
            "policy pack entry contains unsupported field",
        )?;
        reject_explicit_nulls(
            entry,
            &["policy_id", "summary", "policy_path"],
            "policy pack entry field",
        )?;
    }

    Ok(())
}

fn validate_policy_pack_lock_json(raw: &Value) -> Result<(), CatalogueError> {
    let root = require_object(raw, "policy-pack lock root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "lock_id",
            "pack_id",
            "pack_version",
            "policy_id",
            "policy_summary",
            "policy_path",
            "compatibility_mode",
            "policy_pack_entry_semantic_hash",
            "policy_semantic_hash",
            "signatures",
        ],
        "policy-pack lock contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "lock_id",
            "pack_id",
            "pack_version",
            "policy_id",
            "policy_summary",
            "policy_path",
            "compatibility_mode",
            "policy_pack_entry_semantic_hash",
            "policy_semantic_hash",
            "signatures",
        ],
        "policy-pack lock field",
    )?;

    if let Some(signatures) = root.get("signatures") {
        let signatures = signatures.as_array().ok_or_else(|| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "policy_pack_lock_load",
                "policy-pack lock signatures must be an array",
            )
        })?;

        for signature in signatures {
            let signature = require_object(signature, "policy-pack lock signature")?;
            reject_unknown_keys(
                signature,
                &[
                    "key_id",
                    "signer_identity",
                    "public_key",
                    "signature_format",
                    "signature_namespace",
                    "payload_encoding",
                    "payload_semantic_hash",
                    "signed_at",
                    "signature",
                ],
                "policy-pack lock signature contains unsupported field",
            )?;
            reject_explicit_nulls(
                signature,
                &[
                    "key_id",
                    "signer_identity",
                    "public_key",
                    "signature_format",
                    "signature_namespace",
                    "payload_encoding",
                    "payload_semantic_hash",
                    "signed_at",
                    "signature",
                ],
                "policy-pack lock signature field",
            )?;
        }
    }

    Ok(())
}

fn validate_service_profile_catalogue_json(raw: &Value) -> Result<(), CatalogueError> {
    let root = require_object(raw, "service-profile catalogue root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "catalogue_id",
            "catalogue_version",
            "summary",
            "profiles",
        ],
        "service-profile catalogue contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "catalogue_id",
            "catalogue_version",
            "summary",
            "profiles",
        ],
        "service-profile catalogue field",
    )?;

    let entries = root
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "service_profile_catalogue_load",
                "service-profile catalogue profiles must be an array",
            )
        })?;
    for entry in entries {
        let entry = require_object(entry, "service-profile catalogue entry")?;
        reject_unknown_keys(
            entry,
            &["profile_id", "summary", "profile_path"],
            "service-profile catalogue entry contains unsupported field",
        )?;
        reject_explicit_nulls(
            entry,
            &["profile_id", "summary", "profile_path"],
            "service-profile catalogue entry field",
        )?;
    }

    Ok(())
}

fn validate_policy_pack(pack: &PolicyPackV1) -> Result<(), CatalogueError> {
    if pack.schema_id != POLICY_PACK_SCHEMA_ID
        || pack.schema_version != 1
        || is_blank(&pack.pack_id)
        || is_blank(&pack.pack_version)
        || is_blank(&pack.summary)
        || pack.policies.is_empty()
    {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_load",
            "policy packs require the supported schema, non-blank ids and summary, and at least one policy entry",
        ));
    }

    let mut entry_ids = BTreeSet::new();
    for entry in &pack.policies {
        if is_blank(&entry.policy_id)
            || is_blank(&entry.summary)
            || is_blank(&entry.policy_path)
            || !entry_ids.insert(entry.policy_id.clone())
        {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "policy_pack_load",
                "policy pack entries require non-blank unique ids, summaries, and paths",
            ));
        }
    }

    Ok(())
}

fn validate_policy_pack_lock(lock: &PolicyPackLockV1) -> Result<(), CatalogueError> {
    if lock.schema_id != POLICY_PACK_LOCK_SCHEMA_ID
        || lock.schema_version != 1
        || is_blank(&lock.lock_id)
        || is_blank(&lock.pack_id)
        || is_blank(&lock.pack_version)
        || is_blank(&lock.policy_id)
        || is_blank(&lock.policy_summary)
        || is_blank(&lock.policy_path)
        || is_blank(&lock.policy_pack_entry_semantic_hash)
        || is_blank(&lock.policy_semantic_hash)
    {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_load",
            "policy-pack locks require the supported schema and non-blank ids, entry metadata, and semantic hashes",
        ));
    }

    let mut signature_keys = BTreeSet::new();
    for signature in &lock.signatures {
        if is_blank(&signature.key_id) || is_blank(&signature.signature) {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "policy_pack_lock_load",
                "policy-pack lock signatures require non-blank key ids and signatures",
            ));
        }
        if !signature_keys.insert(signature.key_id.clone()) {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "policy_pack_lock_load",
                "policy-pack lock signatures must have unique key ids",
            ));
        }
    }

    Ok(())
}

fn validate_service_profile_catalogue(
    catalogue: &ServiceProfileCatalogueV1,
) -> Result<(), CatalogueError> {
    if catalogue.schema_id != SERVICE_PROFILE_CATALOGUE_SCHEMA_ID
        || catalogue.schema_version != 1
        || is_blank(&catalogue.catalogue_id)
        || is_blank(&catalogue.catalogue_version)
        || is_blank(&catalogue.summary)
        || catalogue.profiles.is_empty()
    {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "service_profile_catalogue_load",
            "service-profile catalogues require the supported schema, non-blank ids and summary, and at least one profile entry",
        ));
    }

    let mut entry_ids = BTreeSet::new();
    for entry in &catalogue.profiles {
        if is_blank(&entry.profile_id)
            || is_blank(&entry.summary)
            || is_blank(&entry.profile_path)
            || !entry_ids.insert(entry.profile_id.clone())
        {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "service_profile_catalogue_load",
                "service-profile catalogue entries require non-blank unique ids, summaries, and paths",
            ));
        }
    }

    Ok(())
}

fn verify_policy_pack_lock_signatures(lock: &PolicyPackLockV1) -> Result<(), CatalogueError> {
    if lock.signatures.is_empty() {
        return Ok(());
    }

    let semantic_bytes = policy_pack_lock_semantic_bytes(lock)?;
    let semantic_hash = policy_pack_lock_semantic_hash_hex(lock)?;
    for signature in &lock.signatures {
        verify_detached_semantic_payload_signature_v1(signature, &semantic_bytes, &semantic_hash)
            .map_err(|error| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestSignatureInvalid,
                "policy_pack_lock_signature_verify",
                error.message,
            )
        })?;
        if signature.signature_namespace.as_deref() != Some(POLICY_PACK_LOCK_SIGNATURE_NAMESPACE_V1)
        {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestSignatureInvalid,
                "policy_pack_lock_signature_verify",
                "policy-pack lock signatures must use the supported signature namespace",
            ));
        }
        if signature.signature_format.as_deref() != Some(SIGNATURE_FORMAT_V1) {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestSignatureInvalid,
                "policy_pack_lock_signature_verify",
                "policy-pack lock signatures must use the supported signature format",
            ));
        }
        if signature.payload_encoding.as_deref() != Some(POLICY_PACK_LOCK_PAYLOAD_ENCODING_V1) {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestSignatureInvalid,
                "policy_pack_lock_signature_verify",
                "policy-pack lock signatures must use the supported payload encoding",
            ));
        }
    }

    Ok(())
}

fn policy_pack_entry_semantic_hash_hex(
    entry: &PolicyPackEntryV1,
) -> Result<String, CatalogueError> {
    #[derive(Serialize)]
    struct PolicyPackEntrySemanticProjection<'a> {
        policy_id: &'a str,
        summary: &'a str,
        policy_path: &'a str,
    }

    let bytes = serde_cbor::to_vec(&PolicyPackEntrySemanticProjection {
        policy_id: &entry.policy_id,
        summary: &entry.summary,
        policy_path: &entry.policy_path,
    })
    .map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_build",
            format!("failed to encode policy-pack entry semantic projection: {error}"),
        )
    })?;

    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn policy_document_semantic_hash_hex(policy: &PolicyDocumentV1) -> Result<String, CatalogueError> {
    #[derive(Serialize)]
    struct PolicyLayerSemanticProjection<'a> {
        layer_id: &'a str,
        kind: &'a str,
        capability_class: &'a Option<String>,
        min_cpu_logical_cores: Option<u32>,
        min_memory_bytes: Option<u64>,
        allow_container_restricted: Option<bool>,
        require_network_visibility: Option<bool>,
        required_accelerator_kind: &'a Option<crate::survey::AcceleratorKindV1>,
        required_accelerator_vendor: &'a Option<String>,
        required_accelerator_integration: &'a Option<crate::survey::AcceleratorIntegrationV1>,
        min_accelerator_devices: Option<u32>,
    }

    #[derive(Serialize)]
    struct PolicyDocumentSemanticProjection<'a> {
        policy_id: &'a str,
        selected_policy_layers: Vec<String>,
        capability_class: String,
        min_cpu_logical_cores: u32,
        min_memory_bytes: u64,
        allow_container_restricted: bool,
        require_network_visibility: bool,
        required_accelerator_kind: &'a Option<crate::survey::AcceleratorKindV1>,
        required_accelerator_vendor: &'a Option<String>,
        required_accelerator_integration: &'a Option<crate::survey::AcceleratorIntegrationV1>,
        min_accelerator_devices: Option<u32>,
        layers: Vec<PolicyLayerSemanticProjection<'a>>,
        allowed_extension_namespaces: Vec<&'a str>,
    }

    let effective_policy = merge_policy_document_v1(policy).map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_build",
            error.message,
        )
    })?;

    let mut layers = policy.layers.iter().collect::<Vec<_>>();
    layers.sort_by(|left, right| {
        left.kind
            .precedence_rank()
            .cmp(&right.kind.precedence_rank())
            .then_with(|| left.layer_id.cmp(&right.layer_id))
    });
    let layers = layers
        .into_iter()
        .map(|layer| PolicyLayerSemanticProjection {
            layer_id: &layer.layer_id,
            kind: match layer.kind {
                crate::policy::PolicyLayerKindV1::BuiltInDefaults => "built_in_defaults",
                crate::policy::PolicyLayerKindV1::Site => "site",
                crate::policy::PolicyLayerKindV1::HostClass => "host_class",
                crate::policy::PolicyLayerKindV1::HostLocal => "host_local",
                crate::policy::PolicyLayerKindV1::ValidationSimulation => "validation_simulation",
            },
            capability_class: &layer.rules.capability_class,
            min_cpu_logical_cores: layer.rules.min_cpu_logical_cores,
            min_memory_bytes: layer.rules.min_memory_bytes,
            allow_container_restricted: layer.rules.allow_container_restricted,
            require_network_visibility: layer.rules.require_network_visibility,
            required_accelerator_kind: &layer.rules.required_accelerator_kind,
            required_accelerator_vendor: &layer.rules.required_accelerator_vendor,
            required_accelerator_integration: &layer.rules.required_accelerator_integration,
            min_accelerator_devices: layer.rules.min_accelerator_devices,
        })
        .collect::<Vec<_>>();
    let mut allowed_extension_namespaces = policy
        .extension_policy
        .allowed_extension_namespaces
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    allowed_extension_namespaces.sort_unstable();

    let bytes = serde_cbor::to_vec(&PolicyDocumentSemanticProjection {
        policy_id: &policy.policy_id,
        selected_policy_layers: effective_policy.selected_policy_layers,
        capability_class: effective_policy.capability_class,
        min_cpu_logical_cores: effective_policy.min_cpu_logical_cores,
        min_memory_bytes: effective_policy.min_memory_bytes,
        allow_container_restricted: effective_policy.allow_container_restricted,
        require_network_visibility: effective_policy.require_network_visibility,
        required_accelerator_kind: &effective_policy.required_accelerator_kind,
        required_accelerator_vendor: &effective_policy.required_accelerator_vendor,
        required_accelerator_integration: &effective_policy.required_accelerator_integration,
        min_accelerator_devices: effective_policy.min_accelerator_devices,
        layers,
        allowed_extension_namespaces,
    })
    .map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_build",
            format!("failed to encode policy-document semantic projection: {error}"),
        )
    })?;

    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn policy_pack_lock_semantic_bytes(lock: &PolicyPackLockV1) -> Result<Vec<u8>, CatalogueError> {
    #[derive(Serialize)]
    struct PolicyPackLockSemanticProjection<'a> {
        lock_id: &'a str,
        pack_id: &'a str,
        pack_version: &'a str,
        policy_id: &'a str,
        policy_summary: &'a str,
        policy_path: &'a str,
        compatibility_mode: PolicyPackLockCompatibilityModeV1,
        policy_pack_entry_semantic_hash: &'a str,
        policy_semantic_hash: &'a str,
    }

    serde_cbor::to_vec(&PolicyPackLockSemanticProjection {
        lock_id: &lock.lock_id,
        pack_id: &lock.pack_id,
        pack_version: &lock.pack_version,
        policy_id: &lock.policy_id,
        policy_summary: &lock.policy_summary,
        policy_path: &lock.policy_path,
        compatibility_mode: lock.compatibility_mode,
        policy_pack_entry_semantic_hash: &lock.policy_pack_entry_semantic_hash,
        policy_semantic_hash: &lock.policy_semantic_hash,
    })
    .map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "policy_pack_lock_build",
            format!("failed to encode policy-pack lock semantic projection: {error}"),
        )
    })
}

fn policy_pack_lock_semantic_hash_hex(lock: &PolicyPackLockV1) -> Result<String, CatalogueError> {
    let bytes = policy_pack_lock_semantic_bytes(lock)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn resolve_manifest_entry_path(
    manifest_path: &Path,
    entry_path: &str,
) -> Result<PathBuf, CatalogueError> {
    let manifest_root = manifest_path.parent().ok_or_else(|| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_path_resolve",
            format!(
                "manifest {} has no parent directory",
                manifest_path.display()
            ),
        )
    })?;
    let manifest_root = manifest_root.canonicalize().map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_path_resolve",
            format!(
                "failed to canonicalise manifest root {}: {error}",
                manifest_root.display()
            ),
        )
    })?;
    let allowed_root = manifest_root
        .parent()
        .unwrap_or(manifest_root.as_path())
        .canonicalize()
        .map_err(|error| {
            CatalogueError::new(
                CatalogueErrorCode::ManifestSelectionInvalid,
                "manifest_path_resolve",
                format!(
                    "failed to canonicalise manifest collection root {}: {error}",
                    manifest_root.display()
                ),
            )
        })?;

    let relative_path = Path::new(entry_path);
    if relative_path.is_absolute() {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_path_resolve",
            "manifest entry paths must be relative, not absolute",
        ));
    }

    let candidate = manifest_root.join(relative_path);
    let resolved = candidate.canonicalize().map_err(|error| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_path_resolve",
            format!(
                "failed to resolve manifest entry path {} relative to {}: {error}",
                entry_path,
                manifest_path.display()
            ),
        )
    })?;

    if !resolved.starts_with(&allowed_root) {
        return Err(CatalogueError::new(
            CatalogueErrorCode::ManifestSelectionInvalid,
            "manifest_path_resolve",
            format!(
                "manifest entry path {} escapes the manifest collection root {}",
                entry_path,
                allowed_root.display()
            ),
        ));
    }

    Ok(resolved)
}

fn require_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>, CatalogueError> {
    value.as_object().ok_or_else(|| {
        CatalogueError::new(
            CatalogueErrorCode::ManifestInputInvalid,
            "manifest_path_resolve",
            format!("{label} must be an object"),
        )
    })
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    message: &str,
) -> Result<(), CatalogueError> {
    for key in object.keys() {
        if !allowed
            .iter()
            .any(|allowed_key| allowed_key == &key.as_str())
        {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "manifest_path_resolve",
                format!("{message}: {key}"),
            ));
        }
    }
    Ok(())
}

fn reject_explicit_nulls(
    object: &Map<String, Value>,
    fields: &[&str],
    label: &str,
) -> Result<(), CatalogueError> {
    for field in fields {
        if object.get(*field).is_some_and(Value::is_null) {
            return Err(CatalogueError::new(
                CatalogueErrorCode::ManifestInputInvalid,
                "manifest_path_resolve",
                format!("{label} {field} must not be null"),
            ));
        }
    }
    Ok(())
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}
