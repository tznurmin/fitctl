// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed policy-document schema and validated loading facade.

use crate::survey::{AcceleratorIntegrationV1, AcceleratorKindV1};
use serde::{Deserialize, Serialize};

pub const POLICY_DOCUMENT_SCHEMA_ID: &str = "fitctl.policy.document.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Policy shapes what a surveyed host may promise.
///
/// The same survey can yield different contracts under different policies.
pub struct PolicyDocumentV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_display_name: Option<String>,
    pub layers: Vec<PolicyLayerV1>,
    #[serde(default)]
    pub extension_policy: PolicyExtensionPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One precedence-ranked override layer inside a policy document.
pub struct PolicyLayerV1 {
    pub layer_id: String,
    pub kind: PolicyLayerKindV1,
    pub rules: PolicyRulesOverrideV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Higher-precedence kinds override lower ones when both set the same rule.
pub enum PolicyLayerKindV1 {
    BuiltInDefaults,
    Site,
    HostClass,
    HostLocal,
    ValidationSimulation,
}

impl PolicyLayerKindV1 {
    pub fn precedence_rank(self) -> u8 {
        match self {
            Self::BuiltInDefaults => 0,
            Self::Site => 1,
            Self::HostClass => 2,
            Self::HostLocal => 3,
            Self::ValidationSimulation => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Controls whether confirmed in-scope accelerators are enough for the claim, or whether the
/// entire policy-scoped accelerator inventory must be complete.
pub enum PolicyScopedAcceleratorInventoryModeV1 {
    ConfirmedSubsetSufficient,
    CompleteRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Sparse override set.
///
/// Omitted fields intentionally inherit from lower-precedence layers.
pub struct PolicyRulesOverrideV1 {
    pub capability_class: Option<String>,
    pub min_cpu_logical_cores: Option<u32>,
    pub min_memory_bytes: Option<u64>,
    pub allow_container_restricted: Option<bool>,
    pub require_network_visibility: Option<bool>,
    pub required_accelerator_kind: Option<AcceleratorKindV1>,
    pub required_accelerator_vendor: Option<String>,
    pub required_accelerator_integration: Option<AcceleratorIntegrationV1>,
    pub min_accelerator_devices: Option<u32>,
    pub policy_scoped_accelerator_inventory_mode: Option<PolicyScopedAcceleratorInventoryModeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Namespace allowlist for extension-derived contract content.
pub struct PolicyExtensionPolicyV1 {
    #[serde(default)]
    pub allowed_extension_namespaces: Vec<String>,
}

pub use super::load_v1::{load_policy_document_from_path, load_policy_document_from_value};
pub(crate) use super::validation_v1::validate_policy_document;
