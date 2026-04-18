// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Config-bundle artifact for one local selected advanced run configuration.

use serde::{Deserialize, Serialize};

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::config::ResolvedConfigV1;
use crate::policy::PolicyDocumentV1;
use crate::verify::TrustPolicyV1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Local reusable bundle around selected advanced-run configuration.
pub struct ConfigBundleV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub config_bundle_basis: ConfigBundleBasisV1,
    pub config_bundle: ConfigBundlePayloadV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen identifiers for the embedded selected config sections.
pub struct ConfigBundleBasisV1 {
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_policy_id: Option<String>,
    pub resolved_config_semantic_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Embedded config documents carried together for one reusable advanced run.
pub struct ConfigBundlePayloadV1 {
    pub policy: PolicyDocumentV1,
    pub resolved_config: ResolvedConfigV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_profile: Option<ServiceProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_policy: Option<TrustPolicyV1>,
}
