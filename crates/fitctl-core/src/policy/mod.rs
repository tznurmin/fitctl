// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Policy schemas and layering rules for capability derivation.
//!
//! Policies shape what a host may promise from observed evidence; they are applied during contract
//! derivation rather than during service-profile validation.

pub mod capability_classes_v1;
pub mod explanation_v1;
pub mod layering_v1;
pub mod schema_v1;

pub use layering_v1::{merge_policy_document_v1, EffectivePolicyV1};
pub use schema_v1::{
    load_policy_document_from_path, PolicyDocumentV1, PolicyExtensionPolicyV1, PolicyLayerKindV1,
    PolicyLayerV1, PolicyRulesOverrideV1,
};
