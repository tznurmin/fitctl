// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Small validation helpers for explanation links carried by derived claims.

use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};

pub fn validate_explanation_links(
    rule_ids: &[String],
    evidence_refs: &[String],
) -> Result<(), ContractDerivationError> {
    if rule_ids.is_empty()
        || evidence_refs.is_empty()
        || rule_ids.iter().any(|rule_id| rule_id.trim().is_empty())
        || evidence_refs
            .iter()
            .any(|evidence_ref| evidence_ref.trim().is_empty())
    {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyExplanationMissing,
            "policy_explain",
            "derived contract claims must carry rule ids and evidence refs",
        ));
    }

    Ok(())
}
