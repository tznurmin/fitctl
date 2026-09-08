// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::{config, policy, service_profile};
use serde_json::Value;

pub fn load_all(policy: Value, profile: Value, pack: Value, context: Value) {
    assert_eq!(
        policy::load_policy_document_from_value(policy.clone()).unwrap(),
        policy::schema_v1::load_policy_document_from_value(policy).unwrap()
    );
    assert_eq!(
        service_profile::load_service_profile_from_value(profile.clone()).unwrap(),
        service_profile::schema_v1::load_service_profile_from_value(profile).unwrap()
    );
    assert_eq!(
        config::load_extension_pack_from_value(pack.clone()).unwrap(),
        config::schema_v1::load_extension_pack_from_value(pack).unwrap()
    );
    assert_eq!(
        config::load_invocation_context_from_value(context.clone()).unwrap(),
        config::schema_v1::load_invocation_context_from_value(context).unwrap()
    );
}
