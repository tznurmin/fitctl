// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "value_loaders/config.rs"]
mod config;
#[path = "value_loaders/policy.rs"]
mod policy;
#[path = "value_loaders/profile.rs"]
mod profile;
#[path = "value_loaders/profile_provenance.rs"]
mod profile_provenance;
#[path = "value_loaders/profile_semantics.rs"]
mod profile_semantics;
#[path = "fixtures/rust_clients/validated_value_loaders.rs"]
mod public_client;
#[path = "value_loaders/resolution.rs"]
mod resolution;
#[path = "value_loaders/support.rs"]
mod support;

#[test]
fn public_client_loads_all_four_documents() {
    public_client::load_all(
        support::policy(),
        support::profile(),
        support::pack(),
        support::context(),
    );
}
