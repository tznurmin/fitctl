// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::config::built_in_config_assets_v1;

use crate::common;

#[test]
fn bundled_config_assets_match_public_configs() {
    let assets = built_in_config_assets_v1();
    assert!(
        !assets.is_empty(),
        "bundled config assets must not be empty"
    );

    for asset in assets {
        let public_path = common::repo_root().join(asset.relative_path);
        let expected = std::fs::read_to_string(&public_path)
            .unwrap_or_else(|error| panic!("{} should read: {error}", public_path.display()));
        assert_eq!(
            asset.contents, expected,
            "embedded config asset {} drifted from {}",
            asset.id, asset.relative_path
        );
    }
}
