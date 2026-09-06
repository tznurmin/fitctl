// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::state_v1::HostStateV1;
use fitctl_core::artifacts::validation_v1::validate_host_state;

#[test]
fn hardware_sensor_optional_section_accepts_typed_voltage() {
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut value = serde_json::to_value(state).unwrap();
    let target =
        serde_json::json!({"target_kind":"current_host", "collection_path":"local_process"});
    value["state"]["core_state"]["hardware_sensor_resources"] = serde_json::json!({
        "observed_at":common::FIXED_TIMESTAMP,
        "collector_host":{"host_alias":"fixture-host"},
        "providers":[{"provider_id":"local-lm-sensors", "provider_kind":"lm_sensors_json",
            "outcome":"success", "evidence_target":target, "observed_at":common::FIXED_TIMESTAMP}],
        "readings":[{"sensor_id":"fixture-voltage", "provider_id":"local-lm-sensors",
            "chip_id":"fixture-chip", "channel_id":"in0_input", "raw_label":"voltage",
            "evidence_target":target, "quantity":"voltage", "unit":"microvolts",
            "measurement_kind":"input", "value":12_000_000, "value_state":"observed",
            "observed_at":common::FIXED_TIMESTAMP, "limits":[], "flags":[]}]
    });
    let typed: HostStateV1 =
        serde_json::from_value(value).expect("typed sensor section must decode");
    validate_host_state(&typed).expect("typed voltage must validate");
}
