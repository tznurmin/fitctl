# fitctl-core

`fitctl-core` is the library crate behind `fitctl`.

Compare Linux hosts against service profiles and produce machine-readable fit decisions.

## What it provides

- typed artifacts for survey, contract, state, thermal evidence, and validation results
- host survey collection and replay
- policy-shaped contract derivation
- runtime health evidence for memory, GPUs, storage paths, and provider-backed temperatures
- service-profile validation against declared host and runtime requirements
- batch classification across several contracts and service profiles

Opt-in hardware sensor collection provides typed voltage, current, power, fan-speed, energy and
humidity evidence from lm-sensors. These are observations, not new health requirements.

In `0.7.0`, exhaustive Rust literals for `HostStateCoreV1`, `CollectedHostStateSnapshotV1`, and
`HostStateFixtureSnapshotV1` must supply `hardware_sensor_resources` (`None` when absent).

## Installation

Add the library crate to your project:

```toml
[dependencies]
fitctl-core = "0.7.0"
```

## Related crate

If you want the command-line tool, install [`fitctl`](https://crates.io/crates/fitctl) instead.
