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

## Installation

Add the library crate to your project:

```toml
[dependencies]
fitctl-core = "0.6.0"
```

## Related crate

If you want the command-line tool, install [`fitctl`](https://crates.io/crates/fitctl) instead.
