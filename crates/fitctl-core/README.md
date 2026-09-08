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

## Installation

Add the library crate to your project:

```toml
[dependencies]
fitctl-core = "0.8.0"
```

## In-memory inputs

The API validates owned `serde_json::Value` inputs without temporary files:

- `policy::load_policy_document_from_value`
- `service_profile::load_service_profile_from_value`
- `config::load_extension_pack_from_value`
- `config::load_invocation_context_from_value`

These use the same raw-input, typed and semantic checks as their file-loading counterparts,
including explicit-null rejection. Use the specialized service-profile loader for supplied
profiles; generic artifact-record decoding does not apply all profile ingress checks.

## Compatibility

`0.8.0` replaces the CBOR encoder with `minicbor` and uses `fitctl.semantic_cbor.v2`.
Regenerate semantic hashes, policy locks, derived reference chains and signatures together;
old signatures do not verify under the new encoding. JSON remains the artifact interchange format.

Path link capabilities and link pairs add optional per-root `cleanup` evidence. Exhaustive Rust
struct literals must supply the field (`None` when absent). Missing cleanup evidence is not proof
that files were removed. Existing hardware-sensor fields remain part of the public Rust structs.

## Related crate

If you want the command-line tool, install [`fitctl`](https://crates.io/crates/fitctl) instead.
