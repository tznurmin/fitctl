# Configuration

Fitctl uses small typed configuration files. For the core `survey -> contract -> validate` flow, the two main configuration types are policy and service profile.

A policy defines what a host may claim from survey evidence. A service profile defines what a role requires from a host.

## Policy

Use a `policy` when deriving a host `contract` from a `survey`. The `policy` shapes the host claim derived from survey evidence: it defines the capability class, the thresholds and admissibility constraints for that claim, and any extension namespace allowlist used during derivation.

Bundled examples live under `configs/policy/`. For example, `general_compute_default.v1.json` defines a general compute baseline, while `gpu_compute_default.v1.json` requires GPU capability.

## Service profile

Use a service profile when validating whether a host contract fits a role. The service profile defines the required capabilities for that role and may also express preferred capabilities, topology constraints, or allowed fallback paths.

Bundled examples live under [configs/service_profiles](../configs/service_profiles/). For example, `general_compute_contract_only.v1.json` requires a general compute baseline, while `gpu_preferred_with_general_compute_fallback.v1.json` prefers GPU capability but allows a general compute fallback.

## Bundled configuration layout

The most relevant bundled configuration directories under `configs/` are:

- `configs/policy/` — policies for contract derivation
- `configs/service_profiles/` — service profiles for direct validation

Most users only need `configs/policy/` and `configs/service_profiles/`. The stable core path is still `survey -> contract -> validate`.
