# Configuration

Configuration is expressed as typed JSON files. Bundled examples in this repository are under [configs](../configs).

The core inputs are [policies](../configs/policy) and
[service profiles](../configs/service_profiles).

A policy defines what a contract may claim from survey evidence. A service profile defines what a
workload expects to be available from that contract during validation.

## Policy

A `policy` controls contract derivation from a `survey`. It decides what the host may claim from
survey evidence: it defines the capability class, the thresholds and
admissibility constraints for that claim, and any extension namespace allowlist used during
derivation.

Policies may also carry human-facing `display_name` and `short_display_name` labels for inspect
and matrix views. Those labels are presentation metadata, not selection identity.

Examples:

- [general_compute_default.v1.json](../configs/policy/general_compute_default.v1.json) - general compute claim
- [gpu_compute_default.v1.json](../configs/policy/gpu_compute_default.v1.json) - GPU-capable claim

[Contracts](./contracts.md) covers contract derivation from survey evidence and policy.

## Service profile

A service profile controls validation against a role. It defines what the workload requires,
prefers, or forbids to be available from that contract during validation.

Service profiles may also carry human-facing `display_name` and `short_display_name` labels for
inspect and matrix views. Those labels are presentation metadata, not selection identity.

Examples:

- [general_compute_contract_only.v2.json](../configs/service_profiles/general_compute_contract_only.v2.json) - requires general compute
- [gpu_preferred_with_general_compute_fallback_contract_only.v2.json](../configs/service_profiles/gpu_preferred_with_general_compute_fallback_contract_only.v2.json) - prefers GPU, allows general compute fallback

[Validation](./validation.md) covers the fit decision flow.
