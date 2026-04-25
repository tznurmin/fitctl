# Configuration

Configuration is expressed as typed JSON files. Bundled examples in this repository are under
[configs](../configs).

The two core configuration inputs are:

- `policy` - defines what a host may claim from survey evidence (shapes the contract)
- `service profile` - defines what a workload requires, prefers, or forbids during validation (shapes the fit decision)

```bash
fitctl contract --survey <survey.json> --policy <policy.json> > contract.json
fitctl validate --contract <contract.json> --profile <profile.json> > validation.json
```

## Policies

A `policy` controls contract derivation from a `survey`.

It determines:

- the capability class the host may claim
- the thresholds and admissibility rules for that claim
- any extension namespace allowlist used during derivation

Policies may also carry human-facing `display_name` and `short_display_name` fields for `inspect`
and matrix views. These are presentation labels, not selection identity.

A policy-scoped accelerator inventory is the subset of observed accelerators that the selected
policy allows the host to claim.

Accelerator policies may further narrow the claim to a policy-scoped accelerator inventory, for
example by vendor or integration class. A stricter policy may also require that scoped inventory to
be complete before the claim is admitted.

Examples:

- [general_compute_default.v1.json](../configs/policy/general_compute_default.v1.json) - general-compute claim
- [gpu_compute_default.v1.json](../configs/policy/gpu_compute_default.v1.json) - GPU-capable claim
- [nvidia_gpu_default.v1.json](../configs/policy/nvidia_gpu_default.v1.json) - NVIDIA-scoped GPU claim
- [nvidia_gpu_complete_required.v1.json](../configs/policy/nvidia_gpu_complete_required.v1.json) - NVIDIA-scoped claim with strict scoped completeness

[Contracts](./contracts.md) covers contract derivation from survey evidence and policy.

## Service profiles

A `service profile` controls validation against a workload role.

It determines what the workload:

- requires
- prefers
- forbids
- may accept through an allowed fallback path

A service profile may also declare a minimum policy-scoped accelerator count in principle.
Runtime availability remains separate and belongs to `state`.

Service profiles may also carry human-facing `display_name` and `short_display_name` fields for
`inspect` and matrix views. These are presentation labels, not selection identity.

Examples:

- [general_compute_contract_only.v2.json](../configs/service_profiles/general_compute_contract_only.v2.json) - requires general compute
- [gpu_preferred_with_general_compute_fallback_contract_only.v2.json](../configs/service_profiles/gpu_preferred_with_general_compute_fallback_contract_only.v2.json) - prefers GPU, allows general-compute fallback
- [gpu_two_required_contract_only.v2.json](../configs/service_profiles/gpu_two_required_contract_only.v2.json) - requires two policy-scoped GPUs

[Validation](./validation.md) covers the fit decision flow.

## How they fit together

A `survey` records observed local facts.

A `policy` decides what contract may be derived from those facts.

A `service profile` checks whether that contract is good enough for a workload.

When the decision also depends on live runtime conditions, validation adds `state`, but the
configuration split stays the same: policy shapes the claim, and the service profile tests it.
