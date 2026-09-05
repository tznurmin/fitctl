# Configuration

Configuration is expressed as typed JSON files. Bundled examples in this repository are under
[configs](../configs).

Installed binaries can export the same bundled configuration set:

```bash
fitctl config export --out-dir fitctl-config
```

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

Policies may also carry `display_name` and `short_display_name` fields for `inspect` and matrix
views. These are presentation labels, not selection identity.

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

A state-aware service profile may declare `required_paths`. Each entry names a path id, such as
`model-cache`, `scratch`, or `output`, and may require minimum available bytes, accepted media
classes, accepted durability classes, filesystem types, accepted filesystem UUIDs, accepted
partition UUIDs, accepted persistent device links, or explicit link capabilities. Validation checks
those requirements against `state` path resources collected with matching
`--path-check <id>=<path>` inputs. Link capability requirements need matching
`--probe-path-links <id>` evidence.

Profiles may also declare `path_relationships` and `required_path_link_pairs`.
`path_relationships` compare two checked path ids and can require distinct storage identities,
such as distinct filesystem UUIDs. `required_path_link_pairs` checks link or copy capability from
one checked path id to another and requires matching `--probe-path-link-pair <from-id>:<to-id>`
evidence.

Storage identity requirements are low-level checks. A profile can say "this path must be mounted
from one of these UUIDs or persistent device links", but fitctl does not decide whether that
identity is scratch, data, cache, or another project-specific role.

`fitctl storage profile init` can generate a reviewable service-profile skeleton from observed
checked-path evidence. Use it to avoid manual transcription of UUIDs, media classes, filesystem
types, and link capabilities:

```bash
fitctl storage profile init \
  --path scratch=/scratch/workload \
  --path output=/data/workload-output \
  --probe-path-links scratch \
  --min-available-bytes scratch=107374182400 \
  --out workload-storage.profile.json
```

The generated file is configuration input for review and version control. It does not assign
project-specific storage roles by itself.

State-aware profiles may also declare `required_thermal_sensors`. Each entry names a thermal
requirement, selects readings by provider id, sensor id, sensor alias, or normalized sensor role,
and sets a maximum temperature in millidegrees Celsius. Provider configs may map raw sensor labels
to site-local aliases so profiles can avoid motherboard-specific labels where possible.

`fitctl thermal profile init` can generate a reviewable thermal service-profile skeleton from
thermal evidence in either a state artifact or a standalone thermal-evidence artifact:

```bash
fitctl thermal profile init \
  --state host.state.json \
  --profile-id thermal_safe_v1 \
  --margin-mc 10000 \
  --out thermal-safe.profile.json
```

```bash
fitctl thermal profile init \
  --thermal-evidence host.thermal.json \
  --profile-id thermal_safe_v1 \
  --margin-mc 10000 \
  --out thermal-safe.profile.json
```

The generated thresholds are observed temperatures plus the supplied margin. Review them before
using the profile as an admission gate.

Service profiles may also carry `display_name` and `short_display_name` fields for `inspect` and
matrix views. These are presentation labels, not selection identity.

Examples:

- [general_compute_contract_only.v2.json](../configs/service_profiles/general_compute_contract_only.v2.json) - requires general compute
- [gpu_preferred_with_general_compute_fallback_contract_only.v2.json](../configs/service_profiles/gpu_preferred_with_general_compute_fallback_contract_only.v2.json) - prefers GPU, allows general-compute fallback
- [gpu_two_required_contract_only.v2.json](../configs/service_profiles/gpu_two_required_contract_only.v2.json) - requires two policy-scoped GPUs
- [local_image_generation_storage_state_required.v2.json](../configs/service_profiles/local_image_generation_storage_state_required.v2.json) - requires state-backed CPU, memory, and named storage path capacity
- [local_image_generation_cuda_state_required.v2.json](../configs/service_profiles/local_image_generation_cuda_state_required.v2.json) - requires GPU inventory, CUDA runtime state, and named storage path capacity

[Validation](./validation.md) covers the fit decision flow.

## How they fit together

A `survey` records observed local facts.

A `policy` decides what contract may be derived from those facts.

A `service profile` checks whether that contract satisfies a workload.

When the decision also depends on live runtime conditions, validation adds `state`, but the
configuration split stays the same: policy shapes the claim, and the service profile tests it.
