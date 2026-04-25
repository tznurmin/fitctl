# Validation

Validation checks a host `contract` against a `service profile` and emits a typed JSON validation
report.

A `contract` is the policy-shaped claim derived from a `survey`. A `service profile` defines what a
workload requires, prefers, or forbids. When the decision also depends on live runtime conditions,
validation uses `state`.

The same validation artifact that `fitctl inspect` renders is the one automation reads unchanged.

| Mode | Use when |
|---|---|
| `contract_only` | The contract claim is enough to decide fit |
| `state_required` | Live runtime evidence is required and must be fresh |
| `state_advisory` | Live runtime evidence should be reported, but missing or stale state must not be treated as proof |

## Validate a contract

```bash
fitctl validate --contract <contract.json> --profile <profile.json> > validation.json
```

Inspect the result:

```bash
fitctl inspect --input validation.json
```

Read the decision directly in automation:

```bash
jq -r '.report.verdict' validation.json
jq -r '.report.primary_reason_code' validation.json
```

[Contracts](./contracts.md) covers contract derivation. [Configuration](./configuration.md) covers
policies and service profiles.

Examples are under [configs/service_profiles](../configs/service_profiles),
[fixtures/host_survey](../fixtures/host_survey), and [fixtures/host_state](../fixtures/host_state).

## State-aware validation

Add `state` when the decision depends on live runtime conditions, such as:

- current accelerator visibility
- allocatable memory
- runtime freshness requirements

State-aware validation should also set the validation mode, validation time, and freshness bound
explicitly:

```bash
fitctl validate \
  --contract <contract.json> \
  --profile <profile.json> \
  --state <state.json> \
  --validation-mode state_required \
  --validated-at <timestamp> \
  --max-state-age <duration> \
  > validation.json
```

See `fitctl --help validate` for more details.

## Default flow

This example uses a bundled survey fixture so the inspect output is stable.

```bash
fitctl survey --fixture linux-bare-metal-like-v1 > survey.json

fitctl contract \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > contract.json

fitctl validate \
  --contract contract.json \
  --profile configs/service_profiles/general_compute_contract_only.v2.json \
  > validation.json

fitctl inspect --input validation.json
```

```text
Summary
  Validation mode: contract_only
  Verdict: fit
  Operator posture: proceed
  Primary reason code: requirements_satisfied
```

If you do not need to keep the intermediate contract artifact, validate directly from a survey and
policy:

```bash
fitctl validate \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  --profile configs/service_profiles/general_compute_contract_only.v2.json \
  > validation.json
```

## Policy-scoped accelerator floors

A service profile may require a minimum policy-scoped accelerator count in principle through
`core_requirements.min_policy_scoped_accelerators`.

In contract-only validation, that floor is checked against the confirmed policy-scoped accelerator
count in the contract summary. If the contract cannot expose that count, the result is
`indeterminate`.

That static floor remains separate from live runtime availability. A contract may confirm two
in-scope accelerators while runtime validation still fails because fewer qualifying devices are
currently visible or usable. The full accelerator inventory does not replace or change that floor.

## CUDA runtime admission

See [Policy-scoped accelerator floors](#policy-scoped-accelerator-floors) for the static
accelerator-count requirement reused by runtime admission.

When CUDA runtime admission is enabled, the same
`core_requirements.min_policy_scoped_accelerators` floor is reused as the current
qualifying-device count.

Profiles can narrow which CUDA devices qualify at runtime:

- `extension_requirements.fitctl.runtime.cuda.minimum_device_allocatable_memory_bytes` counts
  only devices that meet the per-device allocatable-memory floor
- `extension_requirements.fitctl.runtime.cuda.minimum_qualifying_device_aggregate_allocatable_memory_bytes`
  sums allocatable memory only across devices that already satisfy that per-device floor
- `extension_requirements.fitctl.runtime.cuda.minimum_allocatable_memory_bytes` remains the
  total CUDA allocatable memory across all visible runtime devices

The qualifying-device aggregate threshold does not replace the older total CUDA aggregate
threshold. They measure different sets.

The bundled CUDA examples use the extension namespace `fitctl.runtime.cuda`.

## State-aware CUDA validation

Use the same CUDA runtime extension settings during survey, contract derivation, and state
collection so the contract, runtime observation, and validation path stay aligned:

```bash
fitctl survey \
  --fixture linux-gpu-workstation-like-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.contract.json

fitctl state \
  --fixture linux-gpu-workstation-like-cuda-runtime-fit-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.state.json

fitctl validate \
  --contract gpu.contract.json \
  --profile configs/service_profiles/general_compute_cuda_runtime_allocatable_memory_required.v2.json \
  --state gpu.state.json \
  --validation-mode state_required \
  --validated-at 2025-04-21T14:37:19Z \
  > validation.json

fitctl inspect --input validation.json
```

For multi-GPU runtime admission, derive a GPU policy-scoped contract and collect matching
multi-GPU state. The profile keeps the same static scoped-GPU floor and adds the optional
per-device CUDA threshold:

```bash
fitctl survey \
  --fixture linux-gpu-dual-numa-like-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy configs/policy/nvidia_gpu_default.v1.json \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.contract.json

fitctl state \
  --fixture linux-gpu-dual-numa-like-cuda-runtime-fit-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > gpu.state.json

fitctl validate \
  --contract gpu.contract.json \
  --profile configs/service_profiles/gpu_two_required_cuda_runtime_per_device_memory_required.v2.json \
  --state gpu.state.json \
  --validation-mode state_required \
  --validated-at 2025-04-21T14:37:19Z \
  > validation.json

fitctl inspect --input validation.json
```

This does not introduce a second GPU-count field. It reuses
`min_policy_scoped_accelerators` and changes only which CUDA devices qualify now.

## Batch comparison

Use `fitctl classify` to check several contracts against several service profiles. The example
below first derives one general-compute contract and one GPU-compute contract so the matrix is
defined by the contract claims, not by existing local filenames:

```bash
fitctl survey --fixture linux-bare-metal-like-v1 > cpu.survey.json

fitctl contract \
  --survey cpu.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > cpu.contract.json

fitctl survey --fixture linux-gpu-workstation-like-v1 > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy configs/policy/gpu_compute_default.v1.json \
  > gpu.contract.json

fitctl classify \
  --contract cpu.contract.json \
  --contract gpu.contract.json \
  --profile configs/service_profiles/general_compute_no_gpu_contract_only.v2.json \
  --profile configs/service_profiles/gpu_preferred_with_general_compute_fallback_contract_only.v2.json \
  --profile configs/service_profiles/gpu_required_contract_only.v2.json \
  > batch.json

fitctl inspect --input batch.json --view matrix
```

```text
Profile                     | Host        | Contract                | Verdict
----------------------------+-------------+-------------------------+---------------------
CPU only                    | cpu-host-01 | General compute default | fit
CPU only                    | gpu-host-01 | GPU compute default     | unfit
GPU preferred, CPU fallback | cpu-host-01 | General compute default | fit_with_degradation
GPU preferred, CPU fallback | gpu-host-01 | GPU compute default     | fit
GPU required                | cpu-host-01 | General compute default | unfit
GPU required                | gpu-host-01 | GPU compute default     | fit
```

`fitctl classify` emits a typed `fitctl.batch-classification-report.v3` artifact.
`fitctl inspect --view matrix` renders that report as a shortlist table.

For state-aware shortlist decisions, derive a matching CUDA contract and state artifact, then add
state input and freshness bounds explicitly:

```bash
fitctl survey \
  --fixture linux-gpu-workstation-like-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > cuda.survey.json

fitctl contract \
  --survey cuda.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > cuda.contract.json

fitctl state \
  --fixture linux-gpu-workstation-like-cuda-runtime-fit-v1 \
  --extension-pack configs/extensions/fitctl_runtime_cuda.v1.json \
  --enable-extension fitctl.runtime.cuda \
  > cuda.state.json

fitctl classify \
  --contract cuda.contract.json \
  --state cuda.state.json \
  --profile configs/service_profiles/general_compute_cuda_runtime_allocatable_memory_required.v2.json \
  --validation-mode state_required \
  --max-state-age 1h \
  --validated-at 2025-04-21T14:37:19Z \
  > cuda.batch.json

fitctl inspect --input cuda.batch.json
```

```text
Summary
  Validation mode: state_required
  Max state age: 1h
  Validated at: 2025-04-21 14:37:19 UTC
  Contracts: contract-linux-gpu-workstation-like-v1-general-compute-default-v1
  Service profiles: service-profile-general-compute-cuda-runtime-allocatable-memory-required-v1
  State lineage: General compute default -> state-li...e-fit-v1 (fresh, observed 2025-04-21 14:37:19 UTC, via host_alias_fallback)
  Batch classification rows: 1
  Fit rows: 1
  Fit-with-degradation rows: 0
  Unfit rows: 0
  Indeterminate rows: 0
  Operator posture counts: proceed 1; proceed_with_degradation 0; stop 0; hold_for_evidence 0
  Primary reason tally: requirements_satisfied=1
  Row summaries: contract-linux-gpu-workstation-like-v1-general-compute-default-v1 -> service-profile-general-compute-cuda-runtime-allocatable-memory-required-v1: fit (requirements_satisfied)
```

The summary includes state lineage for the ordered contract so it is clear which row used fresh
runtime evidence.

## Verdicts

- `fit` - the host satisfies the profile
- `fit_with_degradation` - the profile fits through an allowed fallback path
- `unfit` - the host does not satisfy the profile
- `indeterminate` - fitctl cannot make a safe decision from the available inputs

A degradation path does not bypass other hard requirements. If network, topology,
accelerator-locality, or policy-scoped accelerator-count requirements still fail, the result
remains `unfit`.

## Coverage view

Use grouped field coverage for survey, contract, or state artifacts when needed:

```bash
fitctl inspect --input <survey-or-contract-or-state.json> --view coverage
```
