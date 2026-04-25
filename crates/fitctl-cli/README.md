# fitctl

fitctl turns host inspection into explicit, machine-readable fit decisions.

## Inspect a live host

```bash
fitctl survey | fitctl inspect
```

```text
Summary
  Host
    Host alias: gpu-workstation-01
    Local stable identity: b6a4d2f1...91c7e840 (machine_id via etc_machine_id)

  Collection
    Collection mode: live
    Privilege level: limited

  Core
    CPU: AMD Ryzen Threadripper PRO 5975WX; x86_64; 64 logical cores; 32 physical cores
    Memory total: 256.00 GiB (274877906944 bytes)
    Storage: 6 block devices; classes solid_state=6
    Network: 3 interfaces; virtuality physical 2, virtual 1; kinds ethernet=2, loopback=1; 12 addresses; families ipv4, ipv6; default routes ipv4, ipv6; carrier-up physical 2/2; max 10000 Mbps

  Accelerators
    Observed GPUs: 2
    GPU 0000:65:00.0: NVIDIA RTX A6000; driver nvidia; operable
    GPU 0000:b3:00.0: NVIDIA RTX A6000; driver nvidia; operable
```

In the example above, `fitctl survey` emits a survey artifact. `fitctl inspect` renders supported
`fitctl` artifacts as structured reports.

## Make a fit decision

Use `fitctl` to decide whether a host fits a workload under a given policy.

Run `fitctl survey` to collect local facts, `fitctl contract` to derive the host claim that policy
allows, and `fitctl validate` to produce the fit decision. Each step emits a typed JSON artifact
that `fitctl inspect` can render and automation can consume unchanged.

The example below uses bundled fixture, policy, and service profile files from a checkout of the
[fitctl repository](https://github.com/tznurmin/fitctl) so the rendered decision is stable.

```bash
fitctl survey --fixture linux-bare-metal-like-v1 > host.survey.json

fitctl contract \
  --survey host.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > host.contract.json

fitctl validate \
  --contract host.contract.json \
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

## Automate from the same artifact

The validation artifact is already the automation interface:

```bash
jq -r '.report.verdict' validation.json
jq -r '.report.primary_reason_code' validation.json
```

```text
fit
requirements_satisfied
```

When a decision depends on live runtime conditions, collect `state` and pass `--state` to
`fitctl validate`. This is typically required for accelerator visibility, allocatable memory, and
other runtime-only detail.

## Core workflow commands and artifacts

| Command | Produces | Purpose |
|---|---|---|
| `fitctl survey` | `host-survey.v2` | Observed local host facts |
| `fitctl contract` | `host-contract.v2` | Policy-shaped host claim |
| `fitctl state` | `host-state.v2` | Current runtime-sensitive facts |
| `fitctl validate` | `validation-report.v2` | Verdict, posture, and reason codes |
| `fitctl classify` | `fitctl.batch-classification-report.v3` | Batch comparison |

The artifact you inspect is the artifact automation reads.

Run `fitctl --help` for the full command surface, including inspection, diffing, redaction,
signing, verification, export, completion, and advanced configuration commands.

## Compare hosts in batch

Create a batch report with `fitctl classify`, then render it as a matrix:

```bash
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

## Install

From crates.io:

```bash
cargo install fitctl --locked
```

## Build from source

```bash
cargo build --workspace
./target/debug/fitctl --help
cargo install --path crates/fitctl-cli --locked
```

## Documentation

- [Configuration](https://github.com/tznurmin/fitctl/blob/v0.3.0/docs/configuration.md) - policies and service profiles
- [Contracts](https://github.com/tznurmin/fitctl/blob/v0.3.0/docs/contracts.md) - contract derivation from survey evidence and policy
- [Validation](https://github.com/tznurmin/fitctl/blob/v0.3.0/docs/validation.md) - validation, batch comparison, and fit decisions
- [Accelerators](https://github.com/tznurmin/fitctl/blob/v0.3.0/docs/accelerators.md) - accelerator inventory, CUDA runtime detail, and the `survey` versus `state` split
- [Artifacts](https://github.com/tznurmin/fitctl/blob/v0.3.0/docs/artifacts.md) - survey, contract, state, and validation-report artifacts

Version history and release notes: [GitHub Releases](https://github.com/tznurmin/fitctl/releases)

## License

[Apache-2.0](https://github.com/tznurmin/fitctl/blob/v0.3.0/LICENSE)
