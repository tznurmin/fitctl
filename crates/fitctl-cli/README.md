# fitctl

fitctl is a command-line tool for producing host-fit artifacts and returning failure exit codes when
validation rejects a host.

It records observed host facts, derives policy-shaped host contracts, captures runtime state when
required, and validates contracts against workload profiles.

The core workflow emits typed JSON artifacts. `fitctl inspect` prints structured text views for
supported artifacts, and automation reads the JSON directly.

Use `--fail-on-unfit` or `--require-fit` when validation should control the process exit status.
The validation report is written to stdout, and the exit status reflects the gate result.

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

In the example above, `fitctl survey` emits a survey artifact and pipes it to `fitctl inspect`.
`fitctl inspect` prints a structured text view of supported `fitctl` artifacts.

## Make a fit decision

Run `fitctl survey` to collect local facts, `fitctl contract` to derive the host claim that policy
allows, and `fitctl validate` to produce the fit decision. Each step emits a typed JSON artifact.
`fitctl inspect` can print a text view, and automation can read the same JSON directly.

The example below uses bundled fixture, policy, and service profile files from a checkout of the
[fitctl repository](https://github.com/tznurmin/fitctl) so the example output is stable.

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
`fitctl validate`. This is typically required for accelerator visibility, allocatable memory,
checked path capacity, and other runtime-only detail.

## Collect runtime health evidence

Runtime health collectors are opt-in. This example selects every `0.6.0` runtime evidence class;
omit collectors and probes the workload does not need:

```bash
fitctl state --live \
  --collect thermal \
  --collect memory-reliability \
  --collect gpu-reliability \
  --collect cuda-runtime \
  --path-check model-cache=/var/lib/model-cache \
  --probe-path-health model-cache \
  --thermal-provider-config site-thermal-providers.json \
  > host.state.json

fitctl inspect --input host.state.json
```

The resulting state can carry normalized thermal readings, memory and GPU reliability evidence,
CUDA runtime state, and storage health for checked paths. Service profiles can require these facts
during validation.

For an out-of-band collector, produce target-bound thermal evidence without treating the collector
host as the evidence target:

```bash
fitctl thermal collect \
  --thermal-provider-config site-thermal-providers.json \
  --require-target-host-id host.compute-01 \
  --out host.thermal.json

fitctl thermal profile init \
  --thermal-evidence host.thermal.json \
  --profile-id thermal_safe_v1 \
  --margin-mc 10000 \
  --out thermal-safe.profile.json
```

The generated profile is a reviewable starting point. Confirm its thresholds before using it as an
admission gate.

## Share a redacted artifact

```bash
fitctl redact --profile external --input host.state.json > host.external.json
```

`auditor` and `external` apply typed redaction to core provenance and supported extension data;
unknown populated extension sections and invalid closed categories fail closed. State-local
identity metadata is omitted and flexible engine provenance is replaced. Inspect every result
before sharing it. Semantic hashes remain linkable, and redacted configuration or decision bundles
remain retained disclosures rather than anonymity boundaries.

## Use Installed Config

Installed binaries include bundled configuration files. Export them when you are not working from a
repository checkout:

```bash
fitctl config export --out-dir fitctl-config
```

The exported files keep the same `configs/...` paths used in the examples.

## Core workflow commands and artifacts

| Command | Produces | Purpose |
|---|---|---|
| `fitctl survey` | `host-survey.v2` | Observed local host facts |
| `fitctl contract` | `host-contract.v2` | Policy-shaped host claim |
| `fitctl state` | `host-state.v2` | Current runtime-sensitive facts |
| `fitctl thermal collect` | `fitctl.thermal-evidence.v1` | Target-bound thermal evidence |
| `fitctl validate` | `validation-report.v2` | Verdict, posture, and reason codes |
| `fitctl classify` | `fitctl.batch-classification-report.v3` | Batch comparison |
| `fitctl config` | configuration files | Bundled config list and export |

The artifact you inspect is the artifact automation reads.

Run `fitctl --help` for the full command surface, including inspection, diffing, redaction,
signing, verification, export, completion, and advanced configuration commands.

## Compare hosts in batch

Create explicit CPU and GPU contracts, then print a batch report as a matrix:

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

- [Configuration](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/configuration.md) - policies and service profiles
- [Contracts](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/contracts.md) - contract derivation from survey evidence and policy
- [Validation](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/validation.md) - validation, batch comparison, and fit decisions
- [Accelerators](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/accelerators.md) - accelerator inventory, CUDA runtime detail, and the `survey` versus `state` split
- [Artifacts](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/artifacts.md) - survey, contract, state, thermal evidence, and validation-report artifacts
- [Installed Configuration](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/installed-config.md) - bundled config listing and export
- [Workload Reports](https://github.com/tznurmin/fitctl/blob/v0.6.0/docs/workload-reports.md) - attaching fit artifacts to workload-run reports

Version history and release notes: [GitHub Releases](https://github.com/tznurmin/fitctl/releases)

## License

[Apache-2.0](https://github.com/tznurmin/fitctl/blob/v0.6.0/LICENSE)
