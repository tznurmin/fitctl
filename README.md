# fitctl

Survey a live host, keep the results as typed JSON artifacts, and use them to decide whether workloads fit.

### Quick live summary

```bash
fitctl survey | fitctl inspect
```

```text
Summary
  Host alias: fithost
  Collection mode: live
  CPU: observed; x86_64; 24 logical cores; 12 physical cores
  Memory total: observed; 94.19 GiB
  Storage: observed; 11 block devices; classes loop=8, solid_state=3
  Network: observed; 2 interfaces; kinds ethernet=1, loopback=1
  Graphics / accelerators: observed; 1 devices; kinds gpu; vendors nvidia
```

### Make decisions from recorded evidence

Create a survey artifact from the live host:

```bash
fitctl survey > survey.json
```

Or use a demo fixture:

```bash
fitctl survey --fixture linux-bare-metal-like-v1 > survey.json
```

Derive a contract from the survey artifact:

```bash
fitctl contract \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > contract.json
```

The contract records the host capabilities that may be claimed under the selected policy.

Validate a contract against a service profile:

```bash
fitctl validate \
  --contract contract.json \
  --profile configs/service_profiles/general_compute_contract_only.v1.json \
  > validation.json
```

The validation report contains a machine-readable verdict that can be used in later automation or deployment decisions.

Inspect the result manually:

```bash
fitctl inspect --input validation.json
```

Or use the verdict in automation:

```bash
jq -r '
  if .report.verdict == "fit" or .report.verdict == "fit_with_degradation"
  then "ALLOW"
  else "DENY"
  end
' validation.json
```

## Use cases

- quick capability view
- workload fit gating
- reusable host evidence and validation reports

The core flow works with three main artifacts: a host survey, a host contract, and a validation report. Use `fitctl state` when a decision depends on current runtime conditions.

## Installation

Install from a checked-out repository with Cargo:

```bash
cargo install --path crates/fitctl-cli --locked
```

Build without installing:

```bash
cargo build --workspace
./target/debug/fitctl --help
```

## Documentation

- [Validation](./docs/validation.md) — survey, contract, validate, and verdicts
- [Configuration](./docs/configuration.md) — policies, service profiles, and bundled config layout
- [Artifacts](./docs/artifacts.md) — surveys, contracts, state, and reports

fitctl makes fit decisions. It does not place workloads or manage hosts.

## License

Apache-2.0
