# Validation

Validation checks whether a host contract fits a service profile. The result is written as a typed
JSON validation report.

The core inputs are a contract and a service profile:

```bash
fitctl validate --contract <contract.json> --profile <profile.json> > validation.json
```

[Contracts](./contracts.md) covers contract derivation. [Configuration](./configuration.md) covers
policies and service profiles.

Examples are in [configs/service_profiles](../configs/service_profiles) and
[fixtures/host_survey](../fixtures/host_survey).

## Default flow

Survey the current host:

```bash
fitctl survey > survey.json
```

Derive a contract from the survey:

```bash
fitctl contract \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > contract.json
```

Validate that contract against a service profile:

```bash
fitctl validate \
  --contract contract.json \
  --profile configs/service_profiles/general_compute_contract_only.v2.json \
  > validation.json
```

If you do not need to keep the intermediate contract, you can validate directly from a survey and
policy:

```bash
fitctl validate \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  --profile configs/service_profiles/general_compute_contract_only.v2.json \
  > validation.json
```

Read the decision:

```bash
jq -r '.report.verdict' validation.json
```

Inspect the full report for more information:

```bash
fitctl inspect --input validation.json
```

## Batch comparison

Use `classify` to check several contracts against several service profiles:

```bash
fitctl survey --fixture linux-bare-metal-like-v1 > cpu.survey.json
fitctl survey --fixture linux-gpu-workstation-like-v1 > gpu.survey.json

fitctl contract \
  --survey cpu.survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > cpu.contract.json

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

`classify` emits a typed `batch-classification-report.v2` artifact. `fitctl inspect --view matrix`
renders that report as a shortlist table.

## Verdicts

- `fit` – the host satisfies the profile
- `fit_with_degradation` – the profile fits through an allowed fallback path
- `unfit` – the host does not satisfy the profile
- `indeterminate` – fitctl cannot make a safe decision from the available inputs
