# Validation

Fitctl checks whether a recorded host fits a workload.

The usual flow is simple: survey a host, derive a contract from that survey with a policy, then validate that contract against a service profile. The result is a typed validation report that can be inspected by a person or read by automation.

## Default flow

Survey the current host:

```bash
fitctl survey > survey.json
```

`survey.json` records observed host evidence.

Derive a contract from the survey:

```bash
fitctl contract \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > contract.json
```

The selected policy turns observed survey evidence into contract claims.

`contract.json` records the capabilities the host may claim under the selected policy.

Validate that contract against a service profile:

```bash
fitctl validate \
  --contract contract.json \
  --profile configs/service_profiles/general_compute_contract_only.v1.json \
  > validation.json
```

The selected service profile defines what the workload needs.

`validation.json` records the verdict and the reasons behind it.

Read the decision:

```bash
jq -r '.report.verdict' validation.json
```

Inspect the full report when you want reason codes and summaries:

```bash
fitctl inspect --input validation.json
```

## Default mode

The default mode is `contract_only`.

Use it when the decision depends on stable host properties already carried by the contract, such as CPU, memory, storage, accelerators, visibility scope, or extension evidence.

No current runtime state is required.

## When state matters

Some decisions depend on what is true right now, not only on what the host can generally provide.

Capture current state separately:

```bash
fitctl state > state.json
```

`state.json` records current runtime-sensitive facts kept separate from the stable contract.

Then validate with a state-aware mode:

```bash
fitctl validate \
  --contract contract.json \
  --profile configs/service_profiles/general_compute_stateful_thresholds.v1.json \
  --validation-mode state_required \
  --state state.json \
  --max-state-age 15m \
  > validation.json
```

Use `state_required` when missing or stale state must stop the decision.

Use `state_advisory` when current state should inform the result but should not be mandatory.

When state is stale, the validation report stays explicit about it. `fitctl inspect` will show the recorded state time and the applied age window when that context is available.

## Verdicts

- `fit` — the host satisfies the profile
- `fit_with_degradation` — the profile fits through an allowed fallback path
- `unfit` — the host does not satisfy the profile
- `indeterminate` — fitctl cannot make a safe decision from the available inputs

A common rule is:

- allow on `fit`
- allow on `fit_with_degradation` when that fallback is acceptable
- deny on `unfit`
- deny on `indeterminate`
