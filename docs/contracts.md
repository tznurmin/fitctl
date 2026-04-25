# Contracts

A contract is the policy-shaped claim a host may make from a `survey`.

A `survey` records observed local facts. A `contract` records what the selected `policy` permits
the host to claim from those facts. `validation` checks that claim against a service profile.

A contract is the handoff artifact between collection and validation. The same JSON that
`fitctl inspect` renders is the JSON that `fitctl validate` reads.
Live runtime detail remains separate in `state`.

## Derive a contract

```bash
fitctl contract --survey <survey.json> --policy <policy.json> > contract.json
fitctl inspect --input contract.json
```

Survey examples are under [fixtures/host_survey](../fixtures/host_survey). Policy examples are under
[configs/policy](../configs/policy).

[Configuration](./configuration.md) covers policies and service profiles.
[Validation](./validation.md) covers fit decisions.

## What a contract contains

A contract records:

- the admitted capability claim
- any policy-derived execution constraints
- host summaries used during validation
- the derivation basis: source survey and source policy

## One survey, different contracts

The same survey can yield different contracts under different policies.

A general-compute policy may admit a general-compute contract. A GPU policy may admit a GPU-capable
contract from the same host. A stricter policy may narrow or reject the claim entirely.

```bash
fitctl survey --fixture linux-gpu-workstation-like-v1 > survey.json

fitctl contract \
  --survey survey.json \
  --policy configs/policy/general_compute_default.v1.json \
  > general-contract.json

fitctl contract \
  --survey survey.json \
  --policy configs/policy/gpu_compute_default.v1.json \
  > gpu-contract.json
```

This example shows why policy matters: survey evidence alone does not say what the host is allowed
to claim.

## Scoped accelerator claims

When a policy narrows accelerator inventory, the contract separates:

- the full accelerator inventory observed on the host
- the policy-scoped accelerator inventory used for the claim

Count-sensitive validation uses the confirmed policy-scoped accelerator count from the contract
summary, not the full accelerator inventory.

That is why `fitctl inspect` may legitimately show both `full accelerator inventory incomplete` and
`policy-scoped accelerator inventory complete` on the same host. These statements describe
different sets.

A stricter policy may also require the policy-scoped accelerator inventory to be complete before the
claim is admitted. That requirement still applies only to the policy scope, not to unrelated
accelerators elsewhere on the host.

## What a contract does not contain

A contract does not carry live runtime state.

Current accelerator visibility, allocatable memory, and other runtime-only facts belong in `state`.
Supply `state` during validation only when the decision depends on those live conditions.

## Where it fits

- `fitctl survey` records observed local facts
- `fitctl contract` turns those facts into a policy-shaped claim
- `fitctl validate` checks that claim against a service profile
- `fitctl inspect` renders any of those artifacts without changing the underlying JSON
