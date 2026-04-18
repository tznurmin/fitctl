# Contracts

A contract is a typed host claim derived from survey evidence under a selected policy.

A survey records what was observed on the machine. A contract records what the machine may claim
from that evidence.

## Contract derivation

```bash
fitctl contract --survey <survey.json> --policy <policy.json> > contract.json
```

Survey examples are in [fixtures/host_survey](../fixtures/host_survey). Policy examples are in
[configs/policy](../configs/policy).

## Context dependence

The same survey can produce different contracts under different policies.

The policy determines the allowed claim. For the same observed machine, a general-compute policy
yields a general-compute contract and a GPU policy yields a GPU-capable contract.

## Create a contract

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

The example above shows how one survey can yield different contracts under different policies.

## Contract contents

- capability claims and admissibility
- execution constraints
- host summaries for identity, network, storage, accelerators, and topology
- derivation basis: source survey and policy
