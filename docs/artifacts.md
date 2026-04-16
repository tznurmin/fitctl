# Artifacts

Fitctl keeps each step of the decision chain as a separate typed JSON artifact.

That keeps observed host evidence, policy-bound host claims, runtime state, and validation results distinct.

Optional host state adds runtime-sensitive input when a decision depends on current conditions.

Configuration files such as `policy` and `service profile` are covered in [Configuration](./configuration.md).

## Common envelope

Every supported artifact contains an `envelope` section.

`envelope` carries:

- `schema_id`
- `schema_version`
- `artifact_id`
- `provenance`
- optional `redaction`
- optional `signatures`

This gives every artifact a stable outer shape for inspection, diffing, signing, and verification.

## host-survey.v1

Top-level shape:

```json
{
  "envelope": { ... },
  "survey": { ... }
}
```

A survey records observed host evidence.

The `survey` section contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- `core_evidence`

`core_evidence` contains:

- `collectors`
- `execution_context`
- `identity_summary`
- `observations`
- `section_metadata`

`observations` carries the recorded host sections, including:

- `cpu`
- `memory`
- `storage`
- `network`
- `topology`
- `accelerators`
- `hostname`

## host-contract.v1

Top-level shape:

```json
{
  "envelope": { ... },
  "contract_basis": { ... },
  "contract": { ... }
}
```

A contract records what the host may claim under a selected policy.

`contract_basis` records how the contract was derived. It contains:

- `core_semantic_basis`
- `derivation_provenance`

`core_semantic_basis` records:

- `source_survey_semantic_hash`
- `policy_semantic_hash`
- `derivation_engine_id`
- `derivation_engine_version`
- `contract_schema_version`
- `selected_policy_layers`

The `contract` section contains `core_contract`, which carries:

- `capability_classes`
- `execution_constraints`
- `identity_summary`
- `network_summary`
- `topology_summary`

`capability_classes` is a map of policy-bound claims such as `general_compute` or `gpu_accelerated`. Each claim records whether it is admissible and which evidence and rules support it.

The same survey can be used to derive different contracts under different policies.

## host-state.v1

Top-level shape:

```json
{
  "envelope": { ... },
  "state": { ... }
}
```

Host state records current runtime-sensitive facts separately from the stable contract.

The `state` section contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- `core_state`

`core_state` contains:

- `collectors`
- `section_metadata`
- `freshness`
- `resources`
- `boundaries`
- `topology`
- `operability`

These sections cover things such as allocatable CPU and memory, cgroup and memory limits, visible topology, degraded capability classes, and whether the captured state is still fresh.

Use a separate state artifact when current conditions matter. Keep them out of the stable contract.

## validation-report.v1

Top-level shape:

```json
{
  "envelope": { ... },
  "validation_basis": { ... },
  "report": { ... }
}
```

A validation report records the result of checking a contract against a service profile.

`validation_basis` records which inputs were used. It contains:

- `validation_mode`
- `contract_artifact_id`
- `service_profile_artifact_id`
- `contract_semantic_hash`
- `service_profile_semantic_hash`
- optional `state_artifact_id`
- optional `state_semantic_hash`
- optional `state_observed_at`
- optional `state_freshness_state`
- optional `max_state_age_seconds`
- `validation_engine_id`
- `validation_engine_version`

When state participates in validation, these optional state fields keep enough context to explain stale-state decisions later.

Key `report` fields include:

- `verdict`
- `primary_reason_code`
- `matched_requirements`
- `failed_requirements`
- `evidence_refs`
- `policy_refs`
- `assurance_mismatches`
- `selected_degradation_tier`
- `warnings`
- `explanations`
- `remediation_hints`
- `summary`

This is the machine-readable output that later automation can consume.

## Reading artifacts

Use `fitctl inspect --input <path>` to read any supported artifact as a human-oriented summary.
