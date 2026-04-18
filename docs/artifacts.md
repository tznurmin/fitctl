# Artifacts

Artifacts are typed JSON records produced at each step of the decision flow.

The core artifacts are `host-survey.v2`, `host-contract.v2`, `host-state.v2`, and
`validation-report.v2`.

Each step writes its own artifact with a shared envelope and an artifact-specific payload.

Read any supported artifact with `inspect`:
```bash
fitctl inspect --input <artifact.json>
```

Example shapes are in [fixtures/schema_shapes/ring_split/valid](../fixtures/schema_shapes/ring_split/valid).
Conformance examples are in [fixtures/conformance/valid](../fixtures/conformance/valid).

[Contracts](./contracts.md) covers contract meaning. [Configuration](./configuration.md) covers
policies and service profiles.

## Common envelope

Every supported artifact contains an `envelope` section.

`envelope` records schema identity, artifact identity, provenance, and optional redaction and
signatures.

It carries:

- `schema_id`
- `schema_version`
- `artifact_id`
- `provenance`
- optional `redaction`
- optional `signatures`

## host-survey.v2

Top-level shape:

```json
{
  "envelope": { ... },
  "survey": { ... }
}
```

A survey records observed host evidence.

The `survey` section combines collection metadata with `core_evidence`.

It contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- `core_evidence`

`core_evidence` combines collector metadata, execution context, section metadata, and recorded
observations.

It contains:

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

## host-contract.v2

Top-level shape:

```json
{
  "envelope": { ... },
  "contract_basis": { ... },
  "contract": { ... }
}
```

A contract records what the host may claim under a selected policy.

`contract_basis` records how the contract was derived.

It contains:

- `core_semantic_basis`
- `derivation_provenance`

`core_semantic_basis` links the contract back to the source survey, the selected policy, and the
derivation engine.

It records:

- `source_survey_semantic_hash`
- `policy_semantic_hash`
- `derivation_engine_id`
- `derivation_engine_version`
- `contract_schema_version`
- `selected_policy_layers`

The `contract` section contains `core_contract` and may also carry optional
`extension_contract`.

`core_contract` carries:

- `capability_classes`
- `execution_constraints`
- `identity_summary`
- `network_summary`
- `storage_summary`
- `accelerator_summary`
- `topology_summary`

`capability_classes` is a map of policy-bound claims such as `general_compute` or
`gpu_accelerated`. Each claim records whether it is admissible and which evidence and rules
support it.

## host-state.v2

Top-level shape:

```json
{
  "envelope": { ... },
  "state": { ... }
}
```

Host state records current runtime-sensitive facts separately from the stable contract.

The `state` section combines collection metadata with `core_state`.

It contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- `core_state`

`core_state` captures current runtime-sensitive sections.

It contains:

- `collectors`
- `section_metadata`
- `freshness`
- `resources`
- `boundaries`
- `topology`
- `operability`

## validation-report.v2

Top-level shape:

```json
{
  "envelope": { ... },
  "validation_basis": { ... },
  "report": { ... }
}
```

A validation report records the result of checking a contract against a service profile.

`validation_basis` records which inputs were used.

It contains:

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

When state participates in validation, the optional state fields keep the extra runtime context.

The `report` section carries the decision itself.

Key fields include:

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
