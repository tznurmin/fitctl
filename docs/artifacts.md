# Artifacts

Artifacts are typed JSON records emitted at each step of the decision flow. They are the stable
handoff format between collection, contract derivation, validation, inspection, and automation.

Common artifacts in the local decision flow:

| Artifact | Produced by | Contains |
|---|---|---|
| `host-survey.v2` | `fitctl survey` | observed host evidence |
| `host-contract.v2` | `fitctl contract` | policy-shaped claim |
| `host-state.v2` | `fitctl state` | current runtime-sensitive facts |
| `validation-report.v2` | `fitctl validate` | verdict, posture, reason codes, evidence |
| `fitctl.batch-classification-report.v3` | `fitctl classify` | multi-contract, multi-profile comparison |

The same JSON that `fitctl inspect` renders is the JSON that automation reads unchanged.

Read any supported artifact with `inspect`:

```bash
fitctl inspect --input <artifact.json>
```

Other inspectable top-level artifacts include service profiles, config bundles, decision bundles,
batch classification reports, and recommendation reports.

For grouped coverage detail on survey, contract, and state artifacts, use:

```bash
fitctl inspect --input <artifact.json> --view coverage
```

Example shapes are under
[fixtures/schema_shapes/core_extension_split/valid](../fixtures/schema_shapes/core_extension_split/valid).
Conformance examples are under [fixtures/conformance/valid](../fixtures/conformance/valid).
Some conformance fixtures intentionally preserve older `fitctl_version` provenance values to
exercise compatibility with artifacts produced by earlier release lines.

[Contracts](./contracts.md) covers contract meaning. [Configuration](./configuration.md) covers
policies and service profiles. [Validation](./validation.md) covers the decision flow.

Namespaced runtime examples in this repository use `fitctl.runtime.*` extension identifiers.

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

`schema_version` is the shared top-level envelope version. The artifact family version is encoded
in `schema_id`; these values can differ, as with `fitctl.batch-classification-report.v3` using
envelope schema version 2.

`envelope.provenance` keeps the release-line field `fitctl_version` separate from optional build
provenance. When available, build provenance may also include:

- `fitctl_vcs_revision`
- `fitctl_vcs_describe`
- `fitctl_build_dirty`

Compact inspect continues to show `fitctl version`. Verbose inspect may show the optional build
provenance fields separately when they are present.

## host-survey.v2

Produced by `fitctl survey`.

Top-level shape:

```text
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
- optional `extension_evidence`

`core_evidence` combines collector metadata, execution context, identity summary, section metadata,
and recorded observations.

It contains:

- `collectors`
- `execution_context`
- `identity_summary`
- `section_metadata`
- `observations`

`identity_summary` records the local correlation identity, including identity class, local stable
ID and version, anchor family and source, stability class, degradation flags, composition digest,
and provenance fingerprint.

`observations` carries the recorded host sections, including:

- `cpu`
- `memory`
- `storage`
- `network`
- `topology`
- `accelerators`
- `hostname`

## host-contract.v2

Produced by `fitctl contract`.

Top-level shape:

```text
{
  "envelope": { ... },
  "contract_basis": { ... },
  "contract": { ... }
}
```

A contract records what the host may claim under a selected policy.

`contract_basis` records how the contract was derived. It links the artifact back to the source
survey, the selected policy, the derivation engine, and the selected policy layers.

It contains:

- `core_semantic_basis`
- optional `extension_basis`
- `derivation_provenance`

`core_semantic_basis` records:

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

When accelerator scope filters are active, `accelerator_summary` separates the
full accelerator inventory from the policy-scoped accelerator inventory used for the claim.

Count-sensitive validation uses the confirmed policy-scoped accelerator count and completeness
signals from that summary, not the full observed inventory. Inspect may therefore show both `full
accelerator inventory incomplete` and `policy-scoped accelerator inventory complete` on the same
host without contradiction.

Inspect renders policy-scoped inventory detail with `confirmed in-scope` and `unresolved in-scope`
counts so resolved out-of-scope devices do not inflate workload GPU floors.

`capability_classes` is the map of policy-bound claims, such as `general_compute` or
`gpu_accelerated`. Each claim records whether it is admissible and which evidence and rules support
it.

## host-state.v2

Produced by `fitctl state`.

Top-level shape:

```text
{
  "envelope": { ... },
  "state": { ... }
}
```

Host state records current runtime-sensitive facts separately from the stable contract.

The `state` section combines collection metadata with `core_state` and may also carry optional
`extension_state`.

It contains:

- `collection_mode`
- `host_alias`
- `snapshot_id`
- `source_ref`
- optional `local_identity`
- `core_state`
- optional `extension_state`

`core_state` captures current runtime-sensitive sections.

It contains:

- `collectors`
- `section_metadata`
- `freshness`
- `resources`
- `boundaries`
- `topology`
- `operability`

`extension_state` carries namespaced runtime facts that do not belong in the stable contract. CUDA
runtime replay and live state appear under
`extension_state.fitctl.runtime.cuda`.

CUDA extension payloads may also carry selected CUDA environment fields as additive observations.
They do not redefine the default CUDA view.

This separation is deliberate: `contract` records what the host may claim in principle, while
`state` records what is true in the current execution context now.

## validation-report.v2

Produced by `fitctl validate`.

Top-level shape:

```text
{
  "envelope": { ... },
  "validation_basis": { ... },
  "report": { ... }
}
```

A validation report records the result of checking a contract against a service profile.

`validation_basis` records which inputs participated in the decision.

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

When state participates in validation, the optional state fields preserve the extra runtime and
freshness context.

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
- `extension_diagnostics`
- `explanations`
- `remediation_hints`
- `summary`

Count-sensitive and runtime-sensitive validation reuse these normal report fields. Scoped
accelerator floors and runtime admission still surface through `matched_requirements`,
`failed_requirements`, `primary_reason_code`, `summary`, and optional `extension_diagnostics`.

CUDA runtime detail is recorded under
`report.extension_diagnostics.fitctl.runtime.cuda`.

For multi-GPU CUDA admission, those diagnostics may also record qualifying-device counts and
allocatable-memory thresholds and observations. That lets validation explain how the static
policy-scoped accelerator floor was reused for runtime admission and how the
qualifying-device subset was evaluated.

Relevant CUDA diagnostic fields include `required_qualifying_device_count`,
`observed_qualifying_device_count`, `required_device_allocatable_memory_bytes`,
and `observed_device_allocatable_memory_bytes`.

## Other supported reports

`fitctl classify` emits `fitctl.batch-classification-report.v3`.

Use:

```bash
fitctl inspect --input batch.json --view matrix
```

to render that report as a shortlist table.

[Validation](./validation.md) covers batch comparison and matrix rendering.
