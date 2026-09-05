# Host report

## What were you trying to validate?

Describe the use case, for example:

- self-hosted GPU runner
- bare-metal deployment gate
- host matrix selection

## Commands run

Paste the commands and errors. If validation completed, include the inspect output:

```bash
fitctl inspect --input validation.json
```

If state freshness was part of the decision, include the validation mode, `--validated-at`, and
`--max-state-age` values used.

## Decision summary

Paste these fields when a validation artifact exists:

```bash
jq -r '.report.verdict' validation.json
jq -r '.report.primary_reason_code' validation.json
```

## Redacted artifacts

Do not attach raw host artifacts by default. Prefer inspect output or the narrowest useful redacted
host artifact.

```bash
fitctl redact --profile external --input host.survey.json > host.survey.redacted.json
fitctl redact --profile external --input host.state.json > host.state.redacted.json
fitctl redact --profile external --input validation.json > validation.redacted.json
```

`auditor` and `external` fail closed when an extension section has no registered typed redactor.
They also replace core provenance strings, path/profile identifiers, and accelerator topology.
Review the complete output before attaching it: semantic hashes and coarse capability facts remain
intentionally visible and linkable.

Attach only the redacted survey, state, or validation files needed to explain the problem. Do not
attach a configuration or decision bundle by default: those bundle views deliberately retain
configuration, trust, signer, and evidence-lineage identities.

## Host context

Provide only what is safe to share:

- operating system:
- CPU model or family:
- GPU model or family:
- NVIDIA driver version:
- CUDA runtime visibility:
- containerized: yes/no/unknown
- privilege level or runner user restrictions:

## Expected result

What did you expect the verdict to be?

## Actual result

What verdict, reason code, or command error did you get?
