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

Do not attach raw host artifacts by default. Prefer inspect output or redacted artifacts.

```bash
fitctl redact --profile external --input host.survey.json > host.survey.redacted.json
fitctl redact --profile external --input host.state.json > host.state.redacted.json
fitctl redact --profile external --input validation.json > validation.redacted.json
```

Attach only the redacted files needed to explain the problem.

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
