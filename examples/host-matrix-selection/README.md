# Host Matrix Selection

Stored host artifacts can be compared before deployment. This example classifies two candidate
hosts against one state-aware memory profile and prints the batch result as a matrix.

The fixture-backed candidates are:

- `cpu-host-01`, a 16 GiB host with 12 GiB allocatable memory in the runtime state fixture
- `gpu-host-01`, a 64 GiB host with 48 GiB allocatable memory in the runtime state fixture

The example profile requires 32 GiB allocatable memory, so the lower-memory host is rejected and the
higher-memory host fits.

## Run the example

```bash
fitctl config export --out-dir fitctl-config

fitctl survey --fixture linux-bare-metal-like-v1 > cpu.survey.json

fitctl contract \
  --survey cpu.survey.json \
  --policy fitctl-config/configs/policy/general_compute_default.v1.json \
  > cpu.contract.json

fitctl state --fixture linux-bare-metal-like-fresh-v1 > cpu.state.json

fitctl survey --fixture linux-gpu-workstation-like-v1 > gpu.survey.json

fitctl contract \
  --survey gpu.survey.json \
  --policy fitctl-config/configs/policy/general_compute_default.v1.json \
  > gpu.contract.json

fitctl state --fixture linux-gpu-workstation-like-fresh-v1 > gpu.state.json

fitctl classify \
  --contract cpu.contract.json \
  --contract gpu.contract.json \
  --state cpu.state.json \
  --state gpu.state.json \
  --profile examples/host-matrix-selection/high-memory-state-required.profile.json \
  --validation-mode state_required \
  --validated-at 2025-06-17T10:00:00Z \
  > batch.json

fitctl inspect --input batch.json --view matrix
```

Expected matrix:

```text
Profile     | Host        | Contract                | Verdict
------------+-------------+-------------------------+--------
High memory | cpu-host-01 | General compute default | unfit
High memory | gpu-host-01 | General compute default | fit
```

## Automation handoff

The matrix is a view over the typed batch artifact emitted above. Automation can read the report
directly or ask `classify` for a CSV projection:

```bash
fitctl classify \
  --contract cpu.contract.json \
  --contract gpu.contract.json \
  --state cpu.state.json \
  --state gpu.state.json \
  --profile examples/host-matrix-selection/high-memory-state-required.profile.json \
  --validation-mode state_required \
  --validated-at 2025-06-17T10:00:00Z \
  --export-view rows_csv
```

The CSV rows include host aliases, contract and profile labels, verdicts, reason codes, and
summaries needed to choose a host or stop before deployment.
