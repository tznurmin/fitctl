# Installed Configuration

`fitctl` ships a small set of bundled configuration files with the installed binary.

List the bundled files:

```bash
fitctl config list
```

Export them into the current workspace:

```bash
fitctl config export --out-dir fitctl-config
```

The exported files keep the same `configs/...` layout used by the repository examples. After
exporting, use normal path-based commands:

```bash
fitctl contract \
  --survey host.survey.json \
  --policy fitctl-config/configs/policy/general_compute_default.v1.json \
  > host.contract.json

fitctl validate \
  --contract host.contract.json \
  --profile fitctl-config/configs/service_profiles/general_compute_contract_only.v2.json \
  > validation.json
```

Bundled configuration includes policies, service profiles, service-profile catalogues, invocation
contexts, runtime extension packs, recommendation packs, trust policies, and CUDA environment
selection examples.

The bundled service profiles include generic local workload gates such as:

- `cpu_small_state_required_v1`
- `cpu_large_state_required_v1`
- `local_model_high_memory_state_required_v1`
- `scratch_tmpfs_state_required_v1`
- `scratch_nvme_state_required_v1`
- `cuda_24gb_state_required_v1`
- `cuda_48gb_state_required_v1`

The exported files are examples and starting points. Edit or replace them when a workload has
different policy or service-profile requirements.
