# fitctl

Survey candidate hosts, compare them against workload profiles, and make explicit fit decisions
from typed local artifacts.

### Quick live summary

```bash
fitctl survey | fitctl inspect
```

```text
Summary
  Host alias: fithost
  Collection mode: live
  CPU: observed; x86_64; 24 logical cores; 12 physical cores
  Memory total: observed; 94.19 GiB
  Storage: observed; 11 block devices; classes loop=8, solid_state=3
  Network: observed; 2 interfaces; kinds ethernet=1, loopback=1
  Graphics / accelerators: observed; 1 devices; kinds gpu; vendors nvidia
```

### Host fitness charting

Compare candidate machines against workload profiles to determine which hosts fit under different
usage policies.

```bash
fitctl inspect --input batch.json --view matrix
```

```text
Profile                     | Host        | Contract                | Verdict
----------------------------+-------------+-------------------------+---------------------
CPU only                    | cpu-host-01 | General compute default | fit
CPU only                    | gpu-host-01 | GPU compute default     | unfit
GPU preferred, CPU fallback | cpu-host-01 | General compute default | fit_with_degradation
GPU preferred, CPU fallback | gpu-host-01 | GPU compute default     | fit
GPU required                | cpu-host-01 | General compute default | unfit
GPU required                | gpu-host-01 | GPU compute default     | fit
```

- `CPU host` – a standard general-purpose compute machine
- `GPU host` – a machine provisioned with GPU acceleration
- `Profiles` – workload requirements and constraints, such as GPU is mandatory or only CPU is allowed
- `Contract` – the capabilities the host is allowed to claim under policy

The example above shows how survey results from two machines are turned into fit decisions against
three workload profiles.

Read [Configuration](./docs/configuration.md) for reusable policy and profile inputs,
[Contracts](./docs/contracts.md) for contract derivation from survey evidence and policy, and
[Validation](./docs/validation.md) for how fit is decided from a contract and a workload profile.

## Installation

From crates.io:

```bash
cargo install fitctl --locked
```

From the GitHub repository:

```bash
cargo install --git https://github.com/tznurmin/fitctl fitctl --locked
```

From a local checkout:

```bash
cargo install --path crates/fitctl-cli --locked
```

Build without installing:

```bash
cargo build --workspace
./target/debug/fitctl --help
```

## Documentation

- [Configuration](./docs/configuration.md) – policies and service profiles for contract derivation and validation
- [Contracts](./docs/contracts.md) – deriving host contracts from survey evidence and policy
- [Validation](./docs/validation.md) – single-host validation and batch comparison against workload profiles
- [Artifacts](./docs/artifacts.md) – survey, contract, state, and validation-report artifacts

fitctl makes fit decisions. It does not place workloads or manage hosts.

Version history and release notes: [GitHub Releases](https://github.com/tznurmin/fitctl/releases)

## License

[Apache-2.0](LICENSE)
