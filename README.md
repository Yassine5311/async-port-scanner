# async-port-scanner

This project is an asynchronous TCP port scanner written in Python.
It resolves targets, opens outbound connections, and optionally reads a short banner from an open service.

## Purpose

This tool is intended only for:

- local development and testing
- lab or home environments you own or control
- explicitly authorized testing on systems covered by written permission

This tool is not intended for unauthorized reconnaissance, hidden scanning, bypassing access controls, or any other unlawful or unethical use.

## Explicit responsibility statement

This project is provided as a technical utility only. It is not a service, guarantee, or legal shield.

The author and maintainers do not accept responsibility for how this project is used after cloning, downloading, modifying, or redistributing it. Any person or organization using this project is solely responsible for ensuring that their use is lawful, authorized, and consistent with all applicable laws, contracts, policies, and terms of service.

No one associated with this project is responsible for misuse, unauthorized scans, legal claims, civil or criminal consequences, network damage, or any other outcome caused by a third party using this software.

## Safety notice

> ⚠️ Only scan systems you own or are explicitly authorized to test.
>
> Unauthorized port scanning may violate local law, network policy, or service terms.
>
> The CLI asks for confirmation before scanning non-local targets unless `--yes` is used.

For the full safety policy and project scope, see [safety-report.md](SAFETY_REPORT.md).

## Installation

Create a virtual environment if you want an isolated setup:

```bash
cd async-port-scanner
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

To install without development tools:

```bash
python -m pip install .
```

## CLI usage

```bash
# Scan the default port range on a hostname
portscan example.com

# Scan a specific set of ports with banner grabbing
portscan 192.168.1.10 -p 22,80,443,8000-8100 --banner

# Scan a wider range with higher concurrency and save output
portscan localhost -p 1-65535 -c 500 -o results.json

# Increase verbosity
portscan 10.0.0.5 -p 1-1024 -v

# Run the loop self-test against local listeners
portscan --self-test --self-test-iterations 10
```

### CLI options

- `-p`, `--ports`: port specification, for example `80`, `1-1024`, or `22,80,443,8000-8100`
- `-c`, `--concurrency`: maximum concurrent connections
- `-t`, `--timeout`: per-connection timeout in seconds
- `--banner`: read a small service banner if a port is open
- `-o`, `--output`: write output to `.json`, `.csv`, or `.txt`
- `--yes`: skip the confirmation prompt for non-local targets
- `-v`, `-vv`: increase logging detail
- `--self-test`: run repeated local validation and exit
- `--version`: print the package version

## Python API

```python
import asyncio
from async_port_scanner import parse_port_spec, resolve_target, scan_ports

async def main():
    ip, family = resolve_target("localhost")
    ports = parse_port_spec("1-1024")
    results = await scan_ports(
        "localhost",
        ports,
        family=family,
        max_concurrency=200,
        timeout=1.0,
        grab_banner=True,
    )

    for result in results:
        print(result.port, result.service, result.banner)

asyncio.run(main())
```

The project also exposes the lower-level `run_scan` function for advanced callers.

## How it works

The scanner pushes ports into an `asyncio.Queue` and runs a fixed-size set of worker tasks. Each worker attempts an outbound TCP connection and records the port only when the connection succeeds. This keeps memory usage and file descriptor count bounded even for large port ranges.

## Loop testing

The project includes a built-in self-test that starts real local TCP listeners and re-runs the scan repeatedly. This is meant to catch flaky timing, bad open/closed detection, and race conditions before a release.

```bash
python -m async_port_scanner --self-test --self-test-iterations 10
```

A successful run prints a PASS result for each iteration and ends with a final summary.

## Testing

```bash
pytest -q
python -m async_port_scanner --self-test --self-test-iterations 10
```

The automated suite covers parsing, target resolution, scanning behavior, banner reading, and repeated local loop checks.

## Project files

- `src/async_port_scanner/scanner.py`: core scanning logic
- `src/async_port_scanner/cli.py`: command-line interface
- `tests/test_scanner.py`: regression and loop tests

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
