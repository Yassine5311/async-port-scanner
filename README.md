# async-port-scanner

A fast, safe, and asynchronous TCP port scanner built with Python's `asyncio`.
It resolves targets, checks ports concurrently, and can optionally read a short banner from open services.

## What it does

- Scans IPv4 and IPv6 addresses or hostnames
- Accepts flexible port specifications such as `80`, `22,80,443`, or `1000-1010`
- Uses a bounded worker pool to avoid unbounded socket creation
- Supports banner grabbing for open TCP ports
- Prints progress while scanning and can save results as JSON, CSV, or text
- Includes a built-in loop self-test for repeated validation

## Responsible use and safety report

This project is a network diagnostics tool for authorized use only. It is intended for:

- local development and validation
- owned lab or home environments
- explicitly authorized testing on in-scope assets

It is not intended for unauthorized reconnaissance, stealth scanning, or bypassing access controls.

> ⚠️ Authorization notice
>
> Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may violate local law, network policy, or service terms.
>
> The CLI warns before scanning non-local targets and requires explicit confirmation unless you pass `--yes`.

For the full safety policy and scope statement, see [safety-report.md](safety-report.md).

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
