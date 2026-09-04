# Contributing

Thanks for considering a contribution!

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/async-port-scanner.git
cd async-port-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src tests          # lint
mypy src                      # type check
pytest -v                     # unit tests
portscan --self-test          # loop-based integration self-test
```

## Safety and responsible contribution policy

Contributions must preserve the project’s purpose: a transparent,
authorization-aware TCP scanner for legitimate diagnostics and network
validation.

Please do not propose or accept changes that:

- hide or spoof the scanner's behavior
- bypass authorization checks or weaken local safety prompts
- enable stealth scanning, evasion, or anti-forensics features
- target systems without an explicit authorization basis

All behavior-changing changes should be reviewed with a safety mindset.
If a patch alters network behavior, include a short explanation of why the
change remains safe, bounded, and legal for authorized use.

The project’s formal safety policy is documented in [safety-report.md](safety-report.md).

## Guidelines

- Keep the core `scanner.py` free of CLI/argparse concerns — it should
  stay usable as a plain library.
- Add or update tests for any behavior change, especially around port
  parsing, target resolution, or the authorization gate.
- Please don't add features intended to evade detection, spoof source
  addresses, or otherwise push this beyond a straightforward TCP-connect
  scanner — see [SECURITY.md](SECURITY.md) for the project's scope and
  responsible-use stance.
- Run `ruff format` (or keep formatting consistent) before submitting.

## Reporting bugs / requesting features

Please open a GitHub issue with:
- Python version and OS
- Exact command run
- Expected vs. actual behavior
- Logs with `-vv` if relevant
