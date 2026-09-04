# Security & Responsible Use

## Responsible use policy

This tool performs active TCP connection attempts against a target host.
Only use it against:

- Hosts and networks **you own**, or
- Hosts and networks you have **explicit, documented authorization** to test
  (e.g. a signed penetration-test agreement, a bug-bounty program's
  in-scope assets, or your own home/lab network).

Scanning systems without authorization may violate computer-crime laws
(such as the U.S. Computer Fraud and Abuse Act), equivalent laws in other
countries, or a network's terms of service — regardless of intent.

To reduce accidental misuse, the CLI will **prompt for explicit
confirmation** before scanning any target that is not localhost or a
private/link-local address (`--yes` bypasses this for scripted/CI use
against infrastructure you control).

## Built-in safeguards

- Concurrency is hard-capped at 2000 simultaneous connection attempts.
- Per-connection timeout is hard-capped at 30 seconds.
- Port numbers and specs are validated before any network activity.
- Banner reads are bounded in both size (1 KB) and time (1.5s) to avoid
  hangs or memory exhaustion from a hostile/misbehaving service.
- No shell execution, no dynamic code evaluation, no third-party
  dependencies in the core package.

## Reporting a vulnerability

If you find a security issue in this project's code itself (not in a
target you scanned with it), please open a private security advisory on
GitHub ("Security" tab → "Report a vulnerability") rather than a public
issue, so it can be addressed before disclosure.
