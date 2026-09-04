# Security & Responsible Use

## Project scope

This project is a basic TCP-connect scanner for lawful and explicitly authorized network diagnostics.

It is intended for:

- local testing
- home or lab networks under your control
- in-scope assets covered by written permission

It is not intended for unauthorized reconnaissance, stealth scanning, evasion, or any other misuse.

## Explicit responsibility statement

This software is provided as a technical tool only. The author and maintainers do not accept responsibility for how any user, team, or third party uses a clone, fork, or modified version of this project.

Any person or organization using this project is solely responsible for ensuring that their use is lawful, authorized, and compliant with all applicable laws, contracts, policies, and service terms.

The author and maintainers are not responsible for misuse, unauthorized scanning, legal claims, penalties, damages, or any other consequences arising from the use of this project by others.

## Built-in safeguards

- concurrency is capped at a safe limit
- per-connection timeouts are enforced
- port ranges are validated before scanning
- banner reads are intentionally limited
- no stealth, evasion, or anti-forensics features are included

## Safety report

This project intentionally does not include features meant to hide activity, bypass access controls, evade detection, or perform unauthorized reconnaissance.

If a contribution proposes stealth behavior, spoofed source addresses, traffic obfuscation, or any other evasive behavior, it is outside the scope of this project and should be rejected.

See [safety-report.md](safety-report.md) for the full project safety and contributor policy.

## Reporting a vulnerability

If you discover a security issue in the project itself, report it privately through the GitHub Security advisory flow instead of creating a public issue.
