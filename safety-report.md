# Safety Report

## Project purpose

This project is a lightweight TCP port scanner designed for legitimate,
authorized network diagnostics, local testing, and controlled operational
validation. It is not a general-purpose reconnaissance or stealth tool.

## Scope

Allowed use cases include:

- local development and self-testing
- home or lab network validation
- authorized security testing of systems you own or manage
- in-scope assessments under explicit written permission

Disallowed use cases include:

- unauthorized scanning of third-party infrastructure
- reconnaissance against public systems without approval
- bypassing access controls, authentication, or alerting systems
- features intended to hide activity, evade detection, or spoof identity
- any use that violates local law, contractual obligations, or service terms

## Built-in safety controls

The project includes guardrails to keep use bounded and predictable:

- a confirmation prompt before scanning non-local targets
- hard limits on concurrency
- careful timeout bounds
- strict validation of port ranges and input values
- limited banner reads to avoid service hang or excessive data capture
- no execution of remote commands, no dynamic code loading, and no obfuscation features

## Contributor expectations

Contributors should preserve the project's narrow, ethical scope.
Contributions must not add features that:

- weaken authorization checks
- enable hidden scanning or anti-forensics behavior
- spoof source addresses or hide network activity
- expand the tool beyond a transparent, bounded TCP-connect scanner

If a proposed change would make the tool more evasive, more aggressive, or
less accountable, it should be rejected as out of scope.

## Reporting concerns

If you identify unsafe or irresponsible behavior in the project, report it
through the project's private security reporting path rather than by
publishing details publicly. For security problems in the code itself, use the
GitHub Security advisory flow. For misuse concerns or feature-safety questions,
open a repository discussion or issue with a clear explanation of the risk and
recommended remediation.

## Summary

This project is intended to support safe, bounded, authorized network checks.
The public safety stance is simple: use it only for clearly authorized,
transparent testing and keep the tool limited to honest, explainable network
validation.
