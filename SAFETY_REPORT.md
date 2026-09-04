# Safety Report — async-port-scanner v1.0.0

**Scope:** `src/async_port_scanner/{__init__,scanner,cli,__main__}.py`, `tests/test_scanner.py`, packaging and docs.
**Reviewed:** full source re-read, not just a diff.

## Summary

This is a TCP-connect scanner — the same technique used by `nmap -sT`, `netcat`, and countless admin tools. It has no exploit code, no payload delivery, and no capability beyond "attempt a connection, report if it succeeded." The main residual risk is **misuse by the operator** (scanning something they don't have permission to scan), not a flaw in the code itself. That risk is mitigated but not eliminated by the design. Details below.

## 1. Dual-use / misuse potential

| Concern | Assessment |
|---|---|
| Could this be used to scan a target the user doesn't own? | **Yes, if they type `--yes` or confirm the prompt.** This is inherent to any port scanner — it can't distinguish "my server" from "someone else's server" by IP alone. |
| Does it help evade detection (fragmentation, decoys, spoofed source, timing jitter to dodge IDS)? | **No.** Plain `asyncio.open_connection` — a normal, logged, visible TCP handshake. Nothing stealthy. |
| Does it enable anything beyond port state? | **Only banner grabbing** (reads up to 1 KB from an already-open connection). This is passive/reactive — it reads whatever the service sends, it doesn't send exploit payloads or fuzz the service. |
| Could it be scripted for mass/automated scanning at scale? | **Yes, via `--yes` in a script.** That flag exists deliberately for legitimate CI/lab use against infrastructure the user controls, but it does remove the human-in-the-loop check for anyone who chooses to set it in a loop over many IPs. This is a known, documented trade-off (see §4). |

**Conclusion:** the tool's capability ceiling is "is this port open, and what does it say back" — equivalent to what any junior sysadmin can already do with `nc -zv` in a shell loop. It doesn't lower the bar for anything more dangerous than that.

## 2. Authorization gate — how it actually behaves

`cli.confirm_authorization()`:
- Auto-allows loopback, RFC1918 private ranges, and link-local addresses (`is_local_or_private` in `scanner.py`) — no prompt.
- For everything else, prints a warning and requires the literal string `"yes"` typed at a prompt.
- `--yes` skips the prompt unconditionally.

**Verified in testing:** a scan against `8.8.8.8` without `--yes` and with `no` piped to stdin was correctly refused (exit code 1).

**Limitations of this gate (worth stating plainly, not hiding):**
- It's a **speed bump, not a control**. Anyone can pass `--yes` immediately. It stops accidental/casual misuse and unattended-script mistakes; it does not stop a determined bad actor, and isn't intended to.
- It checks IP *class* (private vs. public), not actual ownership. A private IP is only "safe by default" because it's overwhelmingly likely to be the user's own LAN — but a user on a shared or corporate network technically could point it at a private-range neighbor without a prompt. This is a reasonable default (matches how e.g. `nmap` and most scanners behave with no gate at all), but it's not a real authorization check.
- The gate lives only in `cli.py`. Anyone importing `scanner.run_scan()` directly as a library bypasses it entirely — this is intentional (a library shouldn't force an interactive prompt on the calling application) but means the safeguard is CLI-only. This should be documented more prominently (currently only implied by SECURITY.md).

## 3. Resource-exhaustion / DoS safety (self-inflicted and target-facing)

| Vector | Mitigation | Verified |
|---|---|---|
| Unbounded concurrent sockets exhausting the scanning machine's file descriptors | `MAX_CONCURRENCY_CAP = 2000`, enforced in both `run_scan()` (clamped) and `cli.py` (rejected outright if out of range) | Yes — tested with `max_concurrency=999999`, silently clamped |
| Runaway per-connection timeout hanging the process | `MAX_TIMEOUT = 30.0`, clamped in `run_scan()`, rejected in CLI if `<= 0` or `> 30` | Yes |
| A malicious/misbehaving service sending unbounded data during banner grab (memory exhaustion) | `BANNER_READ_BYTES = 1024` cap, `BANNER_READ_TIMEOUT = 1.5s` cap, wrapped in `asyncio.wait_for` | Yes — `_grab_banner` catches `TimeoutError`/`OSError` and returns `None`, never raises upstream |
| A huge port list (`1-65535`) creating one task per port up front | Queue-backed worker pool (`asyncio.Queue` + fixed-size worker set), not one task per port | Yes — confirmed via code read; workers pull from queue rather than being spawned per-port |
| Aggressive scanning overwhelming the *target* (unintentional DoS against someone else's service) | Concurrency/timeout caps limit worst case, but there is **no built-in rate limiting or backoff** beyond the semaphore-equivalent worker count | **Gap — see §5** |

## 4. Input validation

- `parse_port_spec`: rejects empty specs, non-numeric chunks, and ports outside 1–65535; handles reversed ranges (`25-20`) and dedupes. Tested against 7 malformed-input cases, all correctly rejected.
- `resolve_target`: rejects empty input; on resolution failure raises `ValueError` with the underlying `gaierror`, never lets a `socket.gaierror` propagate raw.
- No use of `eval`, `exec`, `os.system`, `subprocess` with shell=True, or any string-built shell/SQL/format-string sink anywhere in the codebase. Confirmed by re-reading every file — there is no shell interaction at all.
- No secrets, credentials, or hardcoded IPs/hostnames anywhere in source.

## 5. Gaps and recommendations

These aren't blockers for a personal/lab/authorized-pentest tool, but worth knowing before wider distribution:

1. **No rate limiting toward the target.** High concurrency + low timeout against a fragile or rate-limited service could look like (or functionally be) a mini denial-of-service, even with authorization. Consider an optional `--delay`/`--rate` flag for cautious use against production systems.
2. **The authorization gate is easy to bypass and CLI-only.** Fine for the stated threat model (prevent *accidental* misuse), but the README/SECURITY.md should say this explicitly rather than let a reader assume it's a hard control. (Recommend adding one sentence to SECURITY.md: "This is a reminder, not an access control — it will not stop someone determined to misuse the tool.")
3. **No logging of who ran what, when, against whom.** For any use in a team/organizational context (vs. personal lab use), an audit trail (e.g., append-only log of target + timestamp + user) would matter for accountability and incident review.
4. **`service_name()` via `/etc/services` can be stale/misleading** — it reports the conventional service for a port number, not what's actually listening. Low risk (it's cosmetic), but could mislead a user into false confidence about what a port is running; the banner (when available) is the more trustworthy signal and is already presented alongside it.
5. **IPv6 scope/zone handling untested.** IPv6 literal parsing works, but link-local IPv6 (`fe80::/10`) targets often need a zone index (`%eth0`) to actually connect — not exercised in the test suite.

## 6. Test coverage assessment

28 tests, all passing on re-run:
- Port-spec parsing: 13 tests (valid + 7 invalid-input cases)
- Target resolution: 4 tests (IPv4, IPv6, empty, unresolvable host)
- Locality classification: 3 tests
- Scan correctness against **real local sockets** (not mocks): 5 repeated iterations of open+closed detection, plus concurrency-clamping and banner-grab tests

This is solid coverage for the scanning logic itself. It does **not** cover the CLI's authorization prompt (`confirm_authorization`) or argument-validation error paths (bad concurrency/timeout values) — those are simple enough to be low-risk, but a `tests/test_cli.py` would close that gap and is the single most valuable addition I'd make next.

## Bottom line

The code does what it claims, has no hidden capability beyond stated scope, and the safeguards that exist (concurrency/timeout caps, bounded banner reads, input validation, the authorization prompt) are real and verified working — not just comments. The main thing to be honest with yourself and any future users about is **what the authorization gate is not**: it's a courtesy reminder against fat-fingering a public IP, not a permission system. If you intend for this to be used by anyone other than you, I'd tighten §5 items 1–3 first.
