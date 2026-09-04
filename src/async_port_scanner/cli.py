"""Command-line interface for async-port-scanner."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import socket
import sys
import time

from . import __version__
from .scanner import (
    MAX_CONCURRENCY_CAP,
    MAX_TIMEOUT,
    is_local_or_private,
    parse_port_spec,
    resolve_target,
    run_scan,
    save_results,
)

LOG = logging.getLogger("async_port_scanner")


def confirm_authorization(target_ip: str, assume_yes: bool) -> bool:
    """
    Require explicit confirmation before scanning a non-local/non-private
    target. Only scan systems you own or are authorized to test.
    """
    if is_local_or_private(target_ip):
        return True
    if assume_yes:
        return True
    print(
        f"\n[!] Target {target_ip} is a public/external address.\n"
        "    Only scan systems you own or are explicitly authorized to test.\n"
        "    Unauthorized scanning may violate laws (e.g. CFAA) or terms of service."
    )
    answer = input("    Type 'yes' to confirm you are authorized to scan this target: ").strip().lower()
    return answer == "yes"


async def _self_test(iterations: int = 5) -> bool:
    """
    Spin up two real local TCP listeners plus one known-closed port and
    scan them repeatedly, asserting correct/consistent detection each
    time (a lightweight form of "loop testing").
    """

    async def _dummy_handler(reader, writer):
        writer.write(b"hello\n")
        await writer.drain()
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    server1 = await asyncio.start_server(_dummy_handler, "127.0.0.1", 0)
    server2 = await asyncio.start_server(_dummy_handler, "127.0.0.1", 0)
    open_port_1 = server1.sockets[0].getsockname()[1]
    open_port_2 = server2.sockets[0].getsockname()[1]

    closed_port = open_port_1 + 1
    while closed_port in (open_port_1, open_port_2) or closed_port > 65535:
        closed_port += 1

    ports_to_scan = sorted({open_port_1, open_port_2, closed_port})
    all_passed = True

    try:
        for i in range(1, iterations + 1):
            results = await run_scan(
                "127.0.0.1",
                ports_to_scan,
                family=socket.AF_INET,
                max_concurrency=10,
                timeout=0.5,
                grab_banner=True,
                show_progress=False,
            )
            found_ports = {r.port for r in results}
            expected_open = {open_port_1, open_port_2}
            ok = found_ports == expected_open
            status = "PASS" if ok else "FAIL"
            print(
                f"[self-test] iteration {i}/{iterations}: found={sorted(found_ports)} "
                f"expected={sorted(expected_open)} -> {status}"
            )
            all_passed = all_passed and ok
    finally:
        server1.close()
        server2.close()
        await server1.wait_closed()
        await server2.wait_closed()

    print(f"\n[self-test] {'ALL PASSED' if all_passed else 'SOME FAILED'} ({iterations} iterations)")
    return all_passed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Hardened async TCP-connect port scanner.",
    )
    parser.add_argument("target", nargs="?", help="IP address or hostname to scan")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan, e.g. '80', '1-1024', '22,80,443,8000-8100' (default: 1-1024)",
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=200,
        help=f"Max concurrent connections (1-{MAX_CONCURRENCY_CAP}, default: 200)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help=f"Per-connection timeout in seconds (default: 1.0, max {MAX_TIMEOUT})",
    )
    parser.add_argument("--banner", action="store_true", help="Attempt to grab service banners")
    parser.add_argument("-o", "--output", help="Save results to file (.json, .csv, or .txt)")
    parser.add_argument(
        "--yes", action="store_true",
        help="Skip the authorization confirmation prompt for non-local targets",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run built-in loop self-test against local listeners and exit",
    )
    parser.add_argument(
        "--self-test-iterations", type=int, default=5,
        help="Number of loop iterations for --self-test (default: 5)",
    )
    parser.add_argument("--version", action="version", version=f"async-port-scanner {__version__}")
    return parser


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(message)s")


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.self_test:
        passed = asyncio.run(_self_test(args.self_test_iterations))
        sys.exit(0 if passed else 1)

    if not args.target:
        parser.error("target is required unless --self-test is used")

    try:
        target_ip, family = resolve_target(args.target)
        ports = parse_port_spec(args.ports)
    except ValueError as err:
        print(f"[-] Input error: {err}")
        sys.exit(1)

    if args.concurrency < 1 or args.concurrency > MAX_CONCURRENCY_CAP:
        print(f"[-] Concurrency must be between 1 and {MAX_CONCURRENCY_CAP}.")
        sys.exit(1)
    if args.timeout <= 0 or args.timeout > MAX_TIMEOUT:
        print(f"[-] Timeout must be between 0 and {MAX_TIMEOUT} seconds.")
        sys.exit(1)

    if not confirm_authorization(target_ip, args.yes):
        print("[-] Authorization not confirmed. Aborting.")
        sys.exit(1)

    print(
        f"Scanning {args.target} ({target_ip}) — {len(ports)} port(s), "
        f"concurrency={args.concurrency}, timeout={args.timeout}s\n"
    )

    start = time.monotonic()
    try:
        results = asyncio.run(
            run_scan(
                target_ip, ports, family, args.concurrency, args.timeout,
                args.banner, show_progress=True,
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled by user.")
        sys.exit(130)
    elapsed = time.monotonic() - start

    print(f"\nScan completed in {elapsed:.2f}s. Found {len(results)} open port(s).")
    for r in results:
        line = f"  {r.port:<6} {r.service or 'unknown'}"
        if r.banner:
            line += f"  banner={r.banner!r}"
        print(line)

    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
