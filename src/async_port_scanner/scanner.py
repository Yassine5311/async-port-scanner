"""
Core scanning engine: target resolution, port-spec parsing, the
async TCP-connect scan itself, and result export. No CLI/argparse
code lives here so it can be imported and reused as a library.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import ipaddress
import json
import logging
import socket
from collections.abc import Iterable
from dataclasses import asdict, dataclass

LOG = logging.getLogger("async_port_scanner")

MIN_PORT, MAX_PORT = 1, 65535
MAX_CONCURRENCY_CAP = 2000  # hard ceiling, prevents fd exhaustion
MAX_TIMEOUT = 30.0
BANNER_READ_BYTES = 1024
BANNER_READ_TIMEOUT = 1.5


@dataclass
class ScanResult:
    """A single open-port finding."""

    port: int
    state: str  # currently always "open" -- only open ports are returned
    service: str | None = None
    banner: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    """Reusable configuration for a scan run."""

    family: int = socket.AF_INET
    max_concurrency: int = 200
    timeout: float = 1.0
    grab_banner: bool = False
    show_progress: bool = False


# --------------------------------------------------------------------------- #
# Validation / resolution helpers
# --------------------------------------------------------------------------- #
def resolve_target(target_input: str) -> tuple[str, int]:
    """
    Validate and resolve a target to ``(ip_address, socket_family)``.

    Accepts an IPv4 literal, an IPv6 literal, or a hostname (resolved
    via the OS resolver, preferring an IPv4 result if both exist).

    Raises:
        ValueError: if the input is empty or cannot be resolved.
    """
    target_input = target_input.strip()
    if not target_input:
        raise ValueError("Target input cannot be empty.")

    try:
        ip_obj = ipaddress.ip_address(target_input)
        literal_family: int = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        return str(ip_obj), literal_family
    except ValueError:
        pass  # not a literal IP, try to resolve as hostname

    try:
        infos = socket.getaddrinfo(target_input, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host '{target_input}': {exc}") from exc

    ipv4 = next((i for i in infos if i[0] == socket.AF_INET), None)
    chosen = ipv4 or infos[0]
    resolved_family: int = int(chosen[0])
    ip: str = str(chosen[4][0])
    return ip, resolved_family


def is_local_or_private(ip: str) -> bool:
    """True for loopback / private (RFC1918) / link-local addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


def parse_port_spec(spec: str) -> list[int]:
    """
    Parse a port specification such as ``"80"``, ``"1-1024"``, or
    ``"22,80,443,8000-8100"`` into a sorted, de-duplicated list of ports.

    Raises:
        ValueError: on malformed input or out-of-range ports.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: '{chunk}'") from exc
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            try:
                ports.add(int(chunk))
            except ValueError as exc:
                raise ValueError(f"Invalid port value: '{chunk}'") from exc

    if not ports:
        raise ValueError("No ports specified.")
    for p in ports:
        if not (MIN_PORT <= p <= MAX_PORT):
            raise ValueError(f"Port {p} out of range ({MIN_PORT}-{MAX_PORT}).")
    return sorted(ports)


def service_name(port: int) -> str:
    """Best-effort well-known service name lookup for a TCP port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# --------------------------------------------------------------------------- #
# Core scanning logic
# --------------------------------------------------------------------------- #
async def _grab_banner(reader: asyncio.StreamReader) -> str | None:
    """Best-effort, bounded read of a service banner. Never raises."""
    try:
        data = await asyncio.wait_for(reader.read(BANNER_READ_BYTES), timeout=BANNER_READ_TIMEOUT)
        if not data:
            return None
        return data.decode(errors="replace").strip() or None
    except (asyncio.TimeoutError, OSError):
        return None


async def check_port(
    target_ip: str,
    port: int,
    timeout: float,
    family: int = socket.AF_INET,
    grab_banner: bool = False,
) -> ScanResult | None:
    """
    Attempt a single non-blocking TCP connection.

    Returns:
        A ``ScanResult`` if the port is open, otherwise ``None``.
    """
    writer = None
    try:
        conn = asyncio.open_connection(host=target_ip, port=port, family=family)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)

        banner = None
        if grab_banner:
            banner = await _grab_banner(reader)

        return ScanResult(port=port, state="open", service=service_name(port), banner=banner)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        return None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


async def _worker(
    queue: asyncio.Queue[int],
    target_ip: str,
    family: int,
    timeout: float,
    grab_banner: bool,
    results: list[ScanResult],
    progress: dict,
    progress_lock: asyncio.Lock,
) -> None:
    while True:
        try:
            port = queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        try:
            result = await check_port(target_ip, port, timeout, family, grab_banner)
            if result:
                results.append(result)
                LOG.info("[+] Port %-5d OPEN  %s", result.port, result.service or "")
            async with progress_lock:
                progress["done"] += 1
        finally:
            queue.task_done()


async def run_scan(
    target_ip: str,
    ports: Iterable[int],
    family: int = socket.AF_INET,
    max_concurrency: int = 200,
    timeout: float = 1.0,
    grab_banner: bool = False,
    show_progress: bool = False,
) -> list[ScanResult]:
    """
    Scan the given ports concurrently using a bounded worker pool.

    A queue-backed worker pool is used (rather than spawning one task
    per port up front) so memory and file-descriptor usage stay capped
    regardless of how large the port list is.

    Args:
        target_ip: resolved IP address to scan.
        ports: iterable of port numbers.
        family: socket.AF_INET or socket.AF_INET6.
        max_concurrency: max simultaneous connection attempts (capped
            internally at ``MAX_CONCURRENCY_CAP``).
        timeout: per-connection timeout in seconds (capped at ``MAX_TIMEOUT``).
        grab_banner: attempt to read a short banner from open ports.
        show_progress: print an in-place progress line to stdout.

    Returns:
        A list of ``ScanResult`` for each open port, sorted by port number.
    """
    port_list = list(ports)
    if not port_list:
        return []

    max_concurrency = max(1, min(max_concurrency, MAX_CONCURRENCY_CAP, len(port_list)))
    timeout = max(0.05, min(timeout, MAX_TIMEOUT))

    queue: asyncio.Queue[int] = asyncio.Queue()
    for p in port_list:
        queue.put_nowait(p)

    results: list[ScanResult] = []
    progress = {"done": 0, "total": len(port_list)}
    progress_lock = asyncio.Lock()

    workers = [
        asyncio.create_task(
            _worker(queue, target_ip, family, timeout, grab_banner, results, progress, progress_lock)
        )
        for _ in range(max_concurrency)
    ]

    async def _report_progress() -> None:
        if not show_progress:
            return
        while any(not w.done() for w in workers):
            print(f"\rScanned {progress['done']}/{progress['total']} ports...", end="", flush=True)
            await asyncio.sleep(0.2)
        print(f"\rScanned {progress['done']}/{progress['total']} ports.        ")

    reporter = asyncio.create_task(_report_progress())

    try:
        await asyncio.gather(*workers)
    finally:
        await reporter

    return sorted(results, key=lambda r: r.port)


async def scan_ports(
    target: str,
    ports: str | Iterable[int],
    *,
    family: int | None = None,
    max_concurrency: int = 200,
    timeout: float = 1.0,
    grab_banner: bool = False,
    show_progress: bool = False,
) -> list[ScanResult]:
    """Resolve a hostname or IP and scan the requested ports using the default library API."""
    resolved_ip, resolved_family = resolve_target(target)
    port_list = parse_port_spec(ports) if isinstance(ports, str) else list(ports)
    effective_family = resolved_family if family is None else family
    return await run_scan(
        resolved_ip,
        port_list,
        family=effective_family,
        max_concurrency=max_concurrency,
        timeout=timeout,
        grab_banner=grab_banner,
        show_progress=show_progress,
    )


scan_target = scan_ports


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def save_results(results: list[ScanResult], path: str) -> None:
    """Write scan results to ``path`` as JSON, CSV, or plain text (by extension)."""
    payload = [asdict(r) for r in results]
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
    elif path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            writer.writeheader()
            writer.writerows(payload)
    else:
        with open(path, "w") as f:
            for r in results:
                line = f"{r.port}\t{r.state}\t{r.service or ''}"
                if r.banner:
                    line += f"\t{r.banner}"
                f.write(line + "\n")
    LOG.info("Results written to %s", path)
