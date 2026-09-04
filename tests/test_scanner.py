"""
Unit tests for async_port_scanner, including repeated ("loop") scans
against real local sockets to catch flakiness or race conditions.
"""

import asyncio
import contextlib
import socket

import pytest

from async_port_scanner import (
    is_local_or_private,
    parse_port_spec,
    resolve_target,
    run_scan,
    scan_ports,
)


# --------------------------------------------------------------------------- #
# parse_port_spec
# --------------------------------------------------------------------------- #
def test_parse_single_port():
    assert parse_port_spec("80") == [80]


def test_parse_comma_list():
    assert parse_port_spec("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert parse_port_spec("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_mixed():
    assert parse_port_spec("22,80,8000-8003") == [22, 80, 8000, 8001, 8002, 8003]


def test_parse_dedup_and_sort():
    assert parse_port_spec("80,22,80,22-24") == [22, 23, 24, 80]


def test_parse_reversed_range():
    assert parse_port_spec("25-20") == [20, 21, 22, 23, 24, 25]


@pytest.mark.parametrize("bad_spec", ["", "0", "70000", "abc", "10-", "-10", "10-abc"])
def test_parse_invalid(bad_spec):
    with pytest.raises(ValueError):
        parse_port_spec(bad_spec)


# --------------------------------------------------------------------------- #
# resolve_target
# --------------------------------------------------------------------------- #
def test_resolve_ipv4_literal():
    ip, family = resolve_target("127.0.0.1")
    assert ip == "127.0.0.1"
    assert family == socket.AF_INET


def test_resolve_ipv6_literal():
    ip, family = resolve_target("::1")
    assert ip == "::1"
    assert family == socket.AF_INET6


def test_resolve_empty_raises():
    with pytest.raises(ValueError):
        resolve_target("   ")


def test_resolve_bad_hostname_raises():
    with pytest.raises(ValueError):
        resolve_target("this-host-should-not-exist.invalid.")


# --------------------------------------------------------------------------- #
# is_local_or_private
# --------------------------------------------------------------------------- #
def test_is_local_loopback():
    assert is_local_or_private("127.0.0.1") is True


def test_is_local_private():
    assert is_local_or_private("192.168.1.5") is True


def test_is_local_public():
    assert is_local_or_private("8.8.8.8") is False


# --------------------------------------------------------------------------- #
# run_scan — real local sockets, run in a loop to catch flakiness
# --------------------------------------------------------------------------- #
async def _make_listener():
    async def handler(reader, writer):
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
@pytest.mark.parametrize("iteration", range(5))
async def test_scan_detects_open_and_closed_ports_repeatedly(iteration):
    server, open_port = await _make_listener()
    closed_port = open_port + 1
    while closed_port == open_port or closed_port > 65535:
        closed_port += 1

    try:
        results = await run_scan(
            "127.0.0.1",
            [open_port, closed_port],
            family=socket.AF_INET,
            max_concurrency=5,
            timeout=0.5,
            show_progress=False,
        )
        found = {r.port for r in results}
        assert found == {open_port}
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_run_scan_empty_ports_returns_empty():
    results = await run_scan("127.0.0.1", [], show_progress=False)
    assert results == []


@pytest.mark.asyncio
async def test_scan_ports_alias_works_like_run_scan():
    server, open_port = await _make_listener()
    try:
        results = await scan_ports(
            "127.0.0.1",
            [open_port],
            max_concurrency=5,
            timeout=0.5,
            show_progress=False,
        )
        assert {r.port for r in results} == {open_port}
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_run_scan_respects_concurrency_bounds():
    # concurrency higher than MAX_CONCURRENCY_CAP should be clamped, not error
    server, open_port = await _make_listener()
    try:
        results = await run_scan(
            "127.0.0.1",
            [open_port],
            max_concurrency=999999,
            timeout=0.5,
            show_progress=False,
        )
        assert {r.port for r in results} == {open_port}
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_banner_grab():
    async def handler(reader, writer):
        writer.write(b"HELLO-BANNER\r\n")
        await writer.drain()
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        results = await run_scan(
            "127.0.0.1", [port], timeout=0.5, grab_banner=True, show_progress=False
        )
        assert len(results) == 1
        assert results[0].banner == "HELLO-BANNER"
    finally:
        server.close()
        await server.wait_closed()
