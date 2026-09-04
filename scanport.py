import asyncio

from async_port_scanner import parse_port_spec, resolve_target, run_scan


async def main():
    ip, family = resolve_target("localhost")
    ports = parse_port_spec("1-1024")
    results = await run_scan(ip, ports, family=family, max_concurrency=200, timeout=1.0)
    for r in results:
        print(r.port, r.service, r.banner)


asyncio.run(main())
