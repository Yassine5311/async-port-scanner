"""
async-port-scanner
===================

A hardened, async TCP-connect port scanner for hosts/networks you own
or are explicitly authorized to test.

Public API:
    resolve_target, parse_port_spec, is_local_or_private,
    check_port, run_scan, save_results, ScanResult
"""

from .scanner import (
    ScanConfig,
    ScanResult,
    check_port,
    is_local_or_private,
    parse_port_spec,
    resolve_target,
    run_scan,
    save_results,
    scan_ports,
    scan_target,
    service_name,
)

__version__ = "1.0.0"

__all__ = [
    "ScanConfig",
    "ScanResult",
    "resolve_target",
    "parse_port_spec",
    "is_local_or_private",
    "service_name",
    "check_port",
    "run_scan",
    "scan_ports",
    "scan_target",
    "save_results",
    "__version__",
]
