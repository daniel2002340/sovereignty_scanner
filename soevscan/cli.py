"""Command-line interface: ``soevscan <domain> [--json]``.

This is the only module that writes to stdout or stderr. Exit codes: 0 when the scan ran
(failed lookups are results, not errors), 2 for invalid input, 130 on Ctrl-C.
"""

import argparse
import ipaddress
import math
import sys

from soevscan import __version__
from soevscan.lookups.models import HostAddresses, LookupStatus, ScanResult, to_json
from soevscan.scan import ScanSettings, normalize_domain, scan_domain


def main(argv: list[str] | None = None) -> int:
    """Run the CLI with ``argv`` (default: ``sys.argv[1:]``) and return the exit code."""
    try:
        args = _parser().parse_args(argv)
        try:
            domain = normalize_domain(args.domain)
        except ValueError as e:
            print(f"soevscan: error: {e}", file=sys.stderr)
            return 2
        result = scan_domain(domain, _settings(args))
        print(to_json(result) if args.json else summary(result))
        return 0
    except KeyboardInterrupt:
        print("soevscan: interrupted", file=sys.stderr)
        return 130


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soevscan",
        description="Passively look up which parties a domain's infrastructure depends on.",
    )
    parser.add_argument("domain", help="domain name to scan, e.g. example.nl")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument(
        "--dns-timeout",
        type=_positive_seconds,
        metavar="SECONDS",
        help=f"timeout per DNS query (default: {ScanSettings.dns_timeout})",
    )
    parser.add_argument(
        "--http-timeout",
        type=_positive_seconds,
        metavar="SECONDS",
        help=f"timeout per RIPEstat request (default: {ScanSettings.http_timeout})",
    )
    parser.add_argument(
        "--resolver",
        type=_ip_address,
        action="append",
        metavar="IP",
        help="DNS resolver to use instead of the system resolver; repeat for more than one",
    )
    parser.add_argument(
        "--sourceapp",
        metavar="NAME",
        help=f"name sent to RIPEstat with every request (default: {ScanSettings.sourceapp})",
    )
    parser.add_argument("--version", action="version", version=f"soevscan {__version__}")
    return parser


def _positive_seconds(value: str) -> float:
    """argparse type: a finite number of seconds greater than zero."""
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be a number greater than 0")
    return seconds


def _ip_address(value: str) -> str:
    """argparse type: an IPv4 or IPv6 address, returned in canonical form."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an IPv4 or IPv6 address") from None


def _settings(args: argparse.Namespace) -> ScanSettings:
    """ScanSettings with only the options given on the command line; the rest keep defaults."""
    given = {
        "dns_timeout": args.dns_timeout,
        "http_timeout": args.http_timeout,
        "nameservers": args.resolver,
        "sourceapp": args.sourceapp,
    }
    return ScanSettings(**{name: value for name, value in given.items() if value is not None})


def summary(result: ScanResult) -> str:
    """A short plain-text overview of ``result``; the full data is in the JSON output."""
    ns, mx, txt, spf = result.nameservers, result.mx, result.txt, result.spf
    mx_detail = "null MX (accepts no mail)" if mx.null_mx else _count(len(mx.hosts), "host")
    spf_detail = f"{len(spf.ip4)} ip4, {len(spf.ip6)} ip6, {_count(len(spf.includes), 'include')}"
    statuses = [entry.status for entry in result.asn.values()]
    skipped = statuses.count(LookupStatus.SKIPPED)
    failed = sum(status in (LookupStatus.ERROR, LookupStatus.TIMEOUT) for status in statuses)
    asns = {entry.asn for info in result.asn.values() for entry in info.asns}

    lines = [
        f"{result.domain} (scanned {result.scanned_at}, soevscan {result.tool_version})",
        _line("nameservers", ns.status, ns.error, _count(len(ns.nameservers), "host")),
        _line("mx", mx.status, mx.error, mx_detail),
        _line("txt", txt.status, txt.error, _count(len(txt.records), "record")),
        _line("spf", spf.status, spf.error, spf_detail),
        _row("web", "; ".join(_web(host) for host in result.web)),
        _row("ips", f"{len(result.ip_sources)} unique ({skipped} skipped)"),
        _row("asns", f"{len(asns)} unique ({failed} lookups failed)"),
        "Use --json for the full data.",
    ]
    return "\n".join(lines)


def _line(label: str, status: LookupStatus, error: str | None, ok_detail: str) -> str:
    """A row with the status, then the counts if it is ok or the error message if not."""
    detail = ok_detail if status == LookupStatus.OK else (error or "")
    return _row(label, f"{status:<11} {detail}".rstrip())


def _row(label: str, text: str) -> str:
    return f"{label:<12} {text}"


def _web(host: HostAddresses) -> str:
    return f"{host.name}: A {host.ipv4_status}, AAAA {host.ipv6_status}"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"
