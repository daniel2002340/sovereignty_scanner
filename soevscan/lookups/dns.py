"""DNS lookups: NS, MX, TXT and the A/AAAA addresses of hosts.

These functions only collect raw facts. They never raise on DNS problems; a failure becomes a
``LookupStatus`` plus a short ``error`` message in the returned dataclass. Every function takes
the resolver as a parameter, so callers choose which resolver to trust and tests can pass a fake.
"""

import ipaddress

import dns.exception
import dns.name
import dns.resolver

from soevscan.lookups.models import (
    HostAddresses,
    LookupStatus,
    MxHost,
    MxResult,
    NameserverResult,
    TxtResult,
)


def make_resolver(timeout: float, nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    """Create a resolver that uses the system configuration, or ``nameservers`` if given.

    ``timeout`` is the total time in seconds one query may take, including retries.
    """
    resolver = dns.resolver.Resolver(configure=nameservers is None)
    if nameservers is not None:
        resolver.nameservers = nameservers
    resolver.lifetime = timeout
    return resolver


def resolve_host(name: str, resolver: dns.resolver.Resolver) -> HostAddresses:
    """Look up the A and AAAA records of ``name``, recording the outcome of each separately."""
    name = _normalise(name)
    result = HostAddresses(name=name, ipv4_status=LookupStatus.OK, ipv6_status=LookupStatus.OK)
    for rdtype in ("A", "AAAA"):
        answer, status, error = _query(resolver, name, rdtype)
        addresses = []
        if answer is not None:
            addresses = sorted((rdata.address for rdata in answer), key=ipaddress.ip_address)
            if result.canonical_name is None and answer.canonical_name != answer.qname:
                result.canonical_name = _normalise(answer.canonical_name)
        if error is not None:
            result.errors.append(f"{rdtype}: {error}")
        if rdtype == "A":
            result.ipv4, result.ipv4_status = addresses, status
        else:
            result.ipv6, result.ipv6_status = addresses, status
    return result


def lookup_ns(domain: str, resolver: dns.resolver.Resolver) -> NameserverResult:
    """Look up the NS records of ``domain`` and the addresses of each nameserver."""
    answer, status, error = _query(resolver, _normalise(domain), "NS")
    if answer is None:
        return NameserverResult(status=status, error=error)
    names = sorted({_normalise(rdata.target) for rdata in answer})
    return NameserverResult(
        status=status, nameservers=[resolve_host(name, resolver) for name in names]
    )


def lookup_mx(domain: str, resolver: dns.resolver.Resolver) -> MxResult:
    """Look up the MX records of ``domain``, sorted by preference, and resolve each exchange.

    A sole ``0 .`` record is a null MX (RFC 7505): the domain accepts no mail. A ``.`` target
    in any other form is kept as a host but not resolved, and noted in ``error``. No implicit-MX
    fallback to the domain's own addresses is applied.
    """
    answer, status, error = _query(resolver, _normalise(domain), "MX")
    if answer is None:
        return MxResult(status=status, error=error)

    records = sorted((rdata.preference, _normalise(rdata.exchange)) for rdata in answer)
    if records == [(0, ".")]:
        return MxResult(status=status, null_mx=True)

    hosts = []
    for preference, exchange in records:
        addresses = None if exchange == "." else resolve_host(exchange, resolver)
        hosts.append(MxHost(preference=preference, exchange=exchange, addresses=addresses))

    note = None
    if any(exchange == "." for _, exchange in records):
        if len(records) > 1:
            note = "null MX ('0 .') present alongside other MX records (RFC 7505 violation)"
        else:
            note = "null MX ('.') with non-zero preference (RFC 7505 violation)"
    return MxResult(status=status, error=note, hosts=hosts)


def lookup_txt(domain: str, resolver: dns.resolver.Resolver) -> TxtResult:
    """Look up all TXT records of ``domain``, joining the strings of each record into one."""
    answer, status, error = _query(resolver, _normalise(domain), "TXT")
    if answer is None:
        return TxtResult(status=status, error=error)
    records = sorted(b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answer)
    return TxtResult(status=status, records=records)


def _normalise(name: str | dns.name.Name) -> str:
    """Return a host name in lowercase without the trailing dot; the root name stays ``.``."""
    text = str(name).lower()
    return text if text == "." else text.rstrip(".")


def _query(
    resolver: dns.resolver.Resolver, name: str, rdtype: str
) -> tuple[dns.resolver.Answer | None, LookupStatus, str | None]:
    """Run one query. Returns the answer, or None with a failure status and message."""
    try:
        # The trailing dot makes the name absolute, so no search domains are appended.
        return resolver.resolve(name + ".", rdtype), LookupStatus.OK, None
    except dns.exception.DNSException as exc:
        status, error = _failure(exc, name, rdtype)
        return None, status, error


def _failure(exc: dns.exception.DNSException, name: str, rdtype: str) -> tuple[LookupStatus, str]:
    """Map a dnspython exception to a lookup status and a short message."""
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return LookupStatus.NXDOMAIN, f"{name} does not exist"
    if isinstance(exc, dns.resolver.NoAnswer):
        return LookupStatus.NO_RECORDS, f"no {rdtype} records for {name}"
    if isinstance(exc, dns.exception.Timeout):
        return LookupStatus.TIMEOUT, "timed out"
    if isinstance(exc, dns.resolver.NoNameservers):
        return LookupStatus.ERROR, "no nameserver gave a usable answer (e.g. SERVFAIL)"
    return LookupStatus.ERROR, f"DNS error: {exc}"
