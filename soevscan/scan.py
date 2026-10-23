"""Run all lookups for one domain and collect the results in a ``ScanResult``.

Only ``normalize_domain`` raises, on invalid input and before any network call. After that,
every failure becomes a status in the result, so a scan always returns a complete
``ScanResult``. Lookups run one after another; there is no overall deadline.
"""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime

import dns.resolver
import httpx
import idna

from soevscan import __version__
from soevscan.lookups.asn import AsnLookup, make_http_client
from soevscan.lookups.dns import lookup_mx, lookup_ns, lookup_txt, make_resolver, resolve_host
from soevscan.lookups.models import HostAddresses, ScanResult, SpfResult
from soevscan.lookups.spf import lookup_spf


@dataclass
class ScanSettings:
    """Settings for one scan. Timeouts are in seconds."""

    dns_timeout: float = 5.0
    http_timeout: float = 10.0
    nameservers: list[str] | None = None  # None: use the system resolver
    sourceapp: str = "soevscan"  # sent to RIPEstat with every request


def normalize_domain(raw: str) -> str:
    """Return ``raw`` as a lowercase ASCII domain name without trailing dot.

    Internationalised names are converted to punycode with IDNA 2008 (UTS #46 mapping,
    non-transitional), so ``straße.de`` becomes ``xn--strae-oqa.de``, not ``strasse.de``.
    Raises ``ValueError`` if ``raw`` is not a plain domain name of at least two labels.
    """
    domain = raw.strip()
    if not domain:
        raise ValueError("domain is empty")
    if "://" in domain:
        raise ValueError(f"{raw!r} contains a scheme; give only the domain name, e.g. example.nl")
    if any(char.isspace() for char in domain):
        raise ValueError(f"{raw!r} contains spaces")
    if "/" in domain:
        raise ValueError(f"{raw!r} contains a path; give only the domain name")
    if ":" in domain:
        raise ValueError(f"{raw!r} contains a port or is an IPv6 address; give a domain name")

    domain = domain.lower().removesuffix(".")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError(f"{raw!r} is an IP address; give a domain name")
    if "" in domain.split("."):
        raise ValueError(f"{raw!r} contains an empty label")

    try:
        domain = idna.encode(domain, uts46=True).decode("ascii").lower()
    except idna.IDNAError as e:
        raise ValueError(f"{raw!r} is not a valid domain name: {e}") from None
    if "." not in domain:
        raise ValueError(f"{raw!r} is a single-label name; give a full domain, e.g. example.nl")
    return domain


def scan_domain(
    domain: str,
    settings: ScanSettings | None = None,
    *,
    resolver: dns.resolver.Resolver | None = None,
    http_client: httpx.Client | None = None,
) -> ScanResult:
    """Look up NS, MX, TXT, SPF, web addresses and the ASNs of all IPs found for ``domain``.

    ``resolver`` and ``http_client`` are for tests; by default they are created from
    ``settings``. A client created here is closed afterwards; a client passed in is not.
    Raises ``ValueError`` only for an invalid ``domain``, before any network call.
    """
    domain = normalize_domain(domain)
    settings = settings or ScanSettings()
    scanned_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if resolver is None:
        resolver = make_resolver(settings.dns_timeout, settings.nameservers)

    nameservers = lookup_ns(domain, resolver)
    mx = lookup_mx(domain, resolver)
    txt = lookup_txt(domain, resolver)
    spf = lookup_spf(domain, txt, resolver)
    web = [resolve_host(domain, resolver), resolve_host(f"www.{domain}", resolver)]

    sources: dict[str, set[str]] = {}
    for host in web:
        _add_host(sources, host, f"web:{host.name}")
    for host in nameservers.nameservers:
        _add_host(sources, host, f"ns:{host.name}")
    for mx_host in mx.hosts:
        if mx_host.addresses is not None:
            _add_host(sources, mx_host.addresses, f"mx:{mx_host.exchange}")
    _add_spf(sources, spf, domain)
    ips = sorted(sources, key=lambda ip: ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))

    client = http_client if http_client is not None else make_http_client(settings.http_timeout)
    try:
        lookup = AsnLookup(client, settings.sourceapp)
        asn = {ip: lookup.lookup(ip) for ip in ips}
    finally:
        if http_client is None:
            client.close()

    return ScanResult(
        domain=domain,
        scanned_at=scanned_at,
        tool_version=__version__,
        nameservers=nameservers,
        mx=mx,
        txt=txt,
        spf=spf,
        web=web,
        ip_sources={ip: sorted(sources[ip]) for ip in ips},
        asn=asn,
    )


def _add_host(sources: dict[str, set[str]], host: HostAddresses, label: str) -> None:
    """Record every address of ``host`` under ``label``."""
    for ip in host.ipv4 + host.ipv6:
        _add(sources, ip, label)


def _add_spf(sources: dict[str, set[str]], spf: SpfResult, domain: str) -> None:
    """Record the single addresses in the SPF record and in followed includes and redirects."""
    records = [(domain, spf.ip4, spf.ip6)]
    records += [(include.domain, include.ip4, include.ip6) for include in spf.includes]
    for source, ip4, ip6 in records:
        for value, version in [(v, 4) for v in ip4] + [(v, 6) for v in ip6]:
            ip = _single_address(value, version)
            if ip is not None:
                _add(sources, ip, f"spf:{source}")


def _single_address(value: str, version: int) -> str | None:
    """The canonical address if ``value`` is one IP of the given version, else None.

    ``192.0.2.1`` and ``192.0.2.1/32`` (or ``/128`` for IPv6) are single addresses; ranges,
    invalid values and addresses of the other version are not.
    """
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if network.version != version or network.prefixlen != network.max_prefixlen:
        return None
    return str(network.network_address)


def _add(sources: dict[str, set[str]], ip: str, label: str) -> None:
    """Record ``label`` for ``ip`` under its canonical form."""
    sources.setdefault(str(ipaddress.ip_address(ip)), set()).add(label)
