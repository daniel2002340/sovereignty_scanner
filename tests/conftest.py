import json
from collections.abc import Iterator
from pathlib import Path

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx

from soevscan.lookups.asn import AsnLookup


def rdata(rdtype: str, text: str) -> dns.rdata.Rdata:
    """Build a real rdata object, e.g. ``rdata("MX", "10 mail.example.nl.")``."""
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text)


class FakeAnswer:
    """The parts of ``dns.resolver.Answer`` the lookups use: iteration, qname, canonical_name."""

    def __init__(self, qname: str, canonical_name: str, rdatas: list[dns.rdata.Rdata]) -> None:
        self.qname = dns.name.from_text(qname)
        self.canonical_name = dns.name.from_text(canonical_name)
        self.rdatas = rdatas

    def __iter__(self) -> Iterator[dns.rdata.Rdata]:
        return iter(self.rdatas)


class FakeResolver:
    """Offline stand-in for ``dns.resolver.Resolver``.

    ``records`` maps ``(name, rdtype)`` to a list of rdata or to an exception to raise.
    ``cnames`` maps an alias to its target; queries follow it like a real resolver.
    A missing entry gives NoAnswer if the name has other records, otherwise NXDOMAIN.
    """

    def __init__(
        self,
        records: dict[tuple[str, str], list[dns.rdata.Rdata] | dns.exception.DNSException],
        cnames: dict[str, str] | None = None,
    ) -> None:
        self.records = records
        self.cnames = cnames or {}
        self.queries: list[tuple[str, str]] = []

    def resolve(self, qname: str, rdtype: str) -> FakeAnswer:
        name = qname.rstrip(".").lower()
        self.queries.append((name, rdtype))
        target = name
        while target in self.cnames:
            target = self.cnames[target]
        entry = self.records.get((target, rdtype))
        if isinstance(entry, Exception):
            raise entry
        if entry is None:
            if any(known == target for known, _ in self.records):
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NXDOMAIN()
        return FakeAnswer(qname, target + ".", entry)


FIXTURES = Path(__file__).parent / "fixtures"

RIPE_IPV4 = "193.0.6.139"
RIPE_IPV6 = "2001:67c:2e8:22::c100:68b"
RIPE_HOLDER = "RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"

Route = httpx.Response | Exception


def fixture(name: str) -> httpx.Response:
    """A response with the body of a fixture captured from the real RIPEstat API."""
    return httpx.Response(200, json=json.loads((FIXTURES / name).read_text()))


def network_info(asns: list[str], prefix: str = "198.51.100.0/24") -> httpx.Response:
    return httpx.Response(200, json={"status": "ok", "data": {"asns": asns, "prefix": prefix}})


def as_overview(holder: str | None) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok", "data": {"holder": holder}})


class FakeRipestat:
    """A MockTransport that answers by ``(data call, resource)`` and records every request.

    A route is a response or an exception to raise. A request without a route fails the test.
    """

    def __init__(self, routes: dict[tuple[str, str], Route]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        call = request.url.path.split("/")[2]  # /data/<call>/data.json
        route = self.routes[(call, request.url.params["resource"])]
        if isinstance(route, Exception):
            raise route
        return route

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def lookup(self, sourceapp: str = "soevscan") -> AsnLookup:
        return AsnLookup(self.client(), sourceapp)

    def count(self, call: str) -> int:
        return sum(1 for r in self.requests if r.url.path == f"/data/{call}/data.json")


def ripe_routes() -> dict[tuple[str, str], Route]:
    return {
        ("network-info", RIPE_IPV4): fixture("network_info_193.0.6.139.json"),
        ("network-info", RIPE_IPV6): fixture("network_info_2001_67c_2e8_22__c100_68b.json"),
        ("as-overview", "AS3333"): fixture("as_overview_AS3333.json"),
    }
