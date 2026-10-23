import re

import dns.exception
import dns.rdata
import httpx
import pytest
from conftest import (
    RIPE_HOLDER,
    RIPE_IPV4,
    RIPE_IPV6,
    FakeResolver,
    FakeRipestat,
    Route,
    as_overview,
    network_info,
    rdata,
    ripe_routes,
)

import soevscan
from soevscan import scan
from soevscan.lookups.models import AsnEntry, LookupStatus, ScanResult
from soevscan.scan import ScanSettings, normalize_domain, scan_domain

Records = dict[tuple[str, str], list[dns.rdata.Rdata] | dns.exception.DNSException]


def spf_txt(record: str) -> list[dns.rdata.Rdata]:
    return [rdata("TXT", f'"{record}"')]


def surf_routes(*ips: str) -> dict[tuple[str, str], Route]:
    """RIPEstat routes announcing each of ``ips`` from AS1103."""
    routes: dict[tuple[str, str], Route] = {("as-overview", "AS1103"): as_overview("SURFNET-NL")}
    for ip in ips:
        routes[("network-info", ip)] = network_info(["1103"], "145.100.0.0/15")
    return routes


def run(
    records: Records,
    routes: dict[tuple[str, str], Route],
    cnames: dict[str, str] | None = None,
) -> tuple[ScanResult, FakeRipestat]:
    """Scan example.nl with a fake resolver and a fake RIPEstat."""
    ripestat = FakeRipestat(routes)
    resolver = FakeResolver(records, cnames)
    return scan_domain("example.nl", resolver=resolver, http_client=ripestat.client()), ripestat


# --- full scan ---


def happy_records() -> Records:
    return {
        ("example.nl", "A"): [rdata("A", RIPE_IPV4)],
        ("example.nl", "AAAA"): [rdata("AAAA", RIPE_IPV6)],
        ("example.nl", "NS"): [rdata("NS", "ns1.example.nl."), rdata("NS", "ns2.example.nl.")],
        ("example.nl", "MX"): [rdata("MX", "10 mail.example.nl.")],
        ("example.nl", "TXT"): spf_txt("v=spf1 ip4:145.100.0.3 include:_spf.provider.eu -all"),
        ("ns1.example.nl", "A"): [rdata("A", "145.100.0.1")],
        ("ns2.example.nl", "A"): [rdata("A", "10.0.0.1")],
        ("mail.example.nl", "A"): [rdata("A", "145.100.0.1")],
        ("_spf.provider.eu", "TXT"): spf_txt("v=spf1 ip4:198.51.100.0/24 ip6:2a00:1234::1 -all"),
    }


def happy_routes() -> dict[tuple[str, str], Route]:
    return ripe_routes() | surf_routes("145.100.0.1", "145.100.0.3", "2a00:1234::1")


def test_full_scan_fills_every_section() -> None:
    result, ripestat = run(happy_records(), happy_routes(), cnames={"www.example.nl": "example.nl"})

    assert result.domain == "example.nl"
    assert result.tool_version == soevscan.__version__
    assert [ns.name for ns in result.nameservers.nameservers] == [
        "ns1.example.nl",
        "ns2.example.nl",
    ]
    assert [host.exchange for host in result.mx.hosts] == ["mail.example.nl"]
    assert result.txt.status == LookupStatus.OK
    assert result.spf.status == LookupStatus.OK
    assert result.spf.includes[0].ip4 == ["198.51.100.0/24"]
    assert [host.name for host in result.web] == ["example.nl", "www.example.nl"]
    assert result.web[1].canonical_name == "example.nl"

    assert result.ip_sources == {
        "10.0.0.1": ["ns:ns2.example.nl"],
        "145.100.0.1": ["mx:mail.example.nl", "ns:ns1.example.nl"],
        "145.100.0.3": ["spf:example.nl"],
        "193.0.6.139": ["web:example.nl", "web:www.example.nl"],
        "2001:67c:2e8:22::c100:68b": ["web:example.nl", "web:www.example.nl"],
        "2a00:1234::1": ["spf:_spf.provider.eu"],
    }
    assert list(result.asn) == list(result.ip_sources)
    assert result.asn["10.0.0.1"].status == LookupStatus.SKIPPED
    assert result.asn[RIPE_IPV4].asns == [AsnEntry(3333, RIPE_HOLDER)]
    assert result.asn["145.100.0.1"].asns == [AsnEntry(1103, "SURFNET-NL")]
    for ip, info in result.asn.items():
        assert info.ip == ip

    # Every unique public IP is requested once, and each ASN holder once.
    resources = [
        r.url.params["resource"] for r in ripestat.requests if "network-info" in r.url.path
    ]
    assert sorted(resources) == sorted(
        ["145.100.0.1", "145.100.0.3", RIPE_IPV4, RIPE_IPV6, "2a00:1234::1"]
    )
    assert ripestat.count("as-overview") == 2


def test_ip_sources_and_asn_are_ordered_by_address() -> None:
    records: Records = {
        ("example.nl", "AAAA"): [rdata("AAAA", "2a00:1234::1")],
        ("example.nl", "A"): [rdata("A", "145.100.0.20")],
        ("example.nl", "MX"): [rdata("MX", "10 mail.example.nl.")],
        ("mail.example.nl", "A"): [rdata("A", "145.100.0.3")],
        ("example.nl", "TXT"): spf_txt("v=spf1 ip6:2001:67c::1 ip4:145.100.0.100 -all"),
    }
    routes = surf_routes("145.100.0.3", "145.100.0.20", "145.100.0.100", "2001:67c::1")
    routes |= surf_routes("2a00:1234::1")
    result, _ = run(records, routes)
    expected = ["145.100.0.3", "145.100.0.20", "145.100.0.100", "2001:67c::1", "2a00:1234::1"]
    assert list(result.ip_sources) == expected
    assert list(result.asn) == expected


def test_scanned_at_format() -> None:
    result, _ = run({}, {})
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", result.scanned_at)


# --- SPF addresses ---


def test_spf_single_address_included_and_range_not() -> None:
    records: Records = {
        ("example.nl", "TXT"): spf_txt("v=spf1 ip4:145.100.0.3/32 ip4:145.100.0.0/24 -all"),
    }
    result, _ = run(records, surf_routes("145.100.0.3"))
    assert result.ip_sources == {"145.100.0.3": ["spf:example.nl"]}
    assert result.spf.ip4 == ["145.100.0.3/32", "145.100.0.0/24"]


def test_spf_ipv6_becomes_canonical_key() -> None:
    records: Records = {
        ("example.nl", "TXT"): spf_txt("v=spf1 ip6:2001:67C:2E8::1 ip6:2001:67c:2e8::2/128 -all"),
    }
    routes: dict[tuple[str, str], Route] = {
        ("network-info", "2001:67c:2e8::1"): network_info(["3333"], "2001:67c:2e8::/48"),
        ("network-info", "2001:67c:2e8::2"): network_info(["3333"], "2001:67c:2e8::/48"),
        ("as-overview", "AS3333"): as_overview(RIPE_HOLDER),
    }
    result, _ = run(records, routes)
    assert list(result.ip_sources) == ["2001:67c:2e8::1", "2001:67c:2e8::2"]
    assert result.asn["2001:67c:2e8::1"].ip == "2001:67c:2e8::1"
    assert result.asn["2001:67c:2e8::1"].status == LookupStatus.OK


def test_spf_redirect_addresses_are_labelled_with_target() -> None:
    records: Records = {
        ("example.nl", "TXT"): spf_txt("v=spf1 redirect=_spf.example.net"),
        ("_spf.example.net", "TXT"): spf_txt("v=spf1 ip4:145.100.0.9 -all"),
    }
    result, _ = run(records, surf_routes("145.100.0.9"))
    assert result.ip_sources == {"145.100.0.9": ["spf:_spf.example.net"]}


def test_invalid_spf_values_are_skipped() -> None:
    record = (
        "v=spf1 ip4:999.1.1.1 ip4: ip4:1.2.3.4/33 ip4:2001:db8::1 ip6:1.2.3.4 ip4:145.100.0.3 -all"
    )
    records: Records = {("example.nl", "TXT"): spf_txt(record)}
    result, _ = run(records, surf_routes("145.100.0.3"))
    assert result.ip_sources == {"145.100.0.3": ["spf:example.nl"]}
    assert result.spf.ip4 == ["999.1.1.1", "", "1.2.3.4/33", "2001:db8::1", "145.100.0.3"]
    assert result.spf.ip6 == ["1.2.3.4"]


# --- failures ---


def test_www_nxdomain_while_rest_succeeds() -> None:
    records: Records = {
        ("example.nl", "A"): [rdata("A", RIPE_IPV4)],
        ("example.nl", "NS"): [rdata("NS", "ns1.example.nl.")],
        ("ns1.example.nl", "A"): [rdata("A", "145.100.0.1")],
    }
    result, _ = run(records, ripe_routes() | surf_routes("145.100.0.1"))
    assert result.web[0].ipv4_status == LookupStatus.OK
    assert result.web[1].name == "www.example.nl"
    assert result.web[1].ipv4_status == LookupStatus.NXDOMAIN
    assert result.web[1].ipv6_status == LookupStatus.NXDOMAIN
    assert result.nameservers.status == LookupStatus.OK
    assert result.ip_sources == {
        "145.100.0.1": ["ns:ns1.example.nl"],
        RIPE_IPV4: ["web:example.nl"],
    }


class TimeoutResolver:
    """A resolver for which every query times out."""

    def resolve(self, qname: str, rdtype: str) -> None:
        raise dns.exception.Timeout()


def server_error(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500)


def test_total_failure_returns_result() -> None:
    client = httpx.Client(transport=httpx.MockTransport(server_error))
    result = scan_domain("example.nl", resolver=TimeoutResolver(), http_client=client)
    assert result.domain == "example.nl"
    assert result.nameservers.status == LookupStatus.TIMEOUT
    assert result.mx.status == LookupStatus.TIMEOUT
    assert result.txt.status == LookupStatus.TIMEOUT
    assert result.spf.status == LookupStatus.TIMEOUT
    assert [host.ipv4_status for host in result.web] == [LookupStatus.TIMEOUT] * 2
    assert result.ip_sources == {}
    assert result.asn == {}


def test_ripestat_down_gives_error_entries() -> None:
    records: Records = {("example.nl", "A"): [rdata("A", RIPE_IPV4)]}
    client = httpx.Client(transport=httpx.MockTransport(server_error))
    result = scan_domain("example.nl", resolver=FakeResolver(records), http_client=client)
    assert result.asn[RIPE_IPV4].status == LookupStatus.ERROR
    assert result.asn[RIPE_IPV4].error == "network-info: HTTP 500"


# --- clients and invalid input ---


def test_passed_client_stays_open_and_created_client_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    passed = FakeRipestat({}).client()
    scan_domain("example.nl", resolver=FakeResolver({}), http_client=passed)
    assert not passed.is_closed

    created = FakeRipestat({}).client()
    monkeypatch.setattr(scan, "make_http_client", lambda timeout: created)
    scan_domain("example.nl", ScanSettings(), resolver=FakeResolver({}))
    assert created.is_closed


def test_invalid_domain_raises_before_any_query() -> None:
    resolver = FakeResolver({})
    ripestat = FakeRipestat({})
    with pytest.raises(ValueError):
        scan_domain("https://example.nl", resolver=resolver, http_client=ripestat.client())
    assert resolver.queries == []
    assert ripestat.requests == []


# --- normalize_domain ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.NL", "example.nl"),
        ("  example.nl  ", "example.nl"),
        ("example.nl.", "example.nl"),
        ("bücher.nl", "xn--bcher-kva.nl"),
        ("BÜCHER.NL", "xn--bcher-kva.nl"),
        ("straße.de", "xn--strae-oqa.de"),
        ("xn--strae-oqa.de", "xn--strae-oqa.de"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "https://x.nl",
        "x.nl/path",
        "x.nl:443",
        "x .nl",
        "localhost",
        "localhost.",
        "1.2.3.4",
        "2001:db8::1",
        "x..nl",
        "x.nl..",
        "-x.nl",
    ],
)
def test_normalize_domain_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(raw)
