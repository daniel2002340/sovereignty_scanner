import json
from pathlib import Path

import httpx

from soevscan.lookups.asn import AsnLookup, make_http_client
from soevscan.lookups.models import AsnEntry, LookupStatus

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

    def lookup(self, sourceapp: str = "soevscan") -> AsnLookup:
        return AsnLookup(httpx.Client(transport=httpx.MockTransport(self.handle)), sourceapp)

    def count(self, call: str) -> int:
        return sum(1 for r in self.requests if r.url.path == f"/data/{call}/data.json")


def ripe_routes() -> dict[tuple[str, str], Route]:
    return {
        ("network-info", RIPE_IPV4): fixture("network_info_193.0.6.139.json"),
        ("network-info", RIPE_IPV6): fixture("network_info_2001_67c_2e8_22__c100_68b.json"),
        ("as-overview", "AS3333"): fixture("as_overview_AS3333.json"),
    }


# --- successful lookups ---


def test_ipv4_lookup() -> None:
    ripestat = FakeRipestat(ripe_routes())
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.ip == RIPE_IPV4
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert result.prefix == "193.0.0.0/21"
    assert result.asns == [AsnEntry(asn=3333, holder=RIPE_HOLDER)]


def test_ipv6_lookup() -> None:
    ripestat = FakeRipestat(ripe_routes())
    result = ripestat.lookup().lookup(RIPE_IPV6)
    assert result.status == LookupStatus.OK
    assert result.prefix == "2001:67c:2e8::/48"
    assert result.asns == [AsnEntry(asn=3333, holder=RIPE_HOLDER)]


def test_multi_origin_prefix_keeps_every_asn() -> None:
    ripestat = FakeRipestat(
        {
            ("network-info", "145.100.0.1"): network_info(["1101", "1103"]),
            ("as-overview", "AS1101"): as_overview("IP-EEND-AS"),
            ("as-overview", "AS1103"): as_overview("SURFNET-NL"),
        }
    )
    result = ripestat.lookup().lookup("145.100.0.1")
    assert result.status == LookupStatus.OK
    assert result.asns == [AsnEntry(1101, "IP-EEND-AS"), AsnEntry(1103, "SURFNET-NL")]


def test_unregistered_asn_has_holder_none_without_error() -> None:
    ripestat = FakeRipestat(
        {
            ("network-info", "145.100.0.1"): network_info(["64000"]),
            ("as-overview", "AS64000"): as_overview(""),
        }
    )
    result = ripestat.lookup().lookup("145.100.0.1")
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert result.asns == [AsnEntry(64000, None)]


def test_make_http_client_sends_user_agent() -> None:
    client = make_http_client(5.0)
    assert client.headers["User-Agent"].startswith("soevscan/")
    assert "(+https://github.com/daniel2002340/sovereignty_scanner)" in client.headers["User-Agent"]
    assert client.timeout == httpx.Timeout(5.0)


# --- request details and caching ---


def test_sourceapp_is_in_every_request() -> None:
    ripestat = FakeRipestat(ripe_routes())
    ripestat.lookup(sourceapp="soevscan-test").lookup(RIPE_IPV4)
    assert len(ripestat.requests) == 2
    for request in ripestat.requests:
        assert request.url.host == "stat.ripe.net"
        assert request.url.params["sourceapp"] == "soevscan-test"


def test_same_ip_twice_is_requested_once() -> None:
    ripestat = FakeRipestat(ripe_routes())
    lookup = ripestat.lookup()
    first = lookup.lookup(RIPE_IPV4)
    second = lookup.lookup(RIPE_IPV4)
    assert first == second
    assert ripestat.count("network-info") == 1
    assert ripestat.count("as-overview") == 1


def test_two_spellings_of_one_ip_share_one_request() -> None:
    ripestat = FakeRipestat(ripe_routes())
    lookup = ripestat.lookup()
    upper = lookup.lookup("2001:067C:02E8:0022:0000:0000:C100:068B")
    lower = lookup.lookup(RIPE_IPV6)
    assert upper.ip == RIPE_IPV6
    assert lower.ip == RIPE_IPV6
    assert ripestat.count("network-info") == 1
    assert ripestat.requests[0].url.params["resource"] == RIPE_IPV6


def test_two_ips_in_one_asn_request_the_holder_once() -> None:
    ripestat = FakeRipestat(ripe_routes())
    lookup = ripestat.lookup()
    assert lookup.lookup(RIPE_IPV4).asns[0].holder == RIPE_HOLDER
    assert lookup.lookup(RIPE_IPV6).asns[0].holder == RIPE_HOLDER
    assert ripestat.count("network-info") == 2
    assert ripestat.count("as-overview") == 1


def test_failed_ip_is_not_retried() -> None:
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.Response(500)})
    lookup = ripestat.lookup()
    assert lookup.lookup(RIPE_IPV4).status == LookupStatus.ERROR
    assert lookup.lookup(RIPE_IPV4).status == LookupStatus.ERROR
    assert len(ripestat.requests) == 1


def test_failed_holder_is_not_retried() -> None:
    routes = ripe_routes()
    routes[("as-overview", "AS3333")] = httpx.ReadTimeout("timed out")
    ripestat = FakeRipestat(routes)
    lookup = ripestat.lookup()
    lookup.lookup(RIPE_IPV4)
    lookup.lookup(RIPE_IPV6)
    assert ripestat.count("as-overview") == 1


# --- addresses that are not looked up ---


def test_private_ip_is_skipped_without_requests() -> None:
    ripestat = FakeRipestat({})
    lookup = ripestat.lookup()
    for ip in ("10.0.0.1", "127.0.0.1", "192.0.2.1", "fe80::1", "2001:db8::1"):
        result = lookup.lookup(ip)
        assert result.status == LookupStatus.SKIPPED, ip
    assert ripestat.requests == []


def test_skipped_ip_is_canonical() -> None:
    result = FakeRipestat({}).lookup().lookup("2001:DB8::1")
    assert result.ip == "2001:db8::1"


def test_invalid_ip_is_an_error_without_requests() -> None:
    ripestat = FakeRipestat({})
    result = ripestat.lookup().lookup("not-an-ip")
    assert result.ip == "not-an-ip"
    assert result.status == LookupStatus.ERROR
    assert result.error is not None
    assert ripestat.requests == []


# --- RIPEstat answers without a usable result ---


def test_unannounced_ip_is_no_records() -> None:
    # As returned by RIPEstat for an unrouted address: empty list and empty prefix.
    ripestat = FakeRipestat({("network-info", "145.100.0.1"): network_info([], prefix="")})
    result = ripestat.lookup().lookup("145.100.0.1")
    assert result.status == LookupStatus.NO_RECORDS
    assert result.prefix is None
    assert result.asns == []
    assert ripestat.count("as-overview") == 0


def test_unannounced_ip_keeps_prefix_if_given() -> None:
    ripestat = FakeRipestat({("network-info", "145.100.0.1"): network_info([], "145.100.0.0/15")})
    result = ripestat.lookup().lookup("145.100.0.1")
    assert result.status == LookupStatus.NO_RECORDS
    assert result.prefix == "145.100.0.0/15"


def test_timeout() -> None:
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.ConnectTimeout("timed out")})
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.TIMEOUT
    assert result.error == "network-info: timed out"


def test_connection_error() -> None:
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.ConnectError("refused")})
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.ERROR
    assert result.error == "network-info: refused"


def test_http_500() -> None:
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.Response(500, text="oops")})
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.ERROR
    assert result.error == "network-info: HTTP 500"


def test_non_json_body() -> None:
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.Response(200, text="<html>")})
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.ERROR
    assert result.error == "network-info: response is not JSON"


def test_ripestat_status_not_ok() -> None:
    body = {"status": "error", "data": {}, "messages": [["error", "unsupported resource"]]}
    ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.Response(200, json=body)})
    result = ripestat.lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.ERROR
    assert result.error == "network-info: RIPEstat status 'error'"


def test_missing_fields_are_an_error() -> None:
    bodies: list[object] = [
        [],
        {"status": "ok"},
        {"status": "ok", "data": {"prefix": "193.0.0.0/21"}},
        {"status": "ok", "data": {"asns": ["AS-x"], "prefix": "193.0.0.0/21"}},
        {"status": "ok", "data": {"asns": "3333", "prefix": "193.0.0.0/21"}},
    ]
    for body in bodies:
        ripestat = FakeRipestat({("network-info", RIPE_IPV4): httpx.Response(200, json=body)})
        result = ripestat.lookup().lookup(RIPE_IPV4)
        assert result.status == LookupStatus.ERROR, body
        assert result.error is not None


# --- as-overview failing after network-info succeeded ---


def test_holder_failure_keeps_asn_and_status_ok() -> None:
    routes = ripe_routes()
    routes[("as-overview", "AS3333")] = httpx.Response(503)
    result = FakeRipestat(routes).lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.OK
    assert result.prefix == "193.0.0.0/21"
    assert result.asns == [AsnEntry(asn=3333, holder=None)]
    assert result.error == "holder of AS3333 unknown: as-overview: HTTP 503"


def test_holder_missing_field_keeps_asn_and_status_ok() -> None:
    routes = ripe_routes()
    routes[("as-overview", "AS3333")] = httpx.Response(200, json={"status": "ok", "data": {}})
    result = FakeRipestat(routes).lookup().lookup(RIPE_IPV4)
    assert result.status == LookupStatus.OK
    assert result.asns == [AsnEntry(asn=3333, holder=None)]
    assert result.error == "holder of AS3333 unknown: as-overview: missing holder"
