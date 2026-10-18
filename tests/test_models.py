import json

from soevscan.lookups.models import (
    AsnEntry,
    AsnInfo,
    HostAddresses,
    LookupStatus,
    MxHost,
    MxResult,
    NameserverResult,
    ScanResult,
    SpfInclude,
    SpfResult,
    TxtResult,
    to_dict,
    to_json,
)


def make_scan_result() -> ScanResult:
    mail = HostAddresses(
        name="mail.example.nl",
        ipv4=["192.0.2.25"],
        ipv4_status=LookupStatus.OK,
        ipv6=[],
        ipv6_status=LookupStatus.NO_RECORDS,
    )
    return ScanResult(
        domain="example.nl",
        scanned_at="2026-10-18T09:00:00Z",
        tool_version="0.1.0",
        nameservers=NameserverResult(
            status=LookupStatus.OK,
            nameservers=[
                HostAddresses(
                    name="ns1.example.nl",
                    ipv4=["192.0.2.53"],
                    ipv4_status=LookupStatus.OK,
                    ipv6=["2001:db8::53"],
                    ipv6_status=LookupStatus.OK,
                ),
                HostAddresses(
                    name="ns2.example.net",
                    ipv4_status=LookupStatus.TIMEOUT,
                    ipv6_status=LookupStatus.NXDOMAIN,
                    errors=["A lookup timed out", "AAAA: ns2.example.net does not exist"],
                ),
            ],
        ),
        mx=MxResult(
            status=LookupStatus.OK,
            hosts=[MxHost(preference=10, exchange="mail.example.nl", addresses=mail)],
        ),
        txt=TxtResult(
            status=LookupStatus.OK,
            records=["v=spf1 ip4:192.0.2.0/24 include:_spf.mailer.example -all", "foo=bar"],
        ),
        spf=SpfResult(
            status=LookupStatus.OK,
            record="v=spf1 ip4:192.0.2.0/24 include:_spf.mailer.example -all",
            ip4=["192.0.2.0/24"],
            includes=[
                SpfInclude(
                    domain="_spf.mailer.example",
                    kind="include",
                    status=LookupStatus.OK,
                    record="v=spf1 ip6:2001:db8:1::/48 include:_deeper.mailer.example ~all",
                    ip6=["2001:db8:1::/48"],
                    unfollowed=["_deeper.mailer.example"],
                )
            ],
            all_term="-all",
            lookup_count=1,
        ),
        web=[
            HostAddresses(
                name="example.nl",
                ipv4=["198.51.100.80"],
                ipv4_status=LookupStatus.OK,
                ipv6_status=LookupStatus.NO_RECORDS,
            ),
            HostAddresses(
                name="www.example.nl",
                ipv4=["198.51.100.80"],
                ipv4_status=LookupStatus.OK,
                ipv6_status=LookupStatus.NO_RECORDS,
                canonical_name="example.nl",
            ),
        ],
        ip_sources={
            "198.51.100.80": ["web:example.nl", "web:www.example.nl"],
            "192.0.2.25": ["mx:mail.example.nl"],
        },
        asn={
            "198.51.100.80": AsnInfo(
                ip="198.51.100.80",
                status=LookupStatus.OK,
                prefix="198.51.100.0/24",
                asns=[AsnEntry(asn=64500, holder="EXAMPLE-AS - Example Hosting B.V.")],
            ),
            "192.0.2.25": AsnInfo(
                ip="192.0.2.25",
                status=LookupStatus.ERROR,
                error="HTTP 503 from RIPEstat",
            ),
        },
    )


def test_to_json_is_valid_json() -> None:
    data = json.loads(to_json(make_scan_result()))
    assert data["domain"] == "example.nl"
    assert data["tool_version"] == "0.1.0"


def test_statuses_serialise_as_plain_strings() -> None:
    data = json.loads(to_json(make_scan_result()))
    ns2 = data["nameservers"]["nameservers"][1]
    assert ns2["ipv4_status"] == "timeout"
    assert ns2["ipv6_status"] == "nxdomain"
    assert type(ns2["ipv6_status"]) is str
    assert data["asn"]["192.0.2.25"]["status"] == "error"
    assert '"status": "ok"' in to_json(make_scan_result())


def test_nested_lists_and_dicts_round_trip() -> None:
    result = make_scan_result()
    data = json.loads(to_json(result))

    assert data == json.loads(json.dumps(to_dict(result)))
    assert data["mx"]["hosts"][0]["addresses"]["ipv4"] == ["192.0.2.25"]
    assert data["spf"]["includes"][0]["unfollowed"] == ["_deeper.mailer.example"]
    assert data["web"][1]["canonical_name"] == "example.nl"
    assert data["ip_sources"]["198.51.100.80"] == ["web:example.nl", "web:www.example.nl"]
    assert data["asn"]["198.51.100.80"]["asns"] == [
        {"asn": 64500, "holder": "EXAMPLE-AS - Example Hosting B.V."}
    ]
    assert data["asn"]["192.0.2.25"]["prefix"] is None


def test_to_json_indent() -> None:
    result = make_scan_result()
    assert "\n" not in to_json(result, indent=None)
    assert to_json(result).startswith('{\n  "domain"')
