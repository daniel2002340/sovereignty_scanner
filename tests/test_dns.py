import dns.exception
import dns.resolver
from conftest import FakeResolver, rdata

from soevscan.lookups.dns import lookup_mx, lookup_ns, lookup_txt, make_resolver, resolve_host
from soevscan.lookups.models import LookupStatus

# --- make_resolver ---


def test_make_resolver_uses_given_nameservers_and_timeout() -> None:
    resolver = make_resolver(3.0, nameservers=["192.0.2.53"])
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.lifetime == 3.0


# --- resolve_host ---


def test_resolve_host_ipv4_and_ipv6() -> None:
    resolver = FakeResolver(
        {
            ("www.example.nl", "A"): [rdata("A", "192.0.2.80")],
            ("www.example.nl", "AAAA"): [rdata("AAAA", "2001:db8::80")],
        }
    )
    host = resolve_host("WWW.Example.NL.", resolver)
    assert host.name == "www.example.nl"
    assert host.ipv4 == ["192.0.2.80"]
    assert host.ipv6 == ["2001:db8::80"]
    assert host.ipv4_status == host.ipv6_status == LookupStatus.OK
    assert host.canonical_name is None
    assert host.errors == []


def test_resolve_host_records_canonical_name_of_alias() -> None:
    resolver = FakeResolver(
        {("cdn.hoster.example", "A"): [rdata("A", "198.51.100.1")]},
        cnames={"www.example.nl": "cdn.hoster.example"},
    )
    host = resolve_host("www.example.nl", resolver)
    assert host.name == "www.example.nl"
    assert host.canonical_name == "cdn.hoster.example"
    assert host.ipv4 == ["198.51.100.1"]
    assert host.ipv6_status == LookupStatus.NO_RECORDS


def test_resolve_host_records_status_per_type() -> None:
    resolver = FakeResolver(
        {
            ("mail.example.nl", "A"): [rdata("A", "192.0.2.25")],
            ("mail.example.nl", "AAAA"): dns.exception.Timeout(),
        }
    )
    host = resolve_host("mail.example.nl", resolver)
    assert host.ipv4_status == LookupStatus.OK
    assert host.ipv6_status == LookupStatus.TIMEOUT
    assert host.ipv6 == []
    assert host.errors == ["AAAA: timed out"]


# --- lookup_ns ---


def test_ns_two_hosts_with_ipv4_and_ipv6() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "NS"): [rdata("NS", "NS2.example.net."), rdata("NS", "ns1.example.nl.")],
            ("ns1.example.nl", "A"): [rdata("A", "192.0.2.53")],
            ("ns1.example.nl", "AAAA"): [rdata("AAAA", "2001:db8::53")],
            ("ns2.example.net", "A"): [rdata("A", "198.51.100.53")],
            ("ns2.example.net", "AAAA"): [rdata("AAAA", "2001:db8:1::53")],
        }
    )
    result = lookup_ns("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert [ns.name for ns in result.nameservers] == ["ns1.example.nl", "ns2.example.net"]
    assert result.nameservers[0].ipv4 == ["192.0.2.53"]
    assert result.nameservers[0].ipv6 == ["2001:db8::53"]
    assert result.nameservers[1].ipv4 == ["198.51.100.53"]
    assert result.nameservers[1].ipv6 == ["2001:db8:1::53"]


def test_ns_one_host_failing_keeps_result_ok() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "NS"): [rdata("NS", "ns1.example.nl."), rdata("NS", "ns2.example.net.")],
            ("ns1.example.nl", "A"): [rdata("A", "192.0.2.53")],
            ("ns1.example.nl", "AAAA"): [rdata("AAAA", "2001:db8::53")],
            ("ns2.example.net", "A"): dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]),
            ("ns2.example.net", "AAAA"): dns.resolver.LifetimeTimeout(timeout=5.0, errors=[]),
        }
    )
    result = lookup_ns("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.error is None
    ns1, ns2 = result.nameservers
    assert ns1.ipv4_status == ns1.ipv6_status == LookupStatus.OK
    assert ns2.ipv4_status == ns2.ipv6_status == LookupStatus.TIMEOUT
    assert ns2.errors == ["A: timed out", "AAAA: timed out"]


def test_ns_nxdomain() -> None:
    result = lookup_ns("does-not-exist.example", FakeResolver({}))
    assert result.status == LookupStatus.NXDOMAIN
    assert result.error == "does-not-exist.example does not exist"
    assert result.nameservers == []


def test_ns_no_answer() -> None:
    resolver = FakeResolver({("www.example.nl", "NS"): dns.resolver.NoAnswer()})
    result = lookup_ns("www.example.nl", resolver)
    assert result.status == LookupStatus.NO_RECORDS
    assert result.error == "no NS records for www.example.nl"


def test_ns_timeout() -> None:
    resolver = FakeResolver(
        {("example.nl", "NS"): dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])}
    )
    result = lookup_ns("example.nl", resolver)
    assert result.status == LookupStatus.TIMEOUT
    assert result.error == "timed out"


def test_ns_servfail() -> None:
    resolver = FakeResolver({("example.nl", "NS"): dns.resolver.NoNameservers()})
    result = lookup_ns("example.nl", resolver)
    assert result.status == LookupStatus.ERROR
    assert result.error is not None


def test_other_dns_exception_becomes_error() -> None:
    resolver = FakeResolver({("example.nl", "NS"): dns.exception.SyntaxError("bad")})
    result = lookup_ns("example.nl", resolver)
    assert result.status == LookupStatus.ERROR
    assert result.error == "DNS error: bad"


# --- lookup_mx ---


def test_mx_sorted_by_preference_and_resolved() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "MX"): [
                rdata("MX", "20 backup.example.nl."),
                rdata("MX", "10 Mail.Example.NL."),
            ],
            ("mail.example.nl", "A"): [rdata("A", "192.0.2.25")],
            ("mail.example.nl", "AAAA"): dns.resolver.NoAnswer(),
            ("backup.example.nl", "A"): [rdata("A", "192.0.2.26")],
            ("backup.example.nl", "AAAA"): [rdata("AAAA", "2001:db8::26")],
        }
    )
    result = lookup_mx("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert result.null_mx is False
    assert [(h.preference, h.exchange) for h in result.hosts] == [
        (10, "mail.example.nl"),
        (20, "backup.example.nl"),
    ]
    assert result.hosts[0].addresses.ipv4 == ["192.0.2.25"]
    assert result.hosts[0].addresses.ipv6_status == LookupStatus.NO_RECORDS
    assert result.hosts[1].addresses.ipv6 == ["2001:db8::26"]


def test_null_mx() -> None:
    resolver = FakeResolver({("example.nl", "MX"): [rdata("MX", "0 .")]})
    result = lookup_mx("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert result.null_mx is True
    assert result.hosts == []
    assert resolver.queries == [("example.nl", "MX")]


def test_null_mx_alongside_other_records_is_recorded_not_interpreted() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "MX"): [rdata("MX", "0 ."), rdata("MX", "10 mail.example.nl.")],
            ("mail.example.nl", "A"): [rdata("A", "192.0.2.25")],
            ("mail.example.nl", "AAAA"): [rdata("AAAA", "2001:db8::25")],
        }
    )
    result = lookup_mx("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.null_mx is False
    assert result.error is not None and "RFC 7505" in result.error
    root, mail = result.hosts
    assert (root.preference, root.exchange, root.addresses) == (0, ".", None)
    assert mail.addresses.ipv4 == ["192.0.2.25"]
    assert ("", "A") not in resolver.queries and (".", "A") not in resolver.queries


def test_no_mx_records_has_no_implicit_fallback() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "MX"): dns.resolver.NoAnswer(),
            ("example.nl", "A"): [rdata("A", "192.0.2.80")],
        }
    )
    result = lookup_mx("example.nl", resolver)
    assert result.status == LookupStatus.NO_RECORDS
    assert result.error == "no MX records for example.nl"
    assert result.hosts == []
    assert resolver.queries == [("example.nl", "MX")]


# --- lookup_txt ---


def test_txt_record_split_over_several_strings_is_joined() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "TXT"): [
                rdata("TXT", '"v=spf1 ip4:192.0.2.0/24 " "include:_spf.example -all"')
            ]
        }
    )
    result = lookup_txt("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert result.records == ["v=spf1 ip4:192.0.2.0/24 include:_spf.example -all"]


def test_multiple_txt_records() -> None:
    resolver = FakeResolver(
        {
            ("example.nl", "TXT"): [
                rdata("TXT", '"v=spf1 -all"'),
                rdata("TXT", '"google-site-verification=abc"'),
            ]
        }
    )
    result = lookup_txt("example.nl", resolver)
    assert result.status == LookupStatus.OK
    assert sorted(result.records) == ["google-site-verification=abc", "v=spf1 -all"]


def test_txt_invalid_utf8_is_replaced() -> None:
    resolver = FakeResolver({("example.nl", "TXT"): [rdata("TXT", '"caf\\233"')]})
    result = lookup_txt("example.nl", resolver)
    assert result.records == ["caf�"]


def test_txt_nxdomain() -> None:
    result = lookup_txt("does-not-exist.example", FakeResolver({}))
    assert result.status == LookupStatus.NXDOMAIN
    assert result.records == []
