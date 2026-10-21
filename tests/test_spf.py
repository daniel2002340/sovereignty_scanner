import dns.exception
import dns.rdata
from conftest import FakeResolver, rdata

from soevscan.lookups.models import LookupStatus, TxtResult
from soevscan.lookups.spf import lookup_spf


def txt(*records: str) -> TxtResult:
    """The domain's own TXT result, as step 2 would have returned it."""
    return TxtResult(status=LookupStatus.OK, records=list(records))


def spf_txt(record: str) -> list[dns.rdata.Rdata]:
    """TXT rdata for a target's record (kept under 255 characters, so one string)."""
    return [rdata("TXT", f'"{record}"')]


# --- finding the record ---


def test_no_spf_record() -> None:
    resolver = FakeResolver({})
    result = lookup_spf("example.nl", txt("google-site-verification=abc", "v=spf10 -all"), resolver)
    assert result.status == LookupStatus.NO_RECORDS
    assert result.error == "no SPF record for example.nl"
    assert result.record is None
    assert resolver.queries == []


def test_uppercase_version_tag_is_found() -> None:
    result = lookup_spf("example.nl", txt("V=SPF1 ip4:192.0.2.1 -all"), FakeResolver({}))
    assert result.status == LookupStatus.OK
    assert result.record == "V=SPF1 ip4:192.0.2.1 -all"
    assert result.ip4 == ["192.0.2.1"]


def test_two_spf_records_is_an_error_and_includes_are_not_followed() -> None:
    resolver = FakeResolver({})
    records = ("v=spf1 include:a.example -all", "v=spf1 ip4:192.0.2.1 -all")
    result = lookup_spf("example.nl", txt(*records), resolver)
    assert result.status == LookupStatus.ERROR
    assert result.error is not None
    assert result.all_records == list(records)
    assert result.includes == []
    assert resolver.queries == []


def test_failed_txt_lookup_is_copied() -> None:
    upstream = TxtResult(status=LookupStatus.TIMEOUT, error="timed out")
    result = lookup_spf("example.nl", upstream, FakeResolver({}))
    assert result.status == LookupStatus.TIMEOUT
    assert result.error == "timed out"


# --- parsing terms ---


def test_ip4_and_ip6_are_kept_as_written() -> None:
    record = "v=spf1 ip4:192.0.2.1 +ip4:198.51.100.0/24 ip6:2001:db8::1 ip6:2001:db8::/32 ~all"
    result = lookup_spf("example.nl", txt(record), FakeResolver({}))
    assert result.status == LookupStatus.OK
    assert result.error is None
    assert result.ip4 == ["192.0.2.1", "198.51.100.0/24"]
    assert result.ip6 == ["2001:db8::1", "2001:db8::/32"]
    assert result.all_term == "~all"
    assert result.lookup_count == 0
    assert result.lookup_limit_exceeded is False


def test_lookup_terms_are_recorded_raw_and_not_resolved() -> None:
    resolver = FakeResolver({})
    record = "v=spf1 a -mx:mail.example.nl/24 ?ptr exists:%{i}.x.example -all"
    result = lookup_spf("example.nl", txt(record), resolver)
    assert result.other_lookup_terms == [
        "a",
        "-mx:mail.example.nl/24",
        "?ptr",
        "exists:%{i}.x.example",
    ]
    assert result.lookup_count == 4
    assert resolver.queries == []


# --- following includes and redirects ---


def test_include_is_followed_one_level() -> None:
    resolver = FakeResolver(
        {
            ("_spf.hoster.example", "TXT"): spf_txt(
                "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8:1::/48 include:deeper.example ~all"
            ),
        }
    )
    result = lookup_spf("example.nl", txt("v=spf1 include:_SPF.Hoster.Example. -all"), resolver)
    assert result.status == LookupStatus.OK
    assert len(result.includes) == 1
    include = result.includes[0]
    assert include.domain == "_spf.hoster.example"
    assert include.kind == "include"
    assert include.status == LookupStatus.OK
    assert include.error is None
    assert include.ip4 == ["203.0.113.0/24"]
    assert include.ip6 == ["2001:db8:1::/48"]
    assert include.unfollowed == ["deeper.example"]
    assert resolver.queries == [("_spf.hoster.example", "TXT")]


def test_valid_redirect_is_fetched_after_the_includes() -> None:
    resolver = FakeResolver(
        {
            ("a.example", "TXT"): spf_txt("v=spf1 ip4:192.0.2.1 -all"),
            ("_spf.example.nl", "TXT"): spf_txt("v=spf1 ip4:192.0.2.2 -all"),
        }
    )
    record = "v=spf1 redirect=_spf.example.nl include:a.example"
    result = lookup_spf("example.nl", txt(record), resolver)
    assert resolver.queries == [("a.example", "TXT"), ("_spf.example.nl", "TXT")]
    assert [(i.domain, i.kind) for i in result.includes] == [
        ("a.example", "include"),
        ("_spf.example.nl", "redirect"),
    ]
    assert result.includes[1].status == LookupStatus.OK
    assert result.includes[1].ip4 == ["192.0.2.2"]
    assert result.lookup_count == 2
    assert result.error is None


def test_redirect_with_all_term_is_ignored() -> None:
    resolver = FakeResolver({("_spf.example.nl", "TXT"): spf_txt("v=spf1 ip4:192.0.2.2 -all")})
    result = lookup_spf("example.nl", txt("v=spf1 redirect=_spf.example.nl -all"), resolver)
    assert result.status == LookupStatus.OK
    assert len(result.includes) == 1
    redirect = result.includes[0]
    assert redirect.domain == "_spf.example.nl"
    assert redirect.kind == "redirect"
    assert redirect.status == LookupStatus.SKIPPED
    assert redirect.error == "ignored per RFC 7208 §6.1: record contains 'all'"
    assert result.lookup_count == 0
    assert resolver.queries == []


def test_include_nxdomain_does_not_stop_the_rest() -> None:
    resolver = FakeResolver({("ok.example", "TXT"): spf_txt("v=spf1 ip4:192.0.2.1 -all")})
    result = lookup_spf(
        "example.nl", txt("v=spf1 include:gone.example include:ok.example -all"), resolver
    )
    gone, ok = result.includes
    assert gone.status == LookupStatus.NXDOMAIN
    assert gone.error == "gone.example does not exist"
    assert ok.status == LookupStatus.OK
    assert ok.ip4 == ["192.0.2.1"]
    assert result.status == LookupStatus.OK


def test_include_timeout() -> None:
    resolver = FakeResolver({("slow.example", "TXT"): dns.exception.Timeout()})
    result = lookup_spf("example.nl", txt("v=spf1 include:slow.example -all"), resolver)
    assert result.includes[0].status == LookupStatus.TIMEOUT
    assert result.includes[0].error == "timed out"
    assert result.status == LookupStatus.OK


def test_include_without_spf_record() -> None:
    resolver = FakeResolver({("plain.example", "TXT"): spf_txt("some-verification=1")})
    result = lookup_spf("example.nl", txt("v=spf1 include:plain.example -all"), resolver)
    assert result.includes[0].status == LookupStatus.NO_RECORDS
    assert result.includes[0].error == "no SPF record for plain.example"


def test_include_with_two_spf_records_is_an_error() -> None:
    resolver = FakeResolver(
        {
            ("double.example", "TXT"): [
                rdata("TXT", '"v=spf1 ip4:192.0.2.1 -all"'),
                rdata("TXT", '"v=spf1 ip4:192.0.2.2 -all"'),
            ]
        }
    )
    result = lookup_spf("example.nl", txt("v=spf1 include:double.example -all"), resolver)
    include = result.includes[0]
    assert include.status == LookupStatus.ERROR
    assert include.error is not None
    assert include.ip4 == []
    assert result.status == LookupStatus.OK


def test_macro_include_is_skipped() -> None:
    resolver = FakeResolver({})
    result = lookup_spf("example.nl", txt("v=spf1 include:%{i}._spf.example -all"), resolver)
    include = result.includes[0]
    assert include.domain == "%{i}._spf.example"
    assert include.status == LookupStatus.SKIPPED
    assert include.error is not None
    assert result.lookup_count == 1
    assert resolver.queries == []


def test_duplicate_include_is_fetched_and_counted_each_time() -> None:
    resolver = FakeResolver({("a.example", "TXT"): spf_txt("v=spf1 mx -all")})
    result = lookup_spf(
        "example.nl", txt("v=spf1 include:a.example include:a.example -all"), resolver
    )
    assert resolver.queries == [("a.example", "TXT"), ("a.example", "TXT")]
    assert result.lookup_count == 4  # two includes, plus one mx in each fetched record


# --- lookup count and query cap ---


def test_lookup_count_includes_second_level_terms() -> None:
    resolver = FakeResolver(
        {
            ("a.example", "TXT"): spf_txt(
                "v=spf1 include:b.example mx a:x.example ip4:192.0.2.1 -all"
            ),
        }
    )
    result = lookup_spf("example.nl", txt("v=spf1 include:a.example mx -all"), resolver)
    # Top level: include, mx. In a.example: include (unfollowed), mx, a.
    assert result.lookup_count == 5
    assert result.lookup_limit_exceeded is False
    assert result.includes[0].unfollowed == ["b.example"]


def test_twelve_includes_hit_the_query_cap() -> None:
    names = [f"i{n}.example" for n in range(12)]
    resolver = FakeResolver({(name, "TXT"): spf_txt("v=spf1 ip4:192.0.2.1 -all") for name in names})
    record = "v=spf1 " + " ".join(f"include:{name}" for name in names) + " -all"
    result = lookup_spf("example.nl", txt(record), resolver)
    assert len(resolver.queries) == 10
    assert result.lookup_count == 12
    assert result.lookup_limit_exceeded is True
    assert result.status == LookupStatus.OK
    assert result.error is not None
    assert [i.status for i in result.includes[:10]] == [LookupStatus.OK] * 10
    assert [i.status for i in result.includes[10:]] == [LookupStatus.SKIPPED] * 2


def test_limit_exceeded_through_second_level_terms() -> None:
    resolver = FakeResolver({("big.example", "TXT"): spf_txt("v=spf1 " + "a " * 10 + "-all")})
    result = lookup_spf("example.nl", txt("v=spf1 include:big.example -all"), resolver)
    assert result.lookup_count == 11
    assert result.lookup_limit_exceeded is True
    assert result.error is not None
