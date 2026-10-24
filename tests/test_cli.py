import json

import pytest

import soevscan
from soevscan import cli
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
)
from soevscan.scan import ScanSettings

OK = LookupStatus.OK


def host(name: str, ipv4: list[str], ipv6: list[str]) -> HostAddresses:
    return HostAddresses(name=name, ipv4_status=OK, ipv6_status=OK, ipv4=ipv4, ipv6=ipv6)


def happy_result() -> ScanResult:
    return ScanResult(
        domain="example.nl",
        scanned_at="2026-10-24T09:15:00Z",
        tool_version="0.1.0",
        nameservers=NameserverResult(
            status=OK,
            nameservers=[host("ns1.example.nl", ["192.0.2.1"], []), host("ns2.example.nl", [], [])],
        ),
        mx=MxResult(
            status=OK,
            hosts=[MxHost(10, "mail.example.nl", host("mail.example.nl", ["192.0.2.2"], []))],
        ),
        txt=TxtResult(status=OK, records=["v=spf1 ip4:192.0.2.3 include:_spf.eu -all", "x=ü"]),
        spf=SpfResult(
            status=OK,
            record="v=spf1 ip4:192.0.2.3 include:_spf.eu -all",
            ip4=["192.0.2.3"],
            includes=[SpfInclude(domain="_spf.eu", kind="include", status=OK)],
        ),
        web=[host("example.nl", ["192.0.2.4"], ["2001:db8::4"]), host("www.example.nl", [], [])],
        ip_sources={
            "10.0.0.1": ["web:example.nl"],
            "192.0.2.1": ["ns:ns1.example.nl"],
            "192.0.2.2": ["mx:mail.example.nl"],
            "2001:db8::4": ["web:example.nl"],
        },
        asn={
            "10.0.0.1": AsnInfo(ip="10.0.0.1", status=LookupStatus.SKIPPED),
            "192.0.2.1": AsnInfo(ip="192.0.2.1", status=OK, asns=[AsnEntry(1103, "SURFNET")]),
            "192.0.2.2": AsnInfo(
                ip="192.0.2.2", status=OK, asns=[AsnEntry(1103, "SURFNET"), AsnEntry(3333)]
            ),
            "2001:db8::4": AsnInfo(ip="2001:db8::4", status=LookupStatus.TIMEOUT, error="slow"),
        },
    )


def failed_result() -> ScanResult:
    """Everything timed out."""
    timeout = LookupStatus.TIMEOUT
    return ScanResult(
        domain="example.nl",
        scanned_at="2026-10-24T09:15:00Z",
        tool_version="0.1.0",
        nameservers=NameserverResult(status=timeout, error="DNS timeout"),
        mx=MxResult(status=timeout, error="DNS timeout"),
        txt=TxtResult(status=timeout, error="DNS timeout"),
        spf=SpfResult(status=timeout, error="DNS timeout"),
        web=[
            HostAddresses(name="example.nl", ipv4_status=timeout, ipv6_status=timeout),
            HostAddresses(name="www.example.nl", ipv4_status=timeout, ipv6_status=timeout),
        ],
    )


@pytest.fixture
def fake_scan(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ScanSettings]]:
    """Replace ``scan_domain`` with one that returns ``happy_result()`` and records its calls."""
    calls: list[tuple[str, ScanSettings]] = []

    def scan(domain: str, settings: ScanSettings) -> ScanResult:
        calls.append((domain, settings))
        return happy_result()

    monkeypatch.setattr(cli, "scan_domain", scan)
    return calls


# --- output ---


def test_json_output_is_only_json(fake_scan, capsys) -> None:
    assert cli.main(["example.nl", "--json"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["domain"] == "example.nl"
    assert data["asn"]["10.0.0.1"]["status"] == "skipped"
    assert "x=ü" in out  # non-ASCII kept as-is


def test_summary(fake_scan, capsys) -> None:
    assert cli.main(["example.nl"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "example.nl (scanned 2026-10-24T09:15:00Z, soevscan 0.1.0)"
    assert lines[1].split() == ["nameservers", "ok", "2", "hosts"]
    assert lines[2].split() == ["mx", "ok", "1", "host"]
    assert lines[3].split() == ["txt", "ok", "2", "records"]
    assert lines[4].split() == ["spf", "ok", "1", "ip4,", "0", "ip6,", "1", "include"]
    assert lines[5].split(maxsplit=1)[1] == (
        "example.nl: A ok, AAAA ok; www.example.nl: A ok, AAAA ok"
    )
    assert lines[6].split(maxsplit=1)[1] == "4 unique (1 skipped)"
    assert lines[7].split(maxsplit=1)[1] == "2 unique (1 lookups failed)"
    assert lines[8] == "Use --json for the full data."


def test_summary_null_mx(monkeypatch, capsys) -> None:
    result = happy_result()
    result.mx = MxResult(status=OK, null_mx=True, hosts=[MxHost(0, ".")])
    monkeypatch.setattr(cli, "scan_domain", lambda domain, settings: result)
    assert cli.main(["example.nl"]) == 0
    mx_line = capsys.readouterr().out.splitlines()[2]
    assert mx_line.split(maxsplit=2) == ["mx", "ok", "null MX (accepts no mail)"]


def test_failed_scan_exits_0_and_shows_errors(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "scan_domain", lambda domain, settings: failed_result())
    assert cli.main(["example.nl"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1].split(maxsplit=2) == ["nameservers", "timeout", "DNS timeout"]
    assert "example.nl: A timeout, AAAA timeout" in lines[5]
    assert lines[6].split(maxsplit=1)[1] == "0 unique (0 skipped)"
    assert lines[7].split(maxsplit=1)[1] == "0 unique (0 lookups failed)"


def test_failed_scan_json_exits_0(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "scan_domain", lambda domain, settings: failed_result())
    assert cli.main(["example.nl", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["mx"]["status"] == "timeout"


# --- settings ---


def test_defaults_come_from_scan_settings(fake_scan) -> None:
    cli.main(["Example.NL."])
    assert fake_scan == [("example.nl", ScanSettings())]


def test_options_are_passed_to_scan_settings(fake_scan) -> None:
    argv = ["example.nl", "--dns-timeout", "2.5", "--http-timeout", "7"]
    argv += ["--resolver", "9.9.9.10", "--resolver", "2A13:1001::86:54:11:100"]
    argv += ["--sourceapp", "my-scan"]
    cli.main(argv)
    assert fake_scan[0][1] == ScanSettings(
        dns_timeout=2.5,
        http_timeout=7.0,
        nameservers=["9.9.9.10", "2a13:1001::86:54:11:100"],
        sourceapp="my-scan",
    )


# --- invalid input ---


@pytest.mark.parametrize("domain", ["https://nlnet.nl/", "localhost", "192.0.2.1", ""])
def test_invalid_domain_exits_2_with_one_line(fake_scan, capsys, domain: str) -> None:
    assert cli.main([domain]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("soevscan: error: ")
    assert captured.err.count("\n") == 1
    assert fake_scan == []


@pytest.mark.parametrize(
    "argv",
    [
        ["example.nl", "--resolver", "not-an-ip"],
        ["example.nl", "--dns-timeout", "0"],
        ["example.nl", "--http-timeout", "-1"],
        ["example.nl", "--dns-timeout", "abc"],
        ["example.nl", "--dns-timeout", "inf"],
        [],
    ],
)
def test_argparse_errors_exit_2(fake_scan, capsys, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2
    assert "usage: soevscan" in capsys.readouterr().err
    assert fake_scan == []


def test_version(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out == f"soevscan {soevscan.__version__}\n"


def test_ctrl_c_exits_130(monkeypatch, capsys) -> None:
    def interrupted(domain: str, settings: ScanSettings) -> ScanResult:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "scan_domain", interrupted)
    assert cli.main(["example.nl"]) == 130
    assert capsys.readouterr().err == "soevscan: interrupted\n"
