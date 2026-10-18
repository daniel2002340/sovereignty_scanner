"""Result types for the lookups.

Every field is JSON-friendly (str, int, bool, None, list, dict or a nested dataclass), so a
result can always be serialised with ``json.dumps(dataclasses.asdict(result))``. Lookups never
raise on network problems; they report them through ``status`` and ``error`` instead.
"""

import dataclasses
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal


class LookupStatus(StrEnum):
    """Outcome of a single lookup. Serialises as its plain string value."""

    OK = "ok"
    NXDOMAIN = "nxdomain"  # name does not exist
    NO_RECORDS = "no_records"  # name exists, but has no records of this type
    TIMEOUT = "timeout"
    ERROR = "error"  # any other failure (SERVFAIL, HTTP error, malformed response)
    SKIPPED = "skipped"  # deliberately not looked up (e.g. non-public IP, SPF limit reached)


@dataclass
class HostAddresses:
    """A and AAAA records for one host name."""

    name: str
    ipv4_status: LookupStatus
    ipv6_status: LookupStatus
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    canonical_name: str | None = None  # CNAME target if the name was an alias
    errors: list[str] = field(default_factory=list)  # one entry per failed A/AAAA lookup


@dataclass
class NameserverResult:
    """NS records of the domain, with the addresses of each nameserver."""

    status: LookupStatus
    error: str | None = None
    nameservers: list[HostAddresses] = field(default_factory=list)


@dataclass
class MxHost:
    """One MX record and the addresses of its mail server."""

    preference: int
    exchange: str
    addresses: HostAddresses | None = None  # None for a null MX or when not looked up


@dataclass
class MxResult:
    """MX records of the domain."""

    status: LookupStatus
    error: str | None = None
    null_mx: bool = False  # RFC 7505 "0 ." record: the domain accepts no mail
    hosts: list[MxHost] = field(default_factory=list)


@dataclass
class TxtResult:
    """All TXT records of the domain, as raw strings."""

    status: LookupStatus
    error: str | None = None
    records: list[str] = field(default_factory=list)


@dataclass
class SpfInclude:
    """An SPF include or redirect target, followed one level deep."""

    domain: str
    kind: Literal["include", "redirect"]
    status: LookupStatus
    error: str | None = None
    record: str | None = None
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    unfollowed: list[str] = field(default_factory=list)  # deeper includes, recorded only


@dataclass
class SpfResult:
    """The domain's SPF policy (RFC 7208)."""

    status: LookupStatus
    error: str | None = None
    record: str | None = None
    all_records: list[str] = field(default_factory=list)  # set if more than one v=spf1 record
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    includes: list[SpfInclude] = field(default_factory=list)
    other_lookup_terms: list[str] = field(default_factory=list)  # raw a/mx/ptr/exists terms
    all_term: str | None = None  # e.g. "-all", "~all"
    lookup_count: int = 0
    lookup_limit_exceeded: bool = False


@dataclass
class AsnEntry:
    """An autonomous system that announces a prefix."""

    asn: int
    holder: str | None = None


@dataclass
class AsnInfo:
    """Routing data for one IP address, from the RIPEstat Data API."""

    ip: str
    status: LookupStatus
    error: str | None = None
    prefix: str | None = None
    asns: list[AsnEntry] = field(default_factory=list)  # more than one if multi-origin


@dataclass
class ScanResult:
    """All raw lookup results for one domain."""

    domain: str
    scanned_at: str  # ISO 8601, UTC
    tool_version: str
    nameservers: NameserverResult
    mx: MxResult
    txt: TxtResult
    spf: SpfResult
    web: list[HostAddresses] = field(default_factory=list)  # the domain itself and www.
    ip_sources: dict[str, list[str]] = field(default_factory=dict)  # IP -> ["mx:mail.example.nl"]
    asn: dict[str, AsnInfo] = field(default_factory=dict)  # IP -> ASN data


def to_dict(result: Any) -> dict[str, Any]:
    """Convert a result dataclass to a plain dict."""
    return dataclasses.asdict(result)


def to_json(result: Any, indent: int | None = 2) -> str:
    """Serialise a result dataclass to a JSON string."""
    return json.dumps(to_dict(result), indent=indent, ensure_ascii=False)
