from collections.abc import Iterator

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver


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
