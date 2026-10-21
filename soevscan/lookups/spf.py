"""SPF lookup (RFC 7208): find the domain's SPF record and follow includes one level deep.

Only raw facts are collected: the IP ranges and targets written in the records. ``a``, ``mx``,
``ptr`` and ``exists`` terms are recorded but not resolved, and no policy is evaluated. Like the
other lookups, this never raises on DNS problems; failures become a status and an ``error``.
"""

import re
from dataclasses import dataclass, field
from typing import Literal

import dns.resolver

from soevscan.lookups.dns import _normalise, lookup_txt
from soevscan.lookups.models import LookupStatus, SpfInclude, SpfResult, TxtResult

QUERY_CAP = 10  # DNS queries we make per SPF lookup, not counting the domain's own TXT query
LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4: maximum number of DNS-querying terms

_LOOKUP_MECHANISMS = ("a", "mx", "ptr", "exists")
_QUALIFIERS = "+-~?"


@dataclass
class _Terms:
    """The terms of one SPF record that we record."""

    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    redirect: str | None = None
    other_lookup_terms: list[str] = field(default_factory=list)
    all_term: str | None = None

    def redirect_ignored(self) -> bool:
        """RFC 7208 §6.1: a redirect is ignored when the record contains an ``all`` term."""
        return self.redirect is not None and self.all_term is not None

    def lookup_count(self) -> int:
        """The number of RFC 7208 §4.6.4 terms in this record; an ignored redirect is not one."""
        redirect = 1 if self.redirect is not None and not self.redirect_ignored() else 0
        return len(self.includes) + len(self.other_lookup_terms) + redirect


def lookup_spf(domain: str, txt: TxtResult, resolver: dns.resolver.Resolver) -> SpfResult:
    """Find the SPF record in ``txt`` (the domain's TXT result) and follow it one level deep.

    Each include target, and then a valid redirect target, is fetched once per occurrence and
    parsed into an ``SpfInclude``. Includes and redirects found in those records are recorded
    in ``unfollowed`` but not fetched. At most ``QUERY_CAP`` queries are made; targets beyond
    that, and targets containing macros, get status SKIPPED. A redirect in a record that also
    has an ``all`` term is ignored (RFC 7208 §6.1): recorded as SKIPPED, not fetched or counted.

    ``lookup_count`` counts the RFC 7208 §4.6.4 terms (include, a, mx, ptr, exists, redirect)
    in the domain's record and in every record we fetched. Records we did not fetch (deeper
    levels, skipped targets) are not counted, so it is a lower bound of the real count.
    """
    domain = _normalise(domain)
    if txt.status != LookupStatus.OK:
        return SpfResult(status=txt.status, error=txt.error)
    records = _spf_records(txt.records)
    if not records:
        return SpfResult(status=LookupStatus.NO_RECORDS, error=f"no SPF record for {domain}")
    if len(records) > 1:
        return SpfResult(
            status=LookupStatus.ERROR,
            error="more than one SPF record (permerror, RFC 7208 §4.5)",
            all_records=records,
        )

    terms = _parse(records[0])
    result = SpfResult(
        status=LookupStatus.OK,
        record=records[0],
        ip4=terms.ip4,
        ip6=terms.ip6,
        other_lookup_terms=terms.other_lookup_terms,
        all_term=terms.all_term,
        lookup_count=terms.lookup_count(),
    )

    # A redirect is evaluated after all mechanisms, so it comes last, also for the query cap.
    targets: list[tuple[str, Literal["include", "redirect"]]] = [
        (target, "include") for target in terms.includes
    ]
    if terms.redirect is not None:
        targets.append((terms.redirect, "redirect"))

    queries = 0
    skipped_by_cap = 0
    for target, kind in targets:
        if kind == "redirect" and terms.redirect_ignored():
            note = "ignored per RFC 7208 §6.1: record contains 'all'"
            include = SpfInclude(domain=target, kind=kind, status=LookupStatus.SKIPPED, error=note)
        elif "%" in target:
            note = "contains SPF macros; not expanded"
            include = SpfInclude(domain=target, kind=kind, status=LookupStatus.SKIPPED, error=note)
        elif queries >= QUERY_CAP:
            note = f"not fetched: query cap of {QUERY_CAP} reached"
            include = SpfInclude(domain=target, kind=kind, status=LookupStatus.SKIPPED, error=note)
            skipped_by_cap += 1
        else:
            queries += 1
            include, count = _follow(target, kind, resolver)
            result.lookup_count += count
        result.includes.append(include)

    result.lookup_limit_exceeded = result.lookup_count > LOOKUP_LIMIT or skipped_by_cap > 0
    if result.lookup_limit_exceeded:
        result.error = (
            f"at least {result.lookup_count} DNS-querying terms, "
            f"more than the RFC 7208 limit of {LOOKUP_LIMIT}"
        )
        if skipped_by_cap:
            result.error += f"; {skipped_by_cap} target(s) not fetched"
    return result


def _follow(
    target: str, kind: Literal["include", "redirect"], resolver: dns.resolver.Resolver
) -> tuple[SpfInclude, int]:
    """Fetch and parse one include or redirect target, without going deeper.

    Returns the ``SpfInclude`` and the number of DNS-querying terms in its record.
    """
    txt = lookup_txt(target, resolver)
    if txt.status != LookupStatus.OK:
        return SpfInclude(domain=target, kind=kind, status=txt.status, error=txt.error), 0
    records = _spf_records(txt.records)
    if not records:
        error = f"no SPF record for {target}"
        return SpfInclude(domain=target, kind=kind, status=LookupStatus.NO_RECORDS, error=error), 0
    if len(records) > 1:
        error = f"more than one SPF record for {target} (permerror, RFC 7208 §4.5)"
        return SpfInclude(domain=target, kind=kind, status=LookupStatus.ERROR, error=error), 0

    terms = _parse(records[0])
    unfollowed = terms.includes + ([terms.redirect] if terms.redirect is not None else [])
    include = SpfInclude(
        domain=target,
        kind=kind,
        status=LookupStatus.OK,
        record=records[0],
        ip4=terms.ip4,
        ip6=terms.ip6,
        unfollowed=unfollowed,
    )
    return include, terms.lookup_count()


def _spf_records(records: list[str]) -> list[str]:
    """Return the TXT records that are SPF records: ``v=spf1`` followed by a space or the end."""
    return [r for r in records if r.lower() == "v=spf1" or r.lower().startswith("v=spf1 ")]


def _parse(record: str) -> _Terms:
    """Pick the terms we record out of an SPF record. Unknown terms and modifiers are ignored."""
    terms = _Terms()
    for term in record.split()[1:]:
        bare = term[1:] if term[0] in _QUALIFIERS else term
        name = re.split(r"[:=/]", bare, maxsplit=1)[0].lower()
        separator = bare[len(name) : len(name) + 1]
        value = bare[len(name) + 1 :]

        if separator == "=":
            if name == "redirect" and value:
                terms.redirect = _normalise(value)
        elif name == "ip4" and separator == ":":
            terms.ip4.append(value)
        elif name == "ip6" and separator == ":":
            terms.ip6.append(value)
        elif name == "include" and separator == ":" and value:
            terms.includes.append(_normalise(value))
        elif name in _LOOKUP_MECHANISMS:
            terms.other_lookup_terms.append(term)
        elif name == "all" and not separator:
            terms.all_term = term
    return terms
