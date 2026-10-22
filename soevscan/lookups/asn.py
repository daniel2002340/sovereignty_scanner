"""IP to ASN lookup via the RIPEstat Data API (RIPE NCC).

For one IP address we ask RIPEstat ``network-info`` for the routed prefix and its origin
ASNs, then ``as-overview`` for the name of each ASN's holder. Only raw facts are collected;
no country or jurisdiction is derived here. Like the other lookups, this never raises on
network or API problems; failures become a status and an ``error``.

Calls are sequential and not retried: within one scan each IP and each ASN is requested at
most once, and failed results are cached too.
"""

import ipaddress
from typing import Any

import httpx

from soevscan import __version__
from soevscan.lookups.models import AsnEntry, AsnInfo, LookupStatus

PROJECT_URL = "https://github.com/daniel2002340/sovereignty_scanner"
RIPESTAT_URL = "https://stat.ripe.net/data"


def make_http_client(timeout: float) -> httpx.Client:
    """An HTTP client that identifies itself as soevscan, for use with ``AsnLookup``.

    ``timeout`` is in seconds and, as in httpx, applies to each phase of a request
    separately (connect, read, write and waiting for a pooled connection), not to the request
    as a whole. A slow server that keeps sending data can therefore take longer than this.
    """
    user_agent = f"soevscan/{__version__} (+{PROJECT_URL})"
    return httpx.Client(timeout=timeout, headers={"User-Agent": user_agent})


class _RipestatError(Exception):
    """A failed RIPEstat call, with the status it maps to."""

    def __init__(self, status: LookupStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class AsnLookup:
    """Looks up IPs in RIPEstat, caching per IP and per ASN for the duration of one scan.

    Use one instance per scan. ``sourceapp`` is sent with every request, as RIPEstat asks
    of regular users, so they can see which tool the traffic comes from.
    """

    def __init__(self, client: httpx.Client, sourceapp: str = "soevscan") -> None:
        self._client = client
        self._sourceapp = sourceapp
        self._by_ip: dict[str, AsnInfo] = {}
        self._holders: dict[int, tuple[str | None, str | None]] = {}  # ASN -> (holder, error)

    def lookup(self, ip: str) -> AsnInfo:
        """The prefix and origin ASNs (with holder names) of ``ip``.

        ``AsnInfo.ip`` is the canonical form of the address (lowercase, compressed IPv6).
        Non-public addresses are SKIPPED without a request. If an ASN's holder cannot be
        fetched, the ASN is kept with holder None and the result stays OK, with a note in
        ``error``.
        """
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return AsnInfo(ip=ip, status=LookupStatus.ERROR, error=f"invalid IP address: {ip!r}")
        canonical = str(address)
        if not address.is_global:
            return AsnInfo(
                ip=canonical, status=LookupStatus.SKIPPED, error="not a public IP address"
            )
        if canonical not in self._by_ip:
            self._by_ip[canonical] = self._lookup_ip(canonical)
        return self._by_ip[canonical]

    def _lookup_ip(self, ip: str) -> AsnInfo:
        try:
            prefix, asns = _parse_network_info(self._get_data("network-info", ip))
        except _RipestatError as e:
            return AsnInfo(ip=ip, status=e.status, error=e.message)
        if not asns:
            return AsnInfo(
                ip=ip,
                status=LookupStatus.NO_RECORDS,
                error="not announced according to RIPEstat",
                prefix=prefix,
            )

        entries: list[AsnEntry] = []
        notes: list[str] = []
        for asn in asns:
            holder, error = self._holder(asn)
            entries.append(AsnEntry(asn=asn, holder=holder))
            if error is not None:
                notes.append(f"holder of AS{asn} unknown: {error}")
        return AsnInfo(
            ip=ip,
            status=LookupStatus.OK,
            error="; ".join(notes) or None,
            prefix=prefix,
            asns=entries,
        )

    def _holder(self, asn: int) -> tuple[str | None, str | None]:
        """The holder name of ``asn`` and an error message if it could not be fetched."""
        if asn not in self._holders:
            try:
                data = self._get_data("as-overview", f"AS{asn}")
                self._holders[asn] = (_parse_as_overview(data), None)
            except _RipestatError as e:
                self._holders[asn] = (None, e.message)
        return self._holders[asn]

    def _get_data(self, call: str, resource: str) -> dict[str, Any]:
        """The ``data`` object of a RIPEstat response. Raises ``_RipestatError`` on failure."""
        url = f"{RIPESTAT_URL}/{call}/data.json"
        params = {"resource": resource, "sourceapp": self._sourceapp}
        try:
            response = self._client.get(url, params=params)
        except httpx.TimeoutException:
            raise _RipestatError(LookupStatus.TIMEOUT, f"{call}: timed out") from None
        except httpx.HTTPError as e:
            raise _RipestatError(
                LookupStatus.ERROR, f"{call}: {str(e) or type(e).__name__}"
            ) from None
        if response.status_code != 200:
            raise _RipestatError(LookupStatus.ERROR, f"{call}: HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            raise _RipestatError(LookupStatus.ERROR, f"{call}: response is not JSON") from None
        if not isinstance(body, dict):
            raise _RipestatError(LookupStatus.ERROR, f"{call}: unexpected response")
        if body.get("status") != "ok":
            raise _RipestatError(
                LookupStatus.ERROR, f"{call}: RIPEstat status {body.get('status')!r}"
            )
        data = body.get("data")
        if not isinstance(data, dict):
            raise _RipestatError(LookupStatus.ERROR, f"{call}: response has no data")
        return data


def _parse_network_info(data: dict[str, Any]) -> tuple[str | None, list[int]]:
    """Prefix and origin ASNs from ``network-info`` data. An unrouted IP has prefix ""."""
    asns = data.get("asns")
    prefix = data.get("prefix")
    if not isinstance(asns, list) or not (prefix is None or isinstance(prefix, str)):
        raise _RipestatError(LookupStatus.ERROR, "network-info: missing asns or prefix")
    try:
        return prefix or None, [int(asn) for asn in asns]  # RIPEstat sends ASNs as strings
    except (TypeError, ValueError):
        raise _RipestatError(LookupStatus.ERROR, "network-info: invalid ASN in asns") from None


def _parse_as_overview(data: dict[str, Any]) -> str | None:
    """Holder name from ``as-overview`` data. Unregistered ASNs have holder null or ""."""
    if "holder" not in data:
        raise _RipestatError(LookupStatus.ERROR, "as-overview: missing holder")
    holder = data["holder"]
    if not (holder is None or isinstance(holder, str)):
        raise _RipestatError(LookupStatus.ERROR, "as-overview: invalid holder")
    return holder or None
