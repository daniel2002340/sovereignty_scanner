# Soevereiniteitsscan

Soevereiniteitsscan (`soevscan`) is an open-source, passive scanner that shows which parties
and jurisdictions a domain's digital infrastructure depends on, in the spirit of
[internet.nl](https://internet.nl). For a given domain it collects public technical facts
(nameservers, mail servers, SPF, web addresses, and the networks those addresses belong to,
via the RIPEstat Data API) without relying on US-based services in its own lookup chain.
Licensed under the [EUPL-1.2](LICENSE).

**Status: work in progress.**

## Usage

```sh
uv run soevscan nlnet.nl                          # short summary
uv run soevscan nlnet.nl --json                   # full result as JSON
uv run soevscan nlnet.nl --resolver 86.54.11.100  # use an unfiltered resolver (see below)
```

`--resolver` can be repeated. `--dns-timeout`, `--http-timeout` and `--sourceapp` are also
available; see `soevscan --help`. The exit code is 0 whenever the scan ran, even if lookups
failed (that is part of the result), and 2 for invalid input.

## Choosing a DNS resolver

The resolver sees every name the scanner looks up, so `soevscan` never hardcodes one. By
default it uses your system resolver; you can pass your own instead:

```python
from soevscan.lookups.dns import lookup_mx, make_resolver

resolver = make_resolver(timeout=5.0, nameservers=["86.54.11.100", "86.54.11.200"])
print(lookup_mx("nlnet.nl", resolver))
```

Use an **unfiltered** resolver. Filtering resolvers (malware, ad or child protection) give
altered answers for blocked names, which would distort the scan results.

European options, for example:

| Resolver | Operator | Unfiltered addresses |
| --- | --- | --- |
| [DNS4EU](https://www.joindns4.eu/for-public) | Whalebone (Czech Republic), EU co-funded | `86.54.11.100`, `86.54.11.200`, `2a13:1001::86:54:11:100`, `2a13:1001::86:54:11:200` |
| [Quad9](https://quad9.net) | Quad9 Foundation (Switzerland) | `9.9.9.10`, `149.112.112.10` (note: `9.9.9.9` filters) |
| Your ISP's resolver | Your provider | see your network settings |
| Your own (e.g. [Unbound](https://nlnetlabs.nl/projects/unbound/)) | You | `127.0.0.1` |

Quad9 is a Swiss foundation, but it was founded with US partners and part of its anycast
network is hosted by partners outside Europe. Running your own recursive resolver avoids
depending on a third party for this step at all.
