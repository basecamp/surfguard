# Surfguard

[![CI](https://github.com/basecamp/surfguard/actions/workflows/ci.yml/badge.svg)](https://github.com/basecamp/surfguard/actions/workflows/ci.yml)

One SSRF address policy for Ruby apps that fetch a URL someone else supplied.

It consolidates several drifting in-house copies of this policy into one — copies that had grown
four different ideas of what "internal" means, including one that decoded a NAT64 prefix whose length
is not recoverable from the address. This gem is their union, decided once and tested against the
full IPv4 × IPv6 range matrix.

## Installation

Not yet published to RubyGems — `v0.1.0` will be the first packaged release. Until it ships,
install from source:

```ruby
gem "surfguard", github: "basecamp/surfguard"
```

Once `v0.1.0` is published:

```ruby
gem "surfguard"
```

## What it does

Resolve **and classify only**. It cannot stop DNS rebinding by itself — the caller owns the fetch
and must **pin** the connection to an address this returned.

```ruby
# Pinning caller (preferred): validate, then pin each address you try.
Surfguard.resolve_public_ips("feeds.example.com")
# => ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]   (IPv4 first, blocked removed)
# Iterate THIS list on failover; do not resolve again inside a retry loop.

# Non-pinning caller (hands the hostname straight to Net::HTTP, which resolves again):
Surfguard.resolvable_public_ip?("https://feeds.example.com/atom")  # => true only if EVERY address is public
Surfguard.enforce_public_ip(url)                                   # raises otherwise

# Single-address compatibility shim:
Surfguard.resolve_public_ip(url)   # => "93.184.216.34" or nil

# The classification core, if you already hold an address:
Surfguard.blocked_address?(IPAddr.new("169.254.169.254"))  # => true
```

## Refused vs. unresolvable

"We refuse that address" and "the host didn't answer" are different answers, and
collapsing them bites callers that treat a refusal as permanent. A webhook that
deactivates a customer's endpoint on `Violation` would retire it on one bad DNS
minute if a failed lookup arrived the same way.

| | resolves to something public | resolves, all blocked | resolves to nothing | malformed URL |
|---|---|---|---|---|
| `resolve_public_ips` (takes a host) | the public addresses | `[]` | raises `Unresolvable` | — |
| `resolve_public_ip` | first public address | `nil` | raises `Unresolvable` | `nil` |
| `enforce_public_ip` | returns | raises `Violation` | raises `Unresolvable` | raises `Violation` |
| `resolvable_public_ip?` | `true` | `false` | `false` | `false` |

`Unresolvable` is **not** a subclass of `Violation` — that's the whole point.
Rescue both where you don't care which it was. Note the predicate answers the
question it was asked and never raises; use `enforce_public_ip` or
`resolve_public_ip` when you need to tell the cases apart.

## The policy

| Range | Handling |
|---|---|
| IPv4 private (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16) | refuse |
| CGNAT (100.64/10), benchmark (198.18/15), TEST-NETs, IETF (192.0.0/24), 6to4 relay anycast (192.88.99/24), multicast (224/4), reserved (240/4), "this" (0/8) | refuse |
| IPv6 ULA (fc00::/7, incl. IMDSv6 `fd00:ec2::254`), loopback (::1), link-local (fe80::/10), site-local (fec0::/10), multicast (ff00::/8), unspecified (::), discard (100::/64), Teredo (2001::/32), docs (2001:db8::/32), benchmark (2001:2::/48) | refuse |
| IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96` | refuse outright |
| **SIIT `::ffff:0:0:0/96`** | decode embedded IPv4 (low 32 bits), re-check |
| NAT64 well-known `64:ff9b::/96` | decode embedded IPv4 (low 32 bits), re-check |
| **RFC 8215 NAT64 local-use `64:ff9b:1::/48`** | **refuse outright** — the Pref64 length is not recoverable from the address (RFC 6052 §2.2), so a low-32-bit decode reads the wrong octets; and the block is never globally routed |
| 6to4 `2002::/16` | refuse (a 6to4 address is just an IPv4 address in disguise) |

## Two things worth knowing

**1. The resolver is part of the policy.** Surfguard resolves with `Resolv.getaddresses`, which
honours `/etc/hosts` and search domains **and** returns every address. The obvious alternatives each
drop something a guard can't afford to lose:

- `Resolv.getaddress` honours `/etc/hosts` but returns only the **first** address — so an AAAA-only
  host deterministically takes the IPv6 path, and a multi-homed host is validated on one address
  while the connection may use another.
- `Resolv::DNS.open` returns every address but **ignores** `/etc/hosts` and search domains — so it
  validates a different set than `Net::HTTP` (which resolves through `getaddrinfo`) will actually
  connect to. Demonstrable: `Resolv.getaddresses("localhost")` → `["::1","127.0.0.1"]` while
  `Resolv::DNS.open`'s `each_address("localhost")` → `["::","0.0.0.0"]`.

`getaddresses` is both complete (every address) and faithful (the same chain the connection layer
uses).

**2. A resolver-level "no AAAA" switch is not a mitigation.** Disabling AAAA at the system resolver
(for example Kamal's `dns-opt: no-aaaa`) is a glibc `getaddrinfo` option. Surfguard resolves through
pure-Ruby `Resolv`, which requests AAAA regardless, so IPv6 answers still reach it. Don't treat that
deploy setting as if it narrowed Surfguard's input.

## Testing

```bash
ruby -Ilib test/surfguard_test.rb
# The full BLOCKED/ALLOWED matrix, checked as execution. Bare Ruby, no gems needed.
```

## Security

Surfguard is a security control, so classification bugs are vulnerabilities. Report them privately
per the [security policy](https://github.com/basecamp/surfguard/security/policy) — not the public
issue tracker.

## Status

Extracted and consolidated from several in-house SSRF guards, tested against the full
IPv4 × IPv6 special-use matrix. Resolve-and-classify only; callers pin. See the
[releases page](https://github.com/basecamp/surfguard/releases) for versions and changes.
