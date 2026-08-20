# Surfguard

Surfguard resolves and classifies addresses for Ruby applications that fetch a URL supplied by someone else. It is deliberately not an HTTP client: the caller owns scheme restrictions, redirects, connection pinning, response limits, retries, and request deadlines.

A Go implementation with the same classification guarantees — plus dial-time enforcement and a hardened `*http.Client`, which are idiomatic and cheap in Go — lives under [`go/`](go/README.md). Both implementations generate their policy tables from the same checked-in IANA snapshots (`script/iana/`) and assert identical verdicts against the shared corpus in [`conformance/`](conformance/README.md).

## Installation

```ruby
gem "surfguard"
```

Surfguard 0.2 requires Ruby 3.4.5 or newer and has zero runtime dependencies.

To verify a downloaded release artifact against its repository, normal release
workflow, and immutable tag:

```sh
gh attestation verify surfguard-X.Y.Z.gem \
  --repo basecamp/surfguard \
  --signer-workflow basecamp/surfguard/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z
```

If the release was completed through the documented recovery path, substitute
`release-recovery.yml` as the signer workflow. Recovery dispatched on `main`
has `refs/heads/main` provenance; confirm its logged tag/rebuild equality as
described in the
[release guide](https://github.com/basecamp/surfguard/blob/main/RELEASING.md)
before accepting that residual case.

## APIs and policies

```ruby
Surfguard.resolve_public_ips(host, policy: :default)
Surfguard.resolvable_public_ip?(url, policy: :default)
Surfguard.enforce_public_ip(url, policy: :default)
Surfguard.resolve_public_ip(url, policy: :default)
Surfguard.blocked_address?(ip, policy: :default)
```

`:default` is reachability-oriented. IPv4 retains the documented SSRF deny ranges. IPv6 is admitted only when it is in a checked-in IANA `Status=ALLOCATED` unicast prefix, subject to the explicit special/transition denies. Public NAT64/SIIT translations and globally reachable AMT/AS112 services remain admitted. This is intentionally not the much broader `2000::/3`.

`:iana_special_use` additionally blocks every prefix in the checked-in IANA IPv4 and IPv6 special-purpose registries, including AMT, AS112, and the whole NAT64 well-known prefix. Use it for advertised or discovered infrastructure values. A target must never choose its own policy; trusted consumer code chooses it.

For CIMD and similar discovery, strict address policy is only one layer. Consumers must still enforce HTTPS, reject userinfo, revalidate and pin redirects, limit response bytes, and apply egress controls.

The host API accepts `String` or `IPAddr`; URL APIs accept `String`. Network prefixes are not endpoints. Invalid encodings, NUL, non-ASCII host syntax, unstable coercion, malformed resolver answers, and oversized answer sets fail closed. Unknown policies raise `ArgumentError` from every API.

| Condition | plural | predicate | enforce | single | classifier |
|---|---|---|---|---|---|
| malformed direct input | `[]` | `false` | malformed `Violation` | `nil` | `true` |
| empty, operational, or malformed resolver result | `Unresolvable` | `false` | `Unresolvable` | `Unresolvable` | n/a |
| mixed public and blocked answers | public subset | `false` | `Violation` | `nil` | n/a |
| unexpected programmer failure | escapes | escapes | escapes | escapes | escapes |

Messages are fixed and contain no input: `Host could not be resolved`, `Refusing blocked address`, and `Refusing malformed address`.

The plural result is IPv4-first while preserving resolver order within each family. The single result preserves resolver order exactly. Answers are deduplicated in order; more than 256 raw or unique answers invalidates the lookup.

Only the returned plural or single address can be pinned. The predicate and enforcement helpers are conservative preflights; they do not bind a later connection, so resolving the hostname again after either helper reopens DNS-rebinding and resolver-divergence risk.

## Pinning with Net::HTTP

This recipe disables environment proxies, retains the original hostname for HTTP Host, TLS SNI, and certificate verification, and pins the validated address. Retry only addresses already returned by the first lookup. Every redirect starts this process again with the redirect's own URL.

<!-- net-http-recipe:start -->
```ruby
require "net/http"
require "openssl"
require "surfguard"
require "uri"

PINNED_MAX_REDIRECTS = 10
PINNED_MAX_BYTES = 16 * 1024 * 1024

class PinnedResponseTooLarge < StandardError; end
class PinnedRedirectError < StandardError; end

def checked_https_uri(value, base: nil)
  uri = base ? URI.join(base, value) : URI(value)
  raise ArgumentError, "HTTPS required", cause: nil unless uri.is_a?(URI::HTTPS)
  raise ArgumentError, "userinfo forbidden", cause: nil if uri.userinfo
  raise ArgumentError, "host required", cause: nil if uri.hostname.nil? || uri.hostname.empty?

  uri
rescue URI::InvalidURIError
  raise ArgumentError, "malformed URL", cause: nil
end

def pinned_get_hop(uri, policy:, max_bytes:)
  hostname = uri.hostname # strips IPv6 URI brackets; preserves DNS identity
  addresses = Surfguard.resolve_public_ips(hostname, policy: policy)
  raise Surfguard::Violation, Surfguard::BLOCKED_MESSAGE, cause: nil if addresses.empty?

  addresses.each do |address|
    http = Net::HTTP.new(hostname, uri.port, nil) # nil disables environment proxies
    http.use_ssl = true
    http.ipaddr = address                         # connect only to this validated address
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_hostname = true
    http.open_timeout = 5
    http.read_timeout = 15
    http.write_timeout = 15
    begin
      body = String.new(encoding: Encoding::BINARY)
      request = Net::HTTP::Get.new(uri.request_uri, "Accept-Encoding" => "identity")
      response = http.request(request) do |candidate|
        candidate.read_body do |chunk|
          raise PinnedResponseTooLarge, "response body exceeds limit", cause: nil if
            chunk.bytesize > max_bytes - body.bytesize

          body << chunk
        end
      end
      return [ response, body.freeze ]
    rescue IOError, SystemCallError, Timeout::Error
      # Try the next address from the original validated list. Never resolve again here.
    end
  end
  raise Surfguard::Unresolvable, Surfguard::UNRESOLVABLE_MESSAGE, cause: nil
end

def pinned_get(url, policy: :default, max_redirects: 5, max_bytes: 1024 * 1024)
  unless max_redirects.is_a?(Integer) && (0..PINNED_MAX_REDIRECTS).cover?(max_redirects)
    raise ArgumentError, "invalid redirect limit", cause: nil
  end
  unless max_bytes.is_a?(Integer) && (1..PINNED_MAX_BYTES).cover?(max_bytes)
    raise ArgumentError, "invalid response limit", cause: nil
  end

  uri = checked_https_uri(url)
  redirects = 0
  loop do
    response, body = pinned_get_hop(uri, policy: policy, max_bytes: max_bytes)
    return [ response, body ] unless response.is_a?(Net::HTTPRedirection)

    raise PinnedRedirectError, "redirect limit exceeded", cause: nil if redirects >= max_redirects

    location = response["location"]
    raise PinnedRedirectError, "redirect location missing", cause: nil if location.nil? || location.empty?

    uri = checked_https_uri(location, base: uri)
    redirects += 1
  end
end
```
<!-- net-http-recipe:end -->

The recipe returns `[response, body]`. It streams and caps each response body, caps redirect count, rejects non-HTTPS or userinfo-bearing redirects, and performs a fresh validation and pin for every redirect target. It never follows a redirect on the previous connection. The hard ceilings prevent a caller from accidentally configuring either bound away; choose smaller trusted values when appropriate.

Surfguard's synchronous resolver has no independent cancellation deadline. The caller must apply a request or worker deadline around the whole operation. Surfguard intentionally does not use `Timeout.timeout`, which can interrupt code at unsafe points.

## Policy boundaries and residual topology risk

Surfguard blocks private, loopback, link-local, CGNAT, documentation, benchmark, multicast, reserved, IETF protocol, deprecated transition, ULA, and other explicitly listed address space. It also blocks Azure WireServer `168.63.129.16`; other provider/platform aliases need equivalent consumer egress policy when they are not represented by a standard address range.

Address labels cannot prove reachability. DNS rebinding is prevented only when the caller pins. Ruby `Resolv` can differ from NSS sources such as mDNS or LDAP; platform and version configuration can also change AAAA behavior. A glibc `no-aaaa` setting does not control pure-Ruby `Resolv`.

Custom DNS64 prefixes cannot be decoded from an address without deployment configuration. ISATAP and 6rd can give deployment-specific meaning to otherwise public-looking IPv6 addresses. Publicly addressed space may be routed internally. Platform aliases can also live in globally addressed space. Surfguard does not add a hostname blocklist or attempt to infer those topologies. Enforce outbound firewall/egress ACLs so the fetch worker cannot reach internal services even when addressing is unusual.

The default policy intentionally admits public NAT64/SIIT destinations and globally reachable AMT/AS112 services. The strict policy intentionally overblocks all registered special-purpose prefixes. Choose based on the trusted source of the target, not target-supplied data.

Operator-named development fixtures are outside Surfguard policy. If a consumer needs one, make it an exact consumer-owned exception gated by trusted configuration and restricted to an approved scheme, literal loopback address, and exact port. Do not expose a general loopback mode or let request data activate it.

Environment proxies can cause a validated URL to connect somewhere else; construct `Net::HTTP` with the explicit `nil` proxy argument as above. Restrict supported schemes, userinfo, redirects, response bytes, decompression, and request duration in the consumer. Egress ACLs remain the final boundary.

## Registry data

Runtime classification never fetches registry data. Normalized IANA snapshots, source URLs, registry update dates, and raw SHA-256 digests live under `script/iana`. Generated runtime constants are deeply frozen. Scheduled and release checks report drift and require a reviewed human update; they never rewrite policy automatically.

## Dependency residual risk

Ruby 3.4.5 is the minimum supported interpreter. CI rejects effective `resolv` versions `<0.2.3`, `>=0.3.0,<0.3.1`, and `>=0.4.0,<0.6.2`. Explicitly replacing the patched standard-library gem with an affected version is unsupported residual risk. Surfguard will not add a runtime dependency or runtime version guard for that operator override.

## Security

Report classification vulnerabilities privately using the [security policy](https://github.com/basecamp/surfguard/security/policy). Do not open a public issue.
