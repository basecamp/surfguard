# frozen_string_literal: true

require "ipaddr"
require "resolv"
require "uri"

require_relative "surfguard/version"

# One SSRF address policy for a Ruby app that fetches a URL someone else supplied.
# It consolidates several drifting in-house copies of this policy — copies that had
# grown four different ideas of what "internal" means, including one that decoded a
# NAT64 prefix whose length is not recoverable from the address. This is their
# union, decided once.
#
# Two policy decisions the copies drifted on, settled here and explained where
# they live in the code:
#
#   * Resolver (see .resolve_public_ips): resolve with Resolv.getaddresses, which
#     honours /etc/hosts and search domains AND returns every address. One copy
#     used Resolv.getaddress (honours hosts, but only the FIRST address, so an
#     AAAA-only host deterministically selected the IPv6 path); another used
#     Resolv::DNS.open (all addresses, but ignores /etc/hosts, so it validated a
#     different set than Net::HTTP would actually connect to). getaddresses is
#     both complete and faithful to what the connection layer resolves.
#
#   * `no-aaaa` in Kamal `dns-opt` is NOT a mitigation. It is a glibc
#     getaddrinfo option; every guard here resolves through pure-Ruby Resolv,
#     which asks for AAAA regardless. IPv6 answers reach this code in production.
#     Do not treat the deploy config as if it narrowed the input.
#
# THREAT MODEL / caller contract: this only resolves and classifies. It cannot
# stop DNS rebinding on its own. A caller must PIN the connection to an address
# this returned (Net::HTTP#ipaddr=), because a second lookup at connect time can
# answer differently than the one that was validated. The plural API exists so
# that a caller failing over between addresses iterates the validated list rather
# than resolving again inside its retry loop. A non-pinning caller must instead
# use .resolvable_public_ip?/.enforce_public_ip, which refuse unless EVERY
# resolved address is public.
module Surfguard
  class Violation < StandardError; end

  extend self

  # IPv4 special-use ranges that must never be a fetch target (RFC 5735/6890,
  # plus CGNAT and benchmarking). RFC1918 / loopback / link-local are also
  # covered by the IPAddr predicates in #disallowed_ipv4?; they are restated here
  # so the policy is complete and auditable in one place.
  DISALLOWED_IPV4 = [
    IPAddr.new("0.0.0.0/8"),        # "This" network (RFC 1122)
    IPAddr.new("10.0.0.0/8"),       # Private (RFC 1918)
    IPAddr.new("100.64.0.0/10"),    # Carrier-grade NAT (RFC 6598)
    IPAddr.new("127.0.0.0/8"),      # Loopback (RFC 1122)
    IPAddr.new("169.254.0.0/16"),   # Link-local (RFC 3927) — includes the cloud metadata endpoint
    IPAddr.new("172.16.0.0/12"),    # Private (RFC 1918)
    IPAddr.new("192.0.0.0/24"),     # IETF protocol assignments (RFC 6890)
    IPAddr.new("192.0.2.0/24"),     # TEST-NET-1 (RFC 5737)
    IPAddr.new("192.88.99.0/24"),   # 6to4 relay anycast (RFC 7526)
    IPAddr.new("192.168.0.0/16"),   # Private (RFC 1918)
    IPAddr.new("198.18.0.0/15"),    # Benchmark testing (RFC 2544)
    IPAddr.new("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    IPAddr.new("203.0.113.0/24"),   # TEST-NET-3 (RFC 5737)
    IPAddr.new("224.0.0.0/4"),      # Multicast (RFC 5771)
    IPAddr.new("240.0.0.0/4")       # Reserved / future use (RFC 1112)
  ].freeze

  # IPv6 special-use ranges beyond what private? (ULA fc00::/7, incl. the IMDSv6
  # address fd00:ec2::254), loopback (::1) and link-local (fe80::/10) already
  # cover. 6to4 and Teredo are deprecated transition mechanisms with no
  # legitimate fetch target — 2002:7f00:1:: is just a 6to4 spelling of 127.0.0.1.
  DISALLOWED_IPV6 = [
    IPAddr.new("::/128"),           # Unspecified (RFC 4291)
    IPAddr.new("100::/64"),         # Discard-only (RFC 6666)
    IPAddr.new("2001::/32"),        # Teredo (RFC 4380)
    IPAddr.new("2001:2::/48"),      # Benchmark testing (RFC 5180)
    IPAddr.new("2001:db8::/32"),    # Documentation (RFC 3849)
    IPAddr.new("2002::/16"),        # 6to4 (RFC 3056)
    IPAddr.new("fec0::/10"),        # Deprecated site-local (RFC 3879)
    IPAddr.new("ff00::/8")          # Multicast (RFC 4291)
  ].freeze

  # NAT64 embeds an IPv4 target that must be re-checked as IPv4. The well-known
  # prefix is a fixed /96, so the embedded octets are always the low 32 bits:
  # decode and re-check them, and NAT64 to a public address still resolves.
  NAT64_WELL_KNOWN = IPAddr.new("64:ff9b::/96")   # RFC 6052

  # The RFC 8215 local-use block is refused whole, not decoded. It can host a
  # Pref64 of any length (/32…/96) whose embedded position is NOT recoverable
  # from the address alone (RFC 6052 §2.2), so decoding the low 32 bits reads the
  # wrong octets and can under-block. It is also never globally routed, so there
  # is no legitimate feed behind it. This is the divergence some in-house copies
  # got wrong by decoding both prefixes the same way.
  NAT64_LOCAL_USE = IPAddr.new("64:ff9b:1::/48")  # RFC 8215

  # SIIT's IPv4-translated form is the third way an IPv4 address rides inside an
  # IPv6 one, and the only one Ruby has no predicate for: ipv4_mapped?,
  # ipv4_compat?, private?, loopback? and link_local? are all false for
  # ::ffff:0:169.254.169.254, so it would reach the metadata address straight
  # through the branches below. Note the extra group — ::ffff:0:0:0/96 is NOT the
  # familiar IPv4-mapped ::ffff:0:0/96, and the two ranges do not overlap. Like
  # the NAT64 well-known prefix it is a fixed /96, so decode the low 32 bits.
  IPV4_TRANSLATABLE = IPAddr.new("::ffff:0:0:0/96") # RFC 2765

  # Every PUBLIC address the host resolves to, IPv4 ahead of IPv6, DNS order
  # preserved within each family so a provider's round-robin still spreads load.
  # Empty when nothing usable resolves — the caller's signal to refuse. A caller
  # that fails over MUST iterate this list and pin each address; resolving again
  # reopens the rebinding window. Accepts a hostname or an IP-literal host.
  def resolve_public_ips(host)
    resolve(host).reject { |ip| blocked_address?(ip) }
                 .partition(&:ipv4?)
                 .flatten
                 .map(&:to_s)
  end

  # True only if the URL's host resolves to at least one address and NONE are
  # blocked. For non-pinning callers (they hand the hostname straight to
  # Net::HTTP, which resolves again), so anything short of "every address is
  # public" is unsafe. Returns false on an unresolvable or malformed host.
  def resolvable_public_ip?(url)
    addresses = resolve(host_of(url))
    addresses.any? && addresses.none? { |ip| blocked_address?(ip) }
  rescue URI::InvalidURIError, IPAddr::InvalidAddressError, ArgumentError
    false
  end

  # Raise Surfguard::Violation unless the URL's host is safe (see
  # .resolvable_public_ip?). For call sites that want a hard stop, not a boolean.
  def enforce_public_ip(url)
    raise Violation, "Refusing to fetch private/internal address for #{url}" unless resolvable_public_ip?(url)
  end

  # The single-address compatibility shim for callers migrating from an older
  # first-address-only guard. Returns the first public address as a String, or nil
  # if the host is unresolvable, malformed, or resolves to anything blocked. Prefer
  # .resolve_public_ips for new code.
  def resolve_public_ip(url)
    addresses = resolve(host_of(url))
    return nil if addresses.empty? || addresses.any? { |ip| blocked_address?(ip) }
    addresses.first.to_s
  rescue URI::InvalidURIError, IPAddr::InvalidAddressError, ArgumentError
    nil
  end

  # The classification core. True if this address must never be a fetch target.
  # Accepts an IPAddr or anything IPAddr.new understands. Errs closed: an address
  # it cannot parse is blocked.
  def blocked_address?(ip)
    ipaddr = ip.is_a?(IPAddr) ? ip : IPAddr.new(ip.to_s)

    # DNS never legitimately returns an IPv4 address embedded these two ways, so
    # refuse them regardless of the address they wrap.
    if ipaddr.ipv4_mapped? || ipaddr.ipv4_compat?
      true
    elsif ipaddr.ipv4?
      disallowed_ipv4?(ipaddr)
    elsif NAT64_LOCAL_USE.include?(ipaddr)
      true
    elsif NAT64_WELL_KNOWN.include?(ipaddr) || IPV4_TRANSLATABLE.include?(ipaddr)
      disallowed_ipv4?(embedded_ipv4(ipaddr))
    else
      disallowed_ipv6?(ipaddr)
    end
  rescue IPAddr::InvalidAddressError
    true
  end

  private

  # An IP-literal host skips DNS so a public literal URL resolves directly and an
  # internal literal is still caught by blocked_address?. Otherwise resolve via
  # Resolv.getaddresses — the Hosts+DNS chain, matching what the connection layer
  # will use, and returning every address. Returns [IPAddr].
  def resolve(host)
    [ IPAddr.new(host) ]
  rescue IPAddr::InvalidAddressError
    Resolv.getaddresses(host).map { |a| IPAddr.new(a) }
  rescue Resolv::ResolvError, Resolv::ResolvTimeout
    []
  end

  def host_of(url)
    # URI#host keeps IPv6 brackets ([::1]); IPAddr.new does not want them.
    host = URI.parse(url).host or raise URI::InvalidURIError, "no host in #{url.inspect}"
    host.delete_prefix("[").delete_suffix("]")
  end

  def disallowed_ipv4?(ipaddr)
    ipaddr.private? || ipaddr.loopback? || ipaddr.link_local? ||
      DISALLOWED_IPV4.any? { |range| range.include?(ipaddr) }
  end

  def disallowed_ipv6?(ipaddr)
    ipaddr.private? || ipaddr.loopback? || ipaddr.link_local? ||
      DISALLOWED_IPV6.any? { |range| range.include?(ipaddr) }
  end

  # RFC 6052 §2.2: a fixed /96 translation prefix carries the IPv4 target in the
  # low 32 bits.
  def embedded_ipv4(ipaddr)
    IPAddr.new([ ipaddr.to_i & 0xffffffff ].pack("N").unpack("C4").join("."))
  end
end
