# frozen_string_literal: true

require "ipaddr"
require "resolv"
require "socket"
require "uri"

require_relative "surfguard/version"

# Resolve and classify addresses for callers that pin the selected address at
# connection time. Surfguard deliberately does not perform HTTP requests.
module Surfguard
  class Violation < StandardError; end
  class Unresolvable < StandardError; end

  class InvalidInput < ArgumentError; end
  class InvalidResolverResult < StandardError; end
  private_constant :InvalidInput, :InvalidResolverResult

  extend self

  UNRESOLVABLE_MESSAGE = "Host could not be resolved"
  BLOCKED_MESSAGE = "Refusing blocked address"
  MALFORMED_MESSAGE = "Refusing malformed address"
  MAX_HOST_BYTES = 255
  MAX_ADDRESSES = 256
  POLICIES = %i[default iana_special_use].freeze

  # iana-generator:begin IANA_ALLOCATED_IPV6_UNICAST
  # Generated from IANA IPv6 Global Unicast Status=ALLOCATED rows.
  # Source provenance is checked in under script/iana.
  IANA_ALLOCATED_IPV6_UNICAST = %w[
    2001::/23 2001:200::/23 2001:400::/23 2001:600::/23 2001:800::/22
    2001:c00::/23 2001:e00::/23 2001:1200::/23 2001:1400::/22 2001:1800::/23
    2001:1a00::/23 2001:1c00::/22 2001:2000::/19 2001:4000::/23 2001:4200::/23
    2001:4400::/23 2001:4600::/23 2001:4800::/23 2001:4a00::/23 2001:4c00::/23
    2001:5000::/20 2001:8000::/19 2001:a000::/20 2001:b000::/20 2002::/16
    2003::/18 2400::/12 2410::/12 2600::/12 2610::/23 2620::/23 2630::/12
    2800::/12 2a00::/12 2a10::/12 2c00::/12
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze
  # iana-generator:end IANA_ALLOCATED_IPV6_UNICAST

  DISALLOWED_IPV4 = %w[
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8
    168.63.129.16/32 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24
    192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15
    198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze

  DISALLOWED_IPV6 = %w[
    ::/128 100::/64 100:0:0:1::/64 2001::/32 2001:2::/48
    2001:db8::/32 2002::/16 3fff::/20 5f00::/16 fec0::/10 ff00::/8
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze

  # iana-generator:begin IANA_SPECIAL_USE_IPV4
  # Every prefix in the checked-in IANA IPv4 special-purpose snapshot.
  IANA_SPECIAL_USE_IPV4 = %w[
    0.0.0.0/8 0.0.0.0/32 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
    172.16.0.0/12 192.0.0.0/24 192.0.0.0/29 192.0.0.8/32 192.0.0.9/32
    192.0.0.10/32 192.0.0.170/32 192.0.0.171/32 192.0.2.0/24 192.31.196.0/24
    192.52.193.0/24 192.88.99.0/24 192.88.99.2/32 192.168.0.0/16
    192.175.48.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 240.0.0.0/4
    255.255.255.255/32
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze
  # iana-generator:end IANA_SPECIAL_USE_IPV4

  # iana-generator:begin IANA_SPECIAL_USE_IPV6
  # Every prefix in the checked-in IANA IPv6 special-purpose snapshot.
  IANA_SPECIAL_USE_IPV6 = %w[
    ::1/128 ::/128 ::ffff:0:0/96 64:ff9b::/96 64:ff9b:1::/48 100::/64
    100:0:0:1::/64 2001::/23 2001::/32 2001:1::1/128 2001:1::2/128
    2001:1::3/128 2001:2::/48 2001:3::/32 2001:4:112::/48 2001:10::/28
    2001:20::/28 2001:30::/28 2001:db8::/32 2002::/16 2620:4f:8000::/48
    3fff::/20 5f00::/16 fc00::/7 fe80::/10
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze
  # iana-generator:end IANA_SPECIAL_USE_IPV6

  IETF_PROTOCOL_ASSIGNMENTS = IPAddr.new("2001::/23").freeze
  GLOBALLY_REACHABLE_IETF_ASSIGNMENTS = %w[
    2001:3::/32 2001:4:112::/48
  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze
  NAT64_WELL_KNOWN = IPAddr.new("64:ff9b::/96").freeze
  NAT64_LOCAL_USE = IPAddr.new("64:ff9b:1::/48").freeze
  IPV4_TRANSLATABLE = IPAddr.new("::ffff:0:0:0/96").freeze
  IPV4_COMPATIBLE = IPAddr.new("::/96").freeze

  POLICY_RANGES = {
    default: {
      allocated_ipv6: IANA_ALLOCATED_IPV6_UNICAST,
      disallowed_ipv4: DISALLOWED_IPV4,
      disallowed_ipv6: DISALLOWED_IPV6
    }.freeze,
    iana_special_use: {
      ipv4: IANA_SPECIAL_USE_IPV4,
      ipv6: IANA_SPECIAL_USE_IPV6
    }.freeze
  }.freeze

  # Return every admitted address, with IPv4 before IPv6 and resolver order
  # retained within each family. Malformed direct input returns [].
  def resolve_public_ips(host, policy: :default)
    validate_policy!(policy)
    addresses = resolve(normalize_host(host))
    public_addresses = addresses.reject { |ip| blocked_address?(ip, policy: policy) }
    ipv4, ipv6 = public_addresses.partition(&:ipv4?)
    (ipv4 + ipv6).map { |ip| ip.to_s.freeze }.freeze
  rescue InvalidInput
    [].freeze
  end

  # True only when the URL resolves and every answer is admitted.
  def resolvable_public_ip?(url, policy: :default)
    validate_policy!(policy)
    addresses = resolve(host_of(normalize_url(url)))
    addresses.none? { |ip| blocked_address?(ip, policy: policy) }
  rescue InvalidInput, Unresolvable
    false
  end

  def enforce_public_ip(url, policy: :default)
    validate_policy!(policy)
    addresses = resolve(host_of(normalize_url(url)))
    if addresses.any? { |ip| blocked_address?(ip, policy: policy) }
      raise Violation, BLOCKED_MESSAGE, cause: nil
    end

    nil
  rescue InvalidInput
    raise Violation, MALFORMED_MESSAGE, cause: nil
  end

  # Preserve resolver order here; unlike the plural API this method does not
  # reorder address families.
  def resolve_public_ip(url, policy: :default)
    validate_policy!(policy)
    addresses = resolve(host_of(normalize_url(url)))
    return nil if addresses.any? { |ip| blocked_address?(ip, policy: policy) }

    addresses.first.to_s.freeze
  rescue InvalidInput
    nil
  end

  # Classify one endpoint. Malformed inputs and networks fail closed.
  def blocked_address?(ip, policy: :default)
    validate_policy!(policy)
    ipaddr = normalize_ip(ip)

    return true if policy == :iana_special_use && iana_special_use?(ipaddr)
    return true if ipaddr.ipv4_mapped? || IPV4_COMPATIBLE.include?(ipaddr)
    return disallowed_ipv4?(ipaddr) if ipaddr.ipv4?
    return true if NAT64_LOCAL_USE.include?(ipaddr)

    if NAT64_WELL_KNOWN.include?(ipaddr) || IPV4_TRANSLATABLE.include?(ipaddr)
      return disallowed_ipv4?(embedded_ipv4(ipaddr), policy: policy)
    end

    disallowed_ipv6?(ipaddr)
  rescue InvalidInput
    true
  end

  private
    def validate_policy!(policy)
      return policy if POLICIES.include?(policy)

      raise ArgumentError, "unknown policy", cause: nil
    end

    def normalize_url(url)
      raise InvalidInput, cause: nil unless String === url

      owned_string(url)
    end

    def normalize_host(host)
      if IPAddr === host
        ip = copy_ipaddr(host)
        raise InvalidInput, cause: nil unless host_address?(ip)

        ip
      elsif String === host
        text = owned_string(host)
        raise InvalidInput, cause: nil if text.empty? || text.bytesize > MAX_HOST_BYTES
        raise InvalidInput, cause: nil if text.include?("%")

        text
      else
        raise InvalidInput, cause: nil
      end
    end

    def normalize_ip(value)
      ip = if IPAddr === value
        copy_ipaddr(value)
      elsif String === value
        copy_ipaddr(IPAddr.new(owned_string(value)))
      else
        raise InvalidInput, cause: nil
      end
      raise InvalidInput, cause: nil unless host_address?(ip)

      ip.freeze
    rescue IPAddr::Error
      raise InvalidInput, cause: nil
    end

    def copy_ipaddr(ip)
      family = IPAddr.instance_method(:family).bind_call(ip)
      raise InvalidInput, cause: nil unless Integer === family

      canonical_family = case family
      when Socket::AF_INET
        Socket::AF_INET
      when Socket::AF_INET6
        Socket::AF_INET6
      else
        raise InvalidInput, cause: nil
      end

      integer = IPAddr.instance_method(:to_i).bind_call(ip)
      raise InvalidInput, cause: nil unless Integer === integer

      mask = Object.instance_method(:instance_variable_get).bind_call(ip, :@mask_addr)
      raise InvalidInput, cause: nil unless Integer === mask

      prefix = IPAddr.instance_method(:prefix).bind_call(ip)
      bits = canonical_family == Socket::AF_INET ? 32 : 128
      raise InvalidInput, cause: nil unless (0..bits).cover?(prefix)
      raise InvalidInput, cause: nil unless (0...(1 << bits)).cover?(integer)
      raise InvalidInput, cause: nil unless mask == ((1 << prefix) - 1) << (bits - prefix)

      zone = Object.instance_method(:instance_variable_get).bind_call(ip, :@zone_id)
      raise InvalidInput, cause: nil unless NilClass === zone

      IPAddr.new(integer, canonical_family).mask(prefix)
    end

    def owned_string(value)
      raise InvalidInput, cause: nil unless String === value

      text = String.new(value)
      raise InvalidInput, cause: nil unless text.valid_encoding? && text.ascii_only?
      raise InvalidInput, cause: nil if text.include?("\0")

      text.freeze
    end

    def resolve(host)
      literals = if IPAddr === host
        [ host ]
      else
        numeric_literals(host)
      end
      raw = literals || Resolv.getaddresses(host)
      normalize_answers(raw)
    rescue Resolv::ResolvError, Resolv::ResolvTimeout, InvalidResolverResult,
      SocketError, SystemCallError, IOError
      raise Unresolvable, UNRESOLVABLE_MESSAGE, cause: nil
    end

    def normalize_answers(raw)
      raise InvalidResolverResult, cause: nil unless Array === raw

      answers = []
      seen = {}
      raw_count = 0
      Array.instance_method(:each).bind_call(raw) do |answer|
        raw_count += 1
        raise InvalidResolverResult, cause: nil if raw_count > MAX_ADDRESSES

        ip = normalize_resolver_answer(answer)
        key = [ ip.family, ip.to_i ]
        next if seen[key]

        seen[key] = true
        answers << ip
      end
      raise Unresolvable, UNRESOLVABLE_MESSAGE, cause: nil if answers.empty?

      answers.freeze
    end

    def normalize_resolver_answer(answer)
      raise InvalidResolverResult, cause: nil unless String === answer || IPAddr === answer

      normalize_ip(answer)
    rescue InvalidInput
      raise InvalidResolverResult, cause: nil
    end

    def numeric_literals(host)
      raise InvalidInput, cause: nil unless valid_host_syntax?(host)
      raise InvalidInput, cause: nil if malformed_numeric_host_candidate?(host)

      raw = Socket.getaddrinfo(
        host, nil, Socket::AF_UNSPEC, Socket::SOCK_STREAM, 0, Socket::AI_NUMERICHOST
      )
      raise InvalidResolverResult, cause: nil unless Array === raw

      Array.instance_method(:map).bind_call(raw) do |answer|
        raise InvalidResolverResult, cause: nil unless Array === answer

        address = Array.instance_method(:[]).bind_call(answer, 3)
        raise InvalidResolverResult, cause: nil unless String === address

        address
      end
    rescue SocketError
      literal = ip_literal(host)
      return [ literal.freeze ] if literal

      raise InvalidInput, cause: nil if numeric_host_candidate?(host)

      nil
    end

    def valid_host_syntax?(host)
      return true if host.include?(":") || legacy_ipv4_shape?(host) || full_width_host_literal?(host)

      absolute = host.end_with?(".")
      labels = (absolute ? host[0...-1] : host).split(".", -1)
      return false if labels.empty? || labels.any?(&:empty?)

      labels.all? do |label|
        label.bytesize <= 63 && label.match?(/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/)
      end
    end

    def numeric_host_candidate?(host)
      host.include?(":") || legacy_ipv4_shape?(host)
    end

    def malformed_numeric_host_candidate?(host)
      return false if host.include?(":")

      core = host.sub(%r{\A[%/]+}, "")[%r{\A[^%/]*}]
      labels = core.split(".", -1)
      malformed = core != host || labels.any?(&:empty?)
      malformed && legacy_ipv4_shape?(core) && !full_width_host_literal?(host)
    end

    def legacy_ipv4_shape?(text)
      parts = text.split(".", -1).reject(&:empty?)
      (1..4).cover?(parts.length) &&
        parts.all? { |part| part.match?(/\A(?:0[xX][0-9A-Fa-f]+|[0-9]+)\z/) }
    end

    def full_width_host_literal?(text)
      host_address?(IPAddr.new(text))
    rescue IPAddr::InvalidAddressError
      false
    end

    def ip_literal(host)
      normalize_ip(host)
    rescue InvalidInput
      nil
    end

    def host_address?(ip)
      ip.prefix == (ip.ipv4? ? 32 : 128)
    end

    def host_of(url)
      uri = URI.parse(url)
      host = uri.host
      raise InvalidInput, cause: nil if host.nil? || host.empty?
      raise InvalidInput, cause: nil if host.match?(/\A\[v[0-9A-F]+\./i)

      normalize_host(host.delete_prefix("[").delete_suffix("]"))
    rescue URI::InvalidURIError
      raise InvalidInput, cause: nil
    end

    def iana_special_use?(ip)
      ranges = ip.ipv4? ? IANA_SPECIAL_USE_IPV4 : IANA_SPECIAL_USE_IPV6
      ranges.any? { |range| range.include?(ip) }
    end

    def disallowed_ipv4?(ip, policy: :default)
      (policy == :iana_special_use && iana_special_use?(ip)) ||
        ip.private? || ip.loopback? || ip.link_local? ||
        DISALLOWED_IPV4.any? { |range| range.include?(ip) }
    end

    def disallowed_ipv6?(ip)
      return false if GLOBALLY_REACHABLE_IETF_ASSIGNMENTS.any? { |range| range.include?(ip) }
      return true if ip.private? || ip.loopback? || ip.link_local?
      return true if IETF_PROTOCOL_ASSIGNMENTS.include?(ip)
      return true if DISALLOWED_IPV6.any? { |range| range.include?(ip) }

      IANA_ALLOCATED_IPV6_UNICAST.none? { |range| range.include?(ip) }
    end

    def embedded_ipv4(ip)
      IPAddr.new([ ip.to_i & 0xffffffff ].pack("N").unpack("C4").join("."))
    end
end
