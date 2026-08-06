# frozen_string_literal: true

require "minitest/autorun"
require "resolv"
require_relative "../lib/surfguard"

class SurfguardTest < Minitest::Test
  # --- classification: the full policy matrix, checked as execution -----------

  BLOCKED = {
    # IPv4 private / special-use
    "link-local (instance metadata)"     => "169.254.169.254",
    "link-local (container credentials)" => "169.254.170.2",
    "loopback"                           => "127.0.0.1",
    "private 10/8"                        => "10.0.0.1",
    "private 172.16/12"                  => "172.16.0.1",
    "private 192.168/16"                 => "192.168.1.1",
    "carrier-grade NAT"                  => "100.64.0.1",
    "this network"                       => "0.0.0.0",
    "IETF protocol assignments"          => "192.0.0.1",
    "6to4 relay anycast"                 => "192.88.99.1",
    "benchmarking"                       => "198.18.0.1",
    "TEST-NET-1"                         => "192.0.2.1",
    "multicast"                          => "224.0.0.1",
    "reserved"                           => "240.0.0.1",
    "broadcast"                          => "255.255.255.255",
    # IPv6 native
    "IPv6 loopback"                      => "::1",
    "IPv6 unspecified"                   => "::",
    "IPv6 unique-local (ULA)"            => "fd00::1",
    "IPv6 IMDSv6"                        => "fd00:ec2::254",
    "IPv6 link-local"                    => "fe80::1",
    "IPv6 site-local (deprecated)"       => "fec0::1",
    "IPv6 multicast"                     => "ff02::1",
    "IPv6 discard-only"                  => "100::1",
    "IPv6 Teredo"                        => "2001:0:a9fe:a9fe::",
    "IPv6 documentation"                 => "2001:db8::1",
    # IPv4-in-IPv6 encapsulations
    "IPv4-mapped link-local"             => "::ffff:169.254.169.254",
    "IPv4-compatible link-local"         => "::169.254.169.254",
    "SIIT loopback"                      => "::ffff:0:7f00:1",
    "SIIT link-local"                    => "::ffff:0:a9fe:a9fe",
    "NAT64 WKP link-local"               => "64:ff9b::a9fe:a9fe",
    "NAT64 WKP loopback"                 => "64:ff9b::7f00:1",
    "NAT64 local-use (public target)"    => "64:ff9b:1::5db8:d822", # decodes to a PUBLIC IPv4 (93.184.216.34), still refused whole
    "6to4 link-local"                    => "2002:a9fe:a9fe::",
    "6to4 loopback"                      => "2002:7f00:1::"
  }.freeze

  ALLOWED = {
    "public IPv4"                          => "93.184.216.34",
    "public IPv6"                          => "2606:2800:220:1:248:1893:25c8:1946",
    "octet below link-local"               => "169.253.255.255",
    "octet above link-local"               => "169.255.0.0",
    "below carrier-grade NAT"              => "100.63.255.255",
    "above carrier-grade NAT"              => "100.128.0.0",
    "NAT64 WKP wrapping a public IPv4"     => "64:ff9b::5db8:d822", # 93.184.216.34
    "SIIT wrapping a public IPv4"          => "::ffff:0:5db8:d822"
  }.freeze

  BLOCKED.each do |label, address|
    define_method("test_blocks_#{label.gsub(/\W+/, '_')}") do
      assert Surfguard.blocked_address?(IPAddr.new(address)),
        "expected #{label} (#{address}) to be blocked"
    end
  end

  ALLOWED.each do |label, address|
    define_method("test_allows_#{label.gsub(/\W+/, '_')}") do
      refute Surfguard.blocked_address?(IPAddr.new(address)),
        "expected #{label} (#{address}) to be allowed"
    end
  end

  def test_the_two_nat64_prefixes_do_not_overlap
    refute Surfguard::NAT64_WELL_KNOWN.include?(IPAddr.new("64:ff9b:1::1"))
    refute Surfguard::NAT64_LOCAL_USE.include?(IPAddr.new("64:ff9b::1"))
  end

  def test_siit_and_mapped_prefixes_do_not_overlap
    refute Surfguard::IPV4_TRANSLATABLE.include?(IPAddr.new("::ffff:169.254.169.254"))
  end

  def test_blocks_an_unparseable_address
    assert Surfguard.blocked_address?("not-an-ip")
  end

  # --- resolution (stub the resolver; never hit the network) ------------------

  def stub_getaddresses(map)
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) { |host| map.fetch(host, []) }
    yield
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def test_resolvable_public_ip_true_for_all_public
    stub_getaddresses("example.com" => %w[93.184.216.34]) do
      assert Surfguard.resolvable_public_ip?("https://example.com/path")
    end
  end

  def test_resolvable_public_ip_false_when_any_address_is_blocked
    # A mixed answer must be refused by the non-pinning boolean: the unpinned
    # connect could pick the blocked one.
    stub_getaddresses("rebind.example" => %w[93.184.216.34 169.254.169.254]) do
      refute Surfguard.resolvable_public_ip?("https://rebind.example")
    end
  end

  def test_resolvable_public_ip_false_when_unresolvable
    stub_getaddresses({}) do
      refute Surfguard.resolvable_public_ip?("https://nope.example")
    end
  end

  def test_resolve_public_ips_filters_blocked_and_orders_ipv4_first
    stub_getaddresses("mix.example" => %w[2606:2800:220:1:248:1893:25c8:1946 93.184.216.34 169.254.169.254]) do
      assert_equal %w[93.184.216.34 2606:2800:220:1:248:1893:25c8:1946],
        Surfguard.resolve_public_ips("mix.example")
    end
  end

  def test_resolve_public_ip_returns_first_public_or_nil
    stub_getaddresses("example.com" => %w[93.184.216.34]) do
      assert_equal "93.184.216.34", Surfguard.resolve_public_ip("https://example.com")
    end
    stub_getaddresses("bad.example" => %w[93.184.216.34 10.0.0.1]) do
      assert_nil Surfguard.resolve_public_ip("https://bad.example")
    end
  end

  def test_ip_literal_hosts_skip_dns
    # No stub: an internal literal is caught without any resolver call.
    refute Surfguard.resolvable_public_ip?("http://169.254.169.254/latest/meta-data/")
    assert Surfguard.resolvable_public_ip?("http://93.184.216.34/")
  end

  def test_bracketed_ipv6_literal_host
    refute Surfguard.resolvable_public_ip?("http://[::1]/")
    refute Surfguard.resolvable_public_ip?("http://[fd00:ec2::254]/")
  end

  def test_enforce_raises_on_internal
    assert_raises(Surfguard::Violation) do
      Surfguard.enforce_public_ip("http://169.254.169.254/")
    end
  end

  def test_enforce_passes_on_public_literal
    Surfguard.enforce_public_ip("http://93.184.216.34/") # no raise
  end

  def test_malformed_url_is_refused
    refute Surfguard.resolvable_public_ip?("http://")
    assert_nil Surfguard.resolve_public_ip("::::not a url")
  end
end
