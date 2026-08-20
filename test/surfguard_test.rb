# frozen_string_literal: true

require_relative "test_helper"
require_relative "support/conformance"
require "resolv"
if ENV["SURFGUARD_INSTALLED_SUITE"]
  require "surfguard"
else
  require_relative "../lib/surfguard"
end

class SurfguardTest < Minitest::Test
  # --- classification: the full policy matrix, checked as execution -----------
  # The matrices live in the language-neutral corpus under conformance/; the
  # tests here only bind them to the Ruby implementation.

  BLOCKED = Conformance.cases("blocked")
    .to_h { |entry| [ entry.fetch("label"), entry.fetch("input") ] }.freeze

  ALLOWED = Conformance.cases("allowed")
    .to_h { |entry| [ entry.fetch("label"), entry.fetch("input") ] }.freeze

  LEGACY_NUMERIC_BLOCKED = Conformance.cases("legacy_numeric")
    .select { |entry| entry.fetch("blocked") }
    .to_h { |entry| [ entry.fetch("label"), entry.fetch("input") ] }.freeze

  MALFORMED_NUMERIC_HOSTS = Conformance.cases("malformed_numeric_hosts")
    .map { |entry| entry.fetch("input") }.freeze

  NON_HOST_PREFIXES = Conformance.cases("non_host_prefixes")
    .map { |entry| entry.fetch("input") }.freeze

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

  def test_conformance_corpus_verdicts_hold_under_both_policies
    %w[boundaries blocked allowed].each do |file|
      Conformance.cases(file).each do |entry|
        label, input = entry.fetch_values("label", "input")
        entry.fetch("policies").each do |policy, verdict|
          assert_equal verdict == "blocked",
            Surfguard.blocked_address?(input, policy: policy.to_sym),
            "#{file}: expected #{label} (#{input}) to be #{verdict} under the #{policy} policy"
        end
      end
    end
  end

  def test_the_two_nat64_prefixes_do_not_overlap
    refute Surfguard::NAT64_WELL_KNOWN.include?(IPAddr.new("64:ff9b:1::1"))
    refute Surfguard::NAT64_LOCAL_USE.include?(IPAddr.new("64:ff9b::1"))
  end

  def test_expanded_documentation_prefix_boundaries
    assert Surfguard.blocked_address?("3fff::")
    assert Surfguard.blocked_address?("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff")
    assert Surfguard.blocked_address?("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    assert Surfguard.blocked_address?("3fff:1000::")
  end

  def test_azure_wire_server_deny_is_one_exact_address
    refute Surfguard.blocked_address?("168.63.129.15")
    assert Surfguard.blocked_address?("168.63.129.16")
    refute Surfguard.blocked_address?("168.63.129.17")
  end

  def test_globally_reachable_ietf_assignment_carve_outs_are_narrow
    assert Surfguard.blocked_address?("2001:1::4")
    assert Surfguard.blocked_address?("2001:2:ffff:ffff:ffff:ffff:ffff:ffff")
    refute Surfguard.blocked_address?("2001:3:ffff:ffff:ffff:ffff:ffff:ffff")
    assert Surfguard.blocked_address?("2001:4:111:ffff:ffff:ffff:ffff:ffff")
    refute Surfguard.blocked_address?("2001:4:112:ffff:ffff:ffff:ffff:ffff")
    assert Surfguard.blocked_address?("2001:4:113::")
  end

  def test_siit_and_mapped_prefixes_do_not_overlap
    refute Surfguard::IPV4_TRANSLATABLE.include?(IPAddr.new("::ffff:169.254.169.254"))
  end

  def test_ipv4_compatible_classification_does_not_depend_on_obsolete_ipaddr_api
    ipaddr_without_compat = Class.new(IPAddr) do
      # Guarded: undef_method raises NameError when nothing is inherited, so an
      # unguarded call would fail this test on the very ipaddr version whose
      # removal of ipv4_compat? it exists to cover.
      undef_method :ipv4_compat? if method_defined?(:ipv4_compat?)
    end

    assert Surfguard.blocked_address?(ipaddr_without_compat.new("::93.184.216.34"))
    assert Surfguard.blocked_address?(ipaddr_without_compat.new("::ffff:93.184.216.34"))
    refute Surfguard.blocked_address?(ipaddr_without_compat.new("::ffff:0:5db8:d822"))
  end

  def test_blocks_an_unparseable_address
    assert Surfguard.blocked_address?("not-an-ip")
  end

  NON_HOST_PREFIXES.each do |address|
    define_method("test_blocks_non_host_prefix_#{address.gsub(/\W+/, '_')}") do
      assert Surfguard.blocked_address?(address)
      assert Surfguard.blocked_address?(IPAddr.new(address))
    end
  end

  def test_allows_full_width_host_prefixes
    refute Surfguard.blocked_address?("93.184.216.34/32")
    refute Surfguard.blocked_address?("2606:2800:220:1:248:1893:25c8:1946/128")
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

  def test_azure_wire_server_literal_is_refused_by_every_resolution_api
    url = "http://168.63.129.16/machine/?comp=goalstate"

    assert_empty Surfguard.resolve_public_ips("168.63.129.16")
    assert_nil Surfguard.resolve_public_ip(url)
    refute Surfguard.resolvable_public_ip?(url)
    assert_raises(Surfguard::Violation) do
      Surfguard.enforce_public_ip(url)
    end
  end

  def test_azure_wire_server_in_a_dns_answer_is_filtered_and_refused_unpinned
    stub_getaddresses("azure.example" => %w[93.184.216.34 168.63.129.16]) do
      assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("azure.example")
      assert_nil Surfguard.resolve_public_ip("https://azure.example")
      refute Surfguard.resolvable_public_ip?("https://azure.example")
      assert_raises(Surfguard::Violation) do
        Surfguard.enforce_public_ip("https://azure.example")
      end
    end
  end

  LEGACY_NUMERIC_BLOCKED.each do |label, host|
    define_method("test_legacy_numeric_#{label.gsub(/\W+/, '_')}_skips_dns_and_is_refused") do
      original = Resolv.method(:getaddresses)
      dns_queries = []
      Resolv.define_singleton_method(:getaddresses) do |resolved_host|
        dns_queries << resolved_host
        [ "93.184.216.34" ] # Model a public wildcard/search-domain answer.
      end

      assert_empty Surfguard.resolve_public_ips(host)
      refute Surfguard.resolvable_public_ip?("http://#{host}/")
      assert_raises(Surfguard::Violation) do
        Surfguard.enforce_public_ip("http://#{host}/")
      end
      assert_empty dns_queries
    ensure
      Resolv.define_singleton_method(:getaddresses, original)
    end
  end

  def test_legacy_numeric_public_address_is_classified_and_skips_dns
    entry = Conformance.cases("legacy_numeric").find { |candidate| !candidate.fetch("blocked") }
    original = Resolv.method(:getaddresses)
    dns_queries = []
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "169.254.169.254" ]
    end

    assert_equal [ entry.fetch("canonical") ], Surfguard.resolve_public_ips(entry.fetch("input"))
    assert Surfguard.resolvable_public_ip?("http://#{entry.fetch("input")}/")
    assert_empty dns_queries
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def test_numeric_parser_fault_cannot_send_numeric_looking_tokens_to_dns
    original_getaddrinfo = Socket.method(:getaddrinfo)
    original_getaddresses = Resolv.method(:getaddresses)
    dns_queries = []
    Socket.define_singleton_method(:getaddrinfo) { |*| raise SocketError, "simulated parser fault" }
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "93.184.216.34" ]
    end

    LEGACY_NUMERIC_BLOCKED.each_value do |host|
      assert_empty Surfguard.resolve_public_ips(host)
    end
    assert_empty Surfguard.resolve_public_ips("not:a:valid:ipv6")
    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("example.com")
    assert_equal [ "example.com" ], dns_queries
  ensure
    Socket.define_singleton_method(:getaddrinfo, original_getaddrinfo)
    Resolv.define_singleton_method(:getaddresses, original_getaddresses)
  end

  def test_malformed_numeric_hosts_are_refused_without_dns
    original = Resolv.method(:getaddresses)
    dns_queries = []
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "93.184.216.34" ] # Model a public wildcard/search-domain answer.
    end

    MALFORMED_NUMERIC_HOSTS.each do |host|
      assert_empty Surfguard.resolve_public_ips(host), host
    end
    assert_empty dns_queries
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def test_malformed_numeric_hosts_are_refused_before_a_loose_platform_parser
    original_getaddrinfo = Socket.method(:getaddrinfo)
    original_getaddresses = Resolv.method(:getaddresses)
    numeric_queries = []
    dns_queries = []
    Socket.define_singleton_method(:getaddrinfo) do |host, *|
      numeric_queries << host
      [ [ "AF_INET", nil, nil, "93.184.216.34" ] ]
    end
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "93.184.216.34" ]
    end

    url = "http://93.184.216.34./"
    assert_empty Surfguard.resolve_public_ips("93.184.216.34.")
    assert_nil Surfguard.resolve_public_ip(url)
    refute Surfguard.resolvable_public_ip?(url)
    assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip(url) }
    assert_empty numeric_queries
    assert_empty dns_queries
  ensure
    Socket.define_singleton_method(:getaddrinfo, original_getaddrinfo)
    Resolv.define_singleton_method(:getaddresses, original_getaddresses)
  end

  def test_numeric_label_hostnames_still_reach_dns
    names = Conformance.cases("dns_hostnames").map { |entry| entry.fetch("input") }

    stub_getaddresses(names.to_h { |name| [ name, [ "93.184.216.34" ] ] }) do
      names.each do |name|
        assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips(name), name
      end
    end
  end

  def test_non_host_prefixes_are_rejected_without_dns
    original = Resolv.method(:getaddresses)
    dns_queries = []
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "93.184.216.34" ]
    end

    NON_HOST_PREFIXES.each do |host|
      assert_empty Surfguard.resolve_public_ips(host)
    end
    assert_empty dns_queries
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def test_full_width_host_prefixes_remain_valid_literals
    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("93.184.216.34/32")
    assert_equal [ "2606:2800:220:1:248:1893:25c8:1946" ],
      Surfguard.resolve_public_ips("2606:2800:220:1:248:1893:25c8:1946/128")
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

  # --- unresolvable is not a refusal ------------------------------------------

  def test_unresolvable_is_not_a_violation
    # The distinction is the point: a caller that stops retrying on Violation
    # must not stop on a lookup that merely came back empty.
    refute_includes Surfguard::Unresolvable.ancestors, Surfguard::Violation
  end

  def test_resolve_public_ip_raises_unresolvable_when_nothing_resolves
    stub_getaddresses({}) do
      assert_raises(Surfguard::Unresolvable) do
        Surfguard.resolve_public_ip("https://nope.example")
      end
    end
  end

  def test_resolve_public_ip_returns_nil_when_resolved_but_blocked
    # Blocked is nil, not Unresolvable — the host answered, we refused it.
    stub_getaddresses("bad.example" => %w[169.254.169.254]) do
      assert_nil Surfguard.resolve_public_ip("https://bad.example")
    end
  end

  def test_resolve_public_ips_raises_unresolvable_when_nothing_resolves
    stub_getaddresses({}) do
      assert_raises(Surfguard::Unresolvable) do
        Surfguard.resolve_public_ips("nope.example")
      end
    end
  end

  def test_resolve_public_ips_returns_empty_when_resolved_but_all_blocked
    stub_getaddresses("bad.example" => %w[10.0.0.1 169.254.169.254]) do
      assert_empty Surfguard.resolve_public_ips("bad.example")
    end
  end

  def test_enforce_raises_unresolvable_rather_than_violation
    stub_getaddresses({}) do
      assert_raises(Surfguard::Unresolvable) do
        Surfguard.enforce_public_ip("https://nope.example")
      end
    end
  end

  def test_enforce_raises_violation_on_malformed_url
    assert_raises(Surfguard::Violation) do
      Surfguard.enforce_public_ip("http://")
    end
  end

  def test_resolver_errors_resolve_to_nothing
    # Resolv.getaddresses runs in the method body, not inside another rescue
    # clause, so the ResolvError rescue actually covers it.
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) { |_host| raise Resolv::ResolvError }
    assert_raises(Surfguard::Unresolvable) do
      Surfguard.resolve_public_ips("boom.example")
    end
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end
end
