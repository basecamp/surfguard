# frozen_string_literal: true

require_relative "test_helper"
require "resolv"
if ENV["SURFGUARD_INSTALLED_SUITE"]
  require "surfguard"
else
  require_relative "../lib/surfguard"
end

class SurfguardHardeningTest < Minitest::Test
  REPORTED_PREFIXES = %w[100:0:0:1::/64 3fff::/20 5f00::/16].freeze
  RESERVED_LITERALS = %w[
    1::1 400::1 100:0:0:2::1 2000::1 3ffe::1 3fff:1000:: 4000::1 f000::1
  ].freeze

  def with_answers(answers)
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) { |_host| answers }
    yield
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def with_resolver_failure(error)
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) { |_host| raise error }
    yield
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def all_api_results(address, policy: :default)
    url = "https://target.example/path"
    with_answers([ address ]) do
      violation = begin
        Surfguard.enforce_public_ip(url, policy: policy)
        nil
      rescue StandardError => error
        error
      end
      {
        plural: Surfguard.resolve_public_ips("target.example", policy: policy),
        predicate: Surfguard.resolvable_public_ip?(url, policy: policy),
        enforce: violation,
        single: Surfguard.resolve_public_ip(url, policy: policy),
        classifier: Surfguard.blocked_address?(address, policy: policy)
      }
    end
  end

  def test_reported_prefix_endpoints_are_blocked_through_every_api_as_literals_and_dns
    REPORTED_PREFIXES.each do |cidr|
      range = IPAddr.new(cidr).to_range
      [ range.begin, range.end ].each do |address|
        assert Surfguard.blocked_address?(address), address.to_s
        assert_empty Surfguard.resolve_public_ips(address), address.to_s
        assert_nil Surfguard.resolve_public_ip("https://[#{address}]/"), address.to_s
        refute Surfguard.resolvable_public_ip?("https://[#{address}]/"), address.to_s
        error = assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip("https://[#{address}]/") }
        assert_equal Surfguard::BLOCKED_MESSAGE, error.message

        results = all_api_results(address.to_s)
        assert_empty results[:plural]
        refute results[:predicate]
        assert_instance_of Surfguard::Violation, results[:enforce]
        assert_nil results[:single]
        assert results[:classifier]
      end
    end
  end

  def test_unallocated_ipv6_examples_are_refused
    RESERVED_LITERALS.each do |address|
      assert Surfguard.blocked_address?(address), address
    end
  end

  def test_allocated_ipv6_boundaries_are_admitted_unless_explicitly_denied
    %w[2003::/18 2400::/12 2410::/12 2600::/12 2630::/12 2c00::/12].each do |cidr|
      range = IPAddr.new(cidr).to_range
      refute Surfguard.blocked_address?(range.begin), cidr
      refute Surfguard.blocked_address?(range.end), cidr
      before = IPAddr.new(range.begin.to_i - 1, Socket::AF_INET6)
      after = IPAddr.new(range.end.to_i + 1, Socket::AF_INET6)
      [ [ "before", before ], [ "after", after ] ].each do |label, address|
        allocated = Surfguard::IANA_ALLOCATED_IPV6_UNICAST.any? { |entry| entry.include?(address) }
        explicit_deny = Surfguard::DISALLOWED_IPV6.any? { |entry| entry.include?(address) } ||
          Surfguard::IETF_PROTOCOL_ASSIGNMENTS.include?(address)
        assert_equal !allocated || explicit_deny, Surfguard.blocked_address?(address), "#{label} #{cidr}"
      end
    end
  end

  def test_every_allocated_ipv6_prefix_has_before_first_last_after_regressions
    Surfguard::IANA_ALLOCATED_IPV6_UNICAST.each do |network|
      range = network.to_range
      points = [ range.begin.to_i - 1, range.begin.to_i, range.end.to_i, range.end.to_i + 1 ]
      points.each do |integer|
        address = IPAddr.new(integer, Socket::AF_INET6)
        assert_equal ipv6_default_oracle(address), Surfguard.blocked_address?(address),
          "#{network}/#{network.prefix} at #{address}"
      end
    end
  end

  def test_default_transition_and_global_service_exceptions
    %w[64:ff9b::5db8:d822 ::ffff:0:5db8:d822 2001:3::1 2001:4:112::1 192.31.196.1 192.52.193.1 192.175.48.1 2620:4f:8000::1].each do |address|
      refute Surfguard.blocked_address?(address), address
    end
  end

  def test_strict_policy_blocks_every_registered_special_use_prefix
    [ Surfguard::IANA_SPECIAL_USE_IPV4, Surfguard::IANA_SPECIAL_USE_IPV6 ].flatten.each do |network|
      assert Surfguard.blocked_address?(network.to_range.begin, policy: :iana_special_use), network.to_s
      assert Surfguard.blocked_address?(network.to_range.end, policy: :iana_special_use), network.to_s
    end
  end

  def test_strict_policy_blocks_every_registered_endpoint_through_all_apis
    networks = [ Surfguard::IANA_SPECIAL_USE_IPV4, Surfguard::IANA_SPECIAL_USE_IPV6 ].flatten
    endpoints = networks.flat_map { |network| [ network.to_range.begin, network.to_range.end ] }
      .uniq { |address| [ address.family, address.to_i ] }

    endpoints.each do |address|
      results = all_api_results(address.to_s, policy: :iana_special_use)
      assert_empty results[:plural], address.to_s
      refute results[:predicate], address.to_s
      assert_instance_of Surfguard::Violation, results[:enforce], address.to_s
      assert_equal Surfguard::BLOCKED_MESSAGE, results[:enforce].message, address.to_s
      assert_nil results[:single], address.to_s
      assert results[:classifier], address.to_s
    end
  end

  def test_strict_and_default_service_boundaries_are_exact
    %w[192.31.196.0/24 192.52.193.0/24 192.175.48.0/24].each do |cidr|
      range = IPAddr.new(cidr).to_range
      [ range.begin, range.end ].each do |address|
        refute Surfguard.blocked_address?(address), address.to_s
        assert Surfguard.blocked_address?(address, policy: :iana_special_use), address.to_s
      end

      [ range.begin.to_i - 1, range.end.to_i + 1 ].each do |integer|
        address = IPAddr.new(integer, Socket::AF_INET)
        refute Surfguard.blocked_address?(address), address.to_s
        refute Surfguard.blocked_address?(address, policy: :iana_special_use), address.to_s
      end
    end
  end

  def test_every_explicit_default_deny_has_before_first_last_after_regressions
    [ Surfguard::DISALLOWED_IPV4, Surfguard::DISALLOWED_IPV6 ].each do |ranges|
      ranges.each do |network|
        range = network.to_range
        family = network.ipv4? ? Socket::AF_INET : Socket::AF_INET6
        maximum = network.ipv4? ? (1 << 32) - 1 : (1 << 128) - 1
        [ range.begin.to_i - 1, range.begin.to_i, range.end.to_i, range.end.to_i + 1 ].each do |integer|
          next unless (0..maximum).cover?(integer)

          address = IPAddr.new(integer, family)
          oracle = address.ipv4? ? ipv4_default_oracle(address) : ipv6_default_oracle(address)
          assert_equal oracle, Surfguard.blocked_address?(address), "#{network}/#{network.prefix} at #{address}"
        end
      end
    end
  end

  def test_strict_policy_blocks_nat64_and_service_exceptions_but_not_ordinary_public_addresses
    %w[64:ff9b::5db8:d822 2001:3::1 2001:4:112::1 192.31.196.1 192.52.193.1 192.175.48.1 2620:4f:8000::1].each do |address|
      assert Surfguard.blocked_address?(address, policy: :iana_special_use), address
    end
    refute Surfguard.blocked_address?("93.184.216.34", policy: :iana_special_use)
    refute Surfguard.blocked_address?("2606:2800:220:1:248:1893:25c8:1946", policy: :iana_special_use)
  end

  def test_unknown_policy_raises_argument_error_from_every_api
    calls = [
      -> { Surfguard.resolve_public_ips("example.com", policy: :unknown) },
      -> { Surfguard.resolvable_public_ip?("https://example.com", policy: :unknown) },
      -> { Surfguard.enforce_public_ip("https://example.com", policy: :unknown) },
      -> { Surfguard.resolve_public_ip("https://example.com", policy: :unknown) },
      -> { Surfguard.blocked_address?("93.184.216.34", policy: :unknown) }
    ]
    calls.each do |call|
      error = assert_raises(ArgumentError, &call)
      assert_equal "unknown policy", error.message
    end
  end

  def test_malformed_direct_input_contract_and_fixed_messages
    malformed = Object.new
    assert_empty Surfguard.resolve_public_ips(malformed)
    refute Surfguard.resolvable_public_ip?(malformed)
    error = assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip(malformed) }
    assert_equal Surfguard::MALFORMED_MESSAGE, error.message
    assert_nil Surfguard.resolve_public_ip(malformed)
    assert Surfguard.blocked_address?(malformed)
  end

  def test_wrong_types_are_not_coerced_and_ipaddr_overrides_are_bypassed
    unstable = Object.new
    unstable.define_singleton_method(:to_s) { raise "must not coerce" }
    assert_empty Surfguard.resolve_public_ips(unstable)
    assert Surfguard.blocked_address?(unstable)

    address = IPAddr.new("93.184.216.34")
    address.define_singleton_method(:to_i) { raise "must use owned IPAddr implementation" }
    refute Surfguard.blocked_address?(address)
    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips(address)
  end

  def test_input_type_checks_do_not_dispatch_to_input_overrides
    wrong_type = Object.new
    wrong_type.define_singleton_method(:is_a?) { |_type| raise "must not dispatch is_a?" }
    assert_empty Surfguard.resolve_public_ips(wrong_type)
    refute Surfguard.resolvable_public_ip?(wrong_type)
    malformed = assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip(wrong_type) }
    assert_equal Surfguard::MALFORMED_MESSAGE, malformed.message
    assert_nil Surfguard.resolve_public_ip(wrong_type)
    assert Surfguard.blocked_address?(wrong_type)

    string_class = Class.new(String) do
      def is_a?(_type)
        raise "must copy without dispatching is_a?"
      end
    end
    host = string_class.new("93.184.216.34")
    url = string_class.new("https://93.184.216.34/")
    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips(host)
    assert Surfguard.resolvable_public_ip?(url)
    assert_nil Surfguard.enforce_public_ip(url)
    assert_equal "93.184.216.34", Surfguard.resolve_public_ip(url)
    refute Surfguard.blocked_address?(host)

    ipaddr_class = Class.new(IPAddr) do
      def is_a?(_type)
        raise "must copy IPAddr without dispatching is_a?"
      end
    end
    address = ipaddr_class.new("93.184.216.34")
    refute Surfguard.blocked_address?(address)
    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips(address)
  end

  def test_invalid_encoding_nul_non_ascii_and_long_hosts_are_malformed
    bad_encoding = "example.com".dup.force_encoding(Encoding::UTF_16LE)
    [ bad_encoding, "example\0.com", "caf\u00e9.example", "a" * 256 ].each do |host|
      assert_empty Surfguard.resolve_public_ips(host)
    end
  end

  def test_zones_ipvfuture_empty_hosts_and_platform_embedding_corpus_fail_closed
    malformed_urls = [ "https://", "https://[fe80::1%25lo]/", "https://[v1.fe]/" ]
    malformed_urls.each do |url|
      refute Surfguard.resolvable_public_ip?(url), url
      assert_nil Surfguard.resolve_public_ip(url), url
    end
    %w[
      100.100.100.200
      64:ff9b::6464:64c8
      ::ffff:0:6464:64c8
      64:ff9b::a83f:8110
      ::ffff:0:a83f:8110
    ].each do |address|
      assert Surfguard.blocked_address?(address), address
    end
  end

  def test_ipv6_zones_are_malformed_through_direct_and_url_apis
    zoned_text = "2606:4700:4700::1111%lo"
    zoned_ip = IPAddr.new(zoned_text)
    url = "https://[#{zoned_text}]/"

    [ zoned_text, zoned_ip ].each do |input|
      assert_empty Surfguard.resolve_public_ips(input)
      assert Surfguard.blocked_address?(input)
      assert Surfguard.blocked_address?(input, policy: :iana_special_use)
    end
    refute Surfguard.resolvable_public_ip?(url)
    assert_nil Surfguard.resolve_public_ip(url)
    error = assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip(url) }
    assert_equal Surfguard::MALFORMED_MESSAGE, error.message
  end

  def test_zoned_resolver_answer_invalidates_the_entire_lookup
    zoned_answers = [
      [ "93.184.216.34", "2606:4700:4700::1111%lo" ],
      [ "93.184.216.34", IPAddr.new("2606:4700:4700::1111%lo") ]
    ]

    zoned_answers.each do |answers|
      with_answers(answers) { assert_unresolvable_api_contract }
    end
  end

  def test_malformed_resolver_answer_invalidates_the_entire_lookup
    [ nil, [ "93.184.216.34", "bad" ], [ "93.184.216.34", "10.0.0.1/8" ], [ Object.new ] ].each do |answers|
      with_answers(answers) do
        error = assert_raises(Surfguard::Unresolvable) { Surfguard.resolve_public_ips("example.com") }
        assert_equal Surfguard::UNRESOLVABLE_MESSAGE, error.message
        refute Surfguard.resolvable_public_ip?("https://example.com")
        assert_raises(Surfguard::Unresolvable) { Surfguard.enforce_public_ip("https://example.com") }
        assert_raises(Surfguard::Unresolvable) { Surfguard.resolve_public_ip("https://example.com") }
      end
    end
  end

  def test_resolver_result_validation_uses_owned_builtin_values
    string_class = Class.new(String) do
      def is_a?(_type)
        raise "must not dispatch resolver-answer is_a?"
      end
    end
    array_class = Class.new(Array) do
      def each(*)
        raise "must use the owned Array implementation"
      end
    end
    answers = array_class.new([ string_class.new("93.184.216.34") ])
    with_answers(answers) do
      assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("example.com")
      assert Surfguard.resolvable_public_ip?("https://example.com")
      assert_nil Surfguard.enforce_public_ip("https://example.com")
      assert_equal "93.184.216.34", Surfguard.resolve_public_ip("https://example.com")
    end

    malformed = Object.new
    malformed.define_singleton_method(:is_a?) { |_type| raise "must not inspect malformed answer" }
    with_answers([ malformed ]) { assert_unresolvable_api_contract }
  end

  def test_numeric_parser_result_validation_bypasses_array_overrides
    answer_class = Class.new(Array) do
      def is_a?(_type)
        raise "must not dispatch numeric-answer is_a?"
      end

      def [](*)
        raise "must use the owned Array implementation"
      end
    end
    result_class = Class.new(Array) do
      def map(*)
        raise "must use the owned Array implementation"
      end
    end
    original = Socket.method(:getaddrinfo)
    Socket.define_singleton_method(:getaddrinfo) do |*|
      result_class.new([ answer_class.new([ "AF_INET", 0, nil, "93.184.216.34" ]) ])
    end

    assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("93.184.216.34")
  ensure
    Socket.define_singleton_method(:getaddrinfo, original) if original
  end

  def test_mixed_answers_follow_the_required_contract
    with_answers(%w[2606:2800:220:1:248:1893:25c8:1946 10.0.0.1 93.184.216.34]) do
      assert_equal %w[93.184.216.34 2606:2800:220:1:248:1893:25c8:1946],
        Surfguard.resolve_public_ips("example.com")
      refute Surfguard.resolvable_public_ip?("https://example.com")
      error = assert_raises(Surfguard::Violation) { Surfguard.enforce_public_ip("https://example.com") }
      assert_equal Surfguard::BLOCKED_MESSAGE, error.message
      assert_nil Surfguard.resolve_public_ip("https://example.com")
    end
  end

  def test_single_preserves_resolver_order_and_plural_is_ipv4_first
    answers = %w[2606:2800:220:1:248:1893:25c8:1946 93.184.216.34]
    with_answers(answers) do
      assert_equal answers.first, Surfguard.resolve_public_ip("https://example.com")
      assert_equal answers.reverse, Surfguard.resolve_public_ips("example.com")
    end
  end

  def test_answers_are_deduplicated_in_order_and_cardinality_is_bounded
    with_answers([ "93.184.216.34" ] * 256) do
      assert_equal [ "93.184.216.34" ], Surfguard.resolve_public_ips("example.com")
      assert Surfguard.resolvable_public_ip?("https://example.com")
      assert_nil Surfguard.enforce_public_ip("https://example.com")
      assert_equal "93.184.216.34", Surfguard.resolve_public_ip("https://example.com")
    end
    with_answers([ "93.184.216.34" ] * 257) { assert_unresolvable_api_contract }
  end

  def test_unique_answer_cardinality_accepts_256_and_refuses_257
    addresses = 257.times.map do |index|
      IPAddr.new(IPAddr.new("11.0.0.0").to_i + index, Socket::AF_INET).to_s
    end

    with_answers(addresses.first(256)) do
      assert_equal addresses.first(256), Surfguard.resolve_public_ips("example.com")
      assert Surfguard.resolvable_public_ip?("https://example.com")
      assert_nil Surfguard.enforce_public_ip("https://example.com")
      assert_equal addresses.first, Surfguard.resolve_public_ip("https://example.com")
    end
    with_answers(addresses) { assert_unresolvable_api_contract }
  end

  def test_operational_resolver_failures_use_the_fixed_failure_contract
    errors = [
      SocketError.new("attacker-controlled resolver detail"),
      Errno::ECONNREFUSED.new,
      IOError.new("attacker-controlled resolver detail"),
      EOFError.new("attacker-controlled resolver detail")
    ]

    errors.each do |error|
      with_resolver_failure(error) do
        assert_unresolvable_api_contract(forbidden_detail: "attacker-controlled resolver detail")
      end
    end
  end

  def test_expected_public_errors_never_chain_attacker_or_ambient_exceptions
    malformed_detail = "attacker-controlled-uri-detail"
    malformed = assert_raises(Surfguard::Violation) do
      Surfguard.enforce_public_ip("https://example.invalid/ #{malformed_detail}")
    end
    assert_sanitized_exception(malformed, Surfguard::MALFORMED_MESSAGE, malformed_detail)

    ambient_detail = "attacker-controlled-ambient-detail"
    blocked = capture_during_rescue(ambient_detail) do
      Surfguard.enforce_public_ip("https://127.0.0.1/")
    end
    assert_instance_of Surfguard::Violation, blocked
    assert_sanitized_exception(blocked, Surfguard::BLOCKED_MESSAGE, ambient_detail)

    public_calls = [
      -> { Surfguard.resolve_public_ips("target.example", policy: :unknown) },
      -> { Surfguard.resolvable_public_ip?("https://target.example", policy: :unknown) },
      -> { Surfguard.enforce_public_ip("https://target.example", policy: :unknown) },
      -> { Surfguard.resolve_public_ip("https://target.example", policy: :unknown) },
      -> { Surfguard.blocked_address?("93.184.216.34", policy: :unknown) }
    ]
    public_calls.each do |call|
      error = capture_during_rescue(ambient_detail, &call)
      assert_instance_of ArgumentError, error
      assert_sanitized_exception(error, "unknown policy", ambient_detail)
    end
  end

  def test_malformed_ipaddr_instances_fail_closed_as_inputs_and_answers
    malformed = [ IPAddr.allocate ]

    bad_family = IPAddr.new("93.184.216.34")
    bad_family.instance_variable_set(:@family, -1)
    malformed << bad_family

    bad_address = IPAddr.new("93.184.216.34")
    bad_address.instance_variable_set(:@addr, Object.new)
    malformed << bad_address

    bad_mask = IPAddr.new("93.184.216.34")
    bad_mask.instance_variable_set(:@mask_addr, Object.new)
    malformed << bad_mask

    bad_zone = IPAddr.new("93.184.216.34")
    bad_zone.instance_variable_set(:@zone_id, "%lo")
    malformed << bad_zone

    hostile_family = Object.new
    hostile_family.define_singleton_method(:==) { |_other| raise "must not compare hostile family" }
    bad_family = IPAddr.new("93.184.216.34")
    bad_family.instance_variable_set(:@family, hostile_family)
    malformed << bad_family

    spoofed_family = Object.new
    spoofed_family.define_singleton_method(:==) { |other| other == Socket::AF_INET }
    bad_family = IPAddr.new("93.184.216.34")
    bad_family.instance_variable_set(:@family, spoofed_family)
    malformed << bad_family

    hostile_address = Object.new
    hostile_address.define_singleton_method(:instance_of?) { |_type| raise "must not inspect hostile address" }
    bad_address = IPAddr.new("93.184.216.34")
    bad_address.instance_variable_set(:@addr, hostile_address)
    malformed << bad_address

    hostile_mask = Object.new
    hostile_mask.define_singleton_method(:instance_of?) { |_type| raise "must not inspect hostile mask" }
    bad_mask = IPAddr.new("93.184.216.34")
    bad_mask.instance_variable_set(:@mask_addr, hostile_mask)
    malformed << bad_mask

    spoofed_zone = Object.new
    spoofed_zone.define_singleton_method(:nil?) { true }
    bad_zone = IPAddr.new("93.184.216.34")
    bad_zone.instance_variable_set(:@zone_id, spoofed_zone)
    malformed << bad_zone

    hostile_zone = Object.new
    hostile_zone.define_singleton_method(:nil?) { raise "must not inspect hostile zone" }
    bad_zone = IPAddr.new("93.184.216.34")
    bad_zone.instance_variable_set(:@zone_id, hostile_zone)
    malformed << bad_zone

    malformed.each do |address|
      assert Surfguard.blocked_address?(address)
      assert_empty Surfguard.resolve_public_ips(address)
      with_answers([ address ]) { assert_unresolvable_api_contract }
    end
  end

  def test_unexpected_resolver_failures_escape
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) { |_host| raise RuntimeError, "programmer bug" }
    assert_raises(RuntimeError) { Surfguard.resolve_public_ips("example.com") }
    assert_raises(RuntimeError) { Surfguard.resolvable_public_ip?("https://example.com") }
    assert_raises(RuntimeError) { Surfguard.enforce_public_ip("https://example.com") }
    assert_raises(RuntimeError) { Surfguard.resolve_public_ip("https://example.com") }
  ensure
    Resolv.define_singleton_method(:getaddresses, original)
  end

  def test_returned_values_and_policy_graph_are_deeply_frozen
    with_answers(%w[93.184.216.34]) do
      result = Surfguard.resolve_public_ips("example.com")
      assert_predicate result, :frozen?
      assert_predicate result.first, :frozen?
    end
    assert_predicate Surfguard::POLICY_RANGES, :frozen?
    Surfguard::POLICY_RANGES.each_value do |policy|
      assert_predicate policy, :frozen?
      policy.each_value do |ranges|
        assert_predicate ranges, :frozen?
        ranges.each { |range| assert_predicate range, :frozen? }
        assert_raises(FrozenError) { ranges.first.prefix = 0 } unless ranges.empty?
      end
    end
  end

  def test_deterministic_standard_library_parser_property_corpus
    random = Random.new(0x5_55_52_46)
    20_000.times do |index|
      family = index.even? ? Socket::AF_INET : Socket::AF_INET6
      bits = family == Socket::AF_INET ? 32 : 128
      address = IPAddr.new(random.rand(1 << bits), family)
      expected_default = default_policy_oracle(address)
      expected_strict = expected_default || iana_special_use_oracle(address)
      assert_equal expected_default, Surfguard.blocked_address?(address), address.to_s
      assert_equal expected_default, Surfguard.blocked_address?(address.to_s), address.to_s
      assert_equal expected_strict,
        Surfguard.blocked_address?(address, policy: :iana_special_use), address.to_s
      assert_equal expected_strict,
        Surfguard.blocked_address?(address.to_s, policy: :iana_special_use), address.to_s
    end
  end

  def test_numeric_host_parser_and_classification_agree_on_deterministic_spellings
    cases = {
      "127.0.0.1" => true,
      "169.254.169.254" => true,
      "10.23.45.67" => true,
      "168.63.129.16" => true,
      "93.184.216.34" => false
    }
    dns_queries = []
    original = Resolv.method(:getaddresses)
    Resolv.define_singleton_method(:getaddresses) do |host|
      dns_queries << host
      [ "203.0.113.1" ]
    end

    assert_spellings = lambda do |canonical, blocked|
      ip = IPAddr.new(canonical)
      assert_equal blocked, ipv4_default_oracle(ip), canonical
      octets = canonical.split(".").map(&:to_i)
      spellings = [
        canonical,
        ip.to_i.to_s,
        "0x#{ip.to_i.to_s(16)}",
        octets.map { |octet| octet.zero? ? "0" : "0#{octet.to_s(8)}" }.join("."),
        "#{octets.first}.#{ip.to_i & 0x00ff_ffff}"
      ]

      spellings.each do |spelling|
        system_addresses = begin
          Socket.getaddrinfo(
            spelling, nil, Socket::AF_UNSPEC, Socket::SOCK_STREAM, 0, Socket::AI_NUMERICHOST
          ).map { |entry| IPAddr.new(entry[3]) }
        rescue SocketError
          []
        end
        actual = Surfguard.resolve_public_ips(spelling)
        if system_addresses.empty?
          assert_empty actual, spelling
        else
          expected = system_addresses.reject { |address| ipv4_default_oracle(address) }
            .uniq { |address| [ address.family, address.to_i ] }
            .map(&:to_s)
          assert_equal expected, actual, spelling
        end
      end
    end
    cases.each { |canonical, blocked| assert_spellings.call(canonical, blocked) }

    random = Random.new(0x4e_55_4d_45_52_49_43)
    1_000.times do
      address = IPAddr.new(random.rand(1 << 32), Socket::AF_INET)
      assert_spellings.call(address.to_s, ipv4_default_oracle(address))
    end
    assert_empty dns_queries
  ensure
    Resolv.define_singleton_method(:getaddresses, original) if original
  end

  private
    def assert_unresolvable_api_contract(forbidden_detail: nil)
      plural = assert_raises(Surfguard::Unresolvable) do
        Surfguard.resolve_public_ips("target.example")
      end
      assert_sanitized_exception(plural, Surfguard::UNRESOLVABLE_MESSAGE, forbidden_detail)
      refute Surfguard.resolvable_public_ip?("https://target.example")

      enforce = assert_raises(Surfguard::Unresolvable) do
        Surfguard.enforce_public_ip("https://target.example")
      end
      assert_sanitized_exception(enforce, Surfguard::UNRESOLVABLE_MESSAGE, forbidden_detail)

      single = assert_raises(Surfguard::Unresolvable) do
        Surfguard.resolve_public_ip("https://target.example")
      end
      assert_sanitized_exception(single, Surfguard::UNRESOLVABLE_MESSAGE, forbidden_detail)
    end

    def assert_sanitized_exception(error, message, forbidden_detail)
      assert_equal message, error.message
      assert_nil error.cause
      refute_includes error.full_message, forbidden_detail if forbidden_detail
    end

    def capture_during_rescue(detail)
      raise RuntimeError, detail
    rescue RuntimeError
      begin
        yield
      rescue StandardError => error
        error
      end
    end

    def ipv6_default_oracle(address)
      carveout = Surfguard::GLOBALLY_REACHABLE_IETF_ASSIGNMENTS.any? { |range| range.include?(address) }
      return false if carveout
      return true if address.private? || address.loopback? || address.link_local?
      return true if Surfguard::IETF_PROTOCOL_ASSIGNMENTS.include?(address)
      return true if Surfguard::DISALLOWED_IPV6.any? { |range| range.include?(address) }

      Surfguard::IANA_ALLOCATED_IPV6_UNICAST.none? { |range| range.include?(address) }
    end

    def ipv4_default_oracle(address)
      address.private? || address.loopback? || address.link_local? ||
        Surfguard::DISALLOWED_IPV4.any? { |range| range.include?(address) }
    end

    def default_policy_oracle(address)
      return true if address.ipv4_mapped? || Surfguard::IPV4_COMPATIBLE.include?(address)
      return ipv4_default_oracle(address) if address.ipv4?
      return true if Surfguard::NAT64_LOCAL_USE.include?(address)

      if Surfguard::NAT64_WELL_KNOWN.include?(address) || Surfguard::IPV4_TRANSLATABLE.include?(address)
        embedded = IPAddr.new(address.to_i & 0xffff_ffff, Socket::AF_INET)
        return ipv4_default_oracle(embedded)
      end

      ipv6_default_oracle(address)
    end

    def iana_special_use_oracle(address)
      ranges = address.ipv4? ? Surfguard::IANA_SPECIAL_USE_IPV4 : Surfguard::IANA_SPECIAL_USE_IPV6
      ranges.any? { |range| range.include?(address) }
    end
end
