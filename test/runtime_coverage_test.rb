# frozen_string_literal: true

require_relative "test_helper"
require_relative "../lib/surfguard"
require_relative "../script/check_resolv_version"

require "stringio"

class RuntimeCoverageTest < Minitest::Test
  def test_network_ipaddr_is_not_accepted_as_a_host_endpoint
    assert_empty Surfguard.resolve_public_ips(IPAddr.new("192.0.2.0/24"))
  end

  def test_corrupt_ipaddr_internals_fail_closed
    corruptions = [
      [ :@mask_addr, "not an integer" ],
      [ :@mask_addr, 1 << 100 ],
      [ :@addr, -1 ],
      [ :@mask_addr, 5 ]
    ]

    corruptions.each do |variable, value|
      address = IPAddr.new("8.8.8.8")
      Object.instance_method(:instance_variable_set).bind_call(address, variable, value)
      assert Surfguard.blocked_address?(address), "#{variable}=#{value.inspect} must fail closed"
    end
  end

  def test_owned_string_rejects_non_strings_even_when_called_directly
    invalid_input = Surfguard.const_get(:InvalidInput, false)

    assert_raises(invalid_input) { Surfguard.send(:owned_string, Object.new) }
  end

  def test_numeric_resolver_adapter_rejects_malformed_container_shapes
    malformed = [
      Object.new,
      [ Object.new ],
      [ [ nil, nil, nil, Object.new ] ]
    ]

    malformed.each do |answer|
      with_singleton_method(Socket, :getaddrinfo, ->(*) { answer }) do
        error = assert_raises(Surfguard::Unresolvable) do
          Surfguard.resolve_public_ips("example.com")
        end
        assert_equal "Host could not be resolved", error.message
      end
    end
  end

  def test_host_syntax_rejects_an_absolute_empty_label_set
    refute Surfguard.send(:valid_host_syntax?, ".")
  end

  def test_resolv_checker_cli_guard_propagates_the_runner_status
    checker = SurfguardRelease::ResolvVersionCheck
    with_singleton_method(checker, :main, -> { 7 }) do
      error = assert_raises(SystemExit) do
        checker.cli(program_name: "checker", file: "checker")
      end
      assert_equal 7, error.status
    end
  end

  private
    def with_singleton_method(object, name, replacement)
      original = object.method(name)
      object.define_singleton_method(name, replacement)
      yield
    ensure
      object.define_singleton_method(name, original)
    end
end
