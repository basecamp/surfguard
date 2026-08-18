# frozen_string_literal: true

require_relative "test_helper"
require_relative "../script/check_resolv_version"

require "stringio"

class ResolvVersionCheckTest < Minitest::Test
  CHECK = SurfguardRelease::ResolvVersionCheck

  def test_rejects_every_affected_range_at_its_boundaries
    %w[0 0.2.2 0.3.0 0.4.0 0.6.1].each do |version|
      assert CHECK.vulnerable?(version), version
    end
  end

  def test_accepts_patched_versions_and_gaps_between_affected_ranges
    %w[0.2.3 0.2.999 0.3.1 0.3.999 0.6.2 1.0.0].each do |version|
      refute CHECK.vulnerable?(version), version
    end
  end

  def test_main_fails_closed_with_a_fixed_diagnostic_for_an_affected_version
    output = StringIO.new
    error = StringIO.new

    assert_equal 1, CHECK.main(version: "0.4.1", output: output, error: error)
    assert_empty output.string
    assert_equal "unsupported vulnerable resolv 0.4.1\n", error.string
  end

  def test_main_reports_the_effective_supported_version
    output = StringIO.new
    error = StringIO.new

    assert_equal 0, CHECK.main(version: "0.6.2", output: output, error: error)
    assert_equal "resolv 0.6.2: supported\n", output.string
    assert_empty error.string
  end

  def test_current_version_is_the_resolv_version_ruby_loaded
    loaded = Struct.new(:version).new("0.6.3")
    default = Struct.new(:version) { def default_gem? = true }.new("0.7.0")

    assert_equal Gem::Version.new("0.6.3"), CHECK.current_version(
      loaded_specs: { "resolv" => loaded }, available_specs: [ default ]
    )
    assert_equal Gem::Version.new("0.7.0"), CHECK.current_version(
      loaded_specs: {}, available_specs: [ default ]
    )
  end

  def test_current_version_fails_closed_if_rubygems_cannot_identify_resolv
    error = assert_raises(RuntimeError) do
      CHECK.current_version(loaded_specs: {}, available_specs: [])
    end

    assert_equal "could not identify the effective resolv version", error.message
  end
end
