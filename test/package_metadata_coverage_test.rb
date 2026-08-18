# frozen_string_literal: true

require_relative "test_helper"

class PackageMetadataCoverageTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)

  def test_version_and_gemspec_are_evaluated_under_coverage
    _out, _err = capture_io { load File.join(ROOT, "lib/surfguard/version.rb") }
    _out, _err = capture_io { load File.join(ROOT, "surfguard.gemspec") }
    spec = Gem::Specification.load(File.join(ROOT, "surfguard.gemspec"))

    # Exact semver with optional RubyGems prerelease segments; asserting the
    # format rather than the literal keeps `rake bump` transactional.
    assert_match(/\A\d+\.\d+\.\d+(\.[a-z0-9]+)*\z/i, Surfguard::VERSION)
    assert_equal "surfguard", spec.name
    assert_equal Surfguard::VERSION, spec.version.to_s
    assert_equal %w[LICENSE README.md SECURITY.md lib/surfguard.rb lib/surfguard/version.rb], spec.files
    assert_empty spec.runtime_dependencies
  end
end
