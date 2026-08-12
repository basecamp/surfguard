# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../script/release/package_verification"

require "fileutils"
require "stringio"
require "tmpdir"

# Fixture tests for the build-job package verifier: every check is exercised
# with a real (tiny) gem built in a temp dir — valid, corrupted, misnamed,
# misversioned, dependency-bearing, incomplete, and over-stuffed variants.
# The install/require subprocesses are scripted so failures are testable.
class PackageVerificationTest < Minitest::Test
  Verification = Surfguard::Release::PackageVerification

  DEFAULT_FILES = {
    "lib/surfguard.rb"         => "# fixture\n",
    "lib/surfguard/version.rb" => "# fixture\n",
    "README.md"                => "readme\n",
    "LICENSE"                  => "license\n",
    "SECURITY.md"              => "security\n"
  }.freeze

  def setup
    @dir = Dir.mktmpdir("package-verification-test")
    @out = StringIO.new
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_a_well_formed_gem_passes_every_check_and_runs_both_probes
    gem_file = build_fixture
    commands = []
    runner = lambda { |env, *command|
      commands << command
      assert_equal env["GEM_HOME"], env["GEM_PATH"]
      assert_nil env["RUBYOPT"]
      assert_nil env["RUBYLIB"]
      true
    }

    assert Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: runner, out: @out).verify!
    assert_equal 2, commands.size
    assert_equal %w[ gem install --local --no-document ], commands.first.first(4)
    assert_equal %w[ ruby -e ], commands.last.first(2)
    assert_match(/passed all checks/, @out.string)
  end

  def test_a_corrupted_archive_fails_the_integrity_check
    gem_file = build_fixture
    File.binwrite(gem_file, File.binread(gem_file).byteslice(0, 100))

    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/archive integrity/, error.message)
  end

  def test_a_different_gem_name_fails
    gem_file = build_fixture(name: "imposter")
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/spec name/, error.message)
  end

  def test_a_different_version_fails
    gem_file = build_fixture(version: "9.9.9")
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/spec version/, error.message)
  end

  def test_a_runtime_dependency_fails
    gem_file = build_fixture(dependencies: %w[ rake ])
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/zero runtime dependencies: got: rake/, error.message)
  end

  def test_a_missing_required_file_fails
    gem_file = build_fixture(files: DEFAULT_FILES.except("SECURITY.md"))
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/required files all present: missing: SECURITY\.md/, error.message)
  end

  def test_an_unexpected_file_fails
    gem_file = build_fixture(files: DEFAULT_FILES.merge("lib/surfguard/payload.txt" => "!\n"))
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/no unexpected files: unexpected: lib\/surfguard\/payload\.txt/, error.message)
  end

  def test_a_failing_install_fails
    gem_file = build_fixture
    error = assert_raises(Verification::Failure) { verification(gem_file, runner: ->(_env, *) { false }).verify! }
    assert_match(/gem install failed/, error.message)
  end

  def test_a_failing_require_probe_fails
    gem_file = build_fixture
    results = [ true, false ]
    error = assert_raises(Verification::Failure) do
      verification(gem_file, runner: ->(_env, *) { results.shift }).verify!
    end
    assert_match(/require probe failed/, error.message)
  end

  # --- CLI entry point --------------------------------------------------------

  def test_run_verifies_and_exits_zero
    gem_file = build_fixture
    err = StringIO.new
    built = nil
    factory = lambda { |file, name:, version:, out:|
      built = [ file, name, version ]
      Verification.new(file, name: name, version: version, runner: ->(_env, *) { true }, out: out)
    }

    status = Verification.run([ gem_file, "surfguard", "0.1.0" ], out: @out, err: err, verification_for: factory)
    assert_equal 0, status
    assert_equal [ gem_file, "surfguard", "0.1.0" ], built
  end

  def test_run_usage_error_exits_two
    err = StringIO.new
    assert_equal 2, Verification.run([ "x.gem" ], out: @out, err: err)
    assert_match(/usage/, err.string)
  end

  def test_run_missing_file_exits_two
    err = StringIO.new
    assert_equal 2, Verification.run([ File.join(@dir, "nope.gem"), "surfguard", "0.1.0" ], out: @out, err: err)
    assert_match(/no such file/, err.string)
  end

  def test_run_failure_exits_one
    gem_file = build_fixture(version: "9.9.9")
    err = StringIO.new
    factory = lambda { |file, name:, version:, out:|
      Verification.new(file, name: name, version: version, runner: ->(_env, *) { true }, out: out)
    }

    status = Verification.run([ gem_file, "surfguard", "0.1.0" ], out: @out, err: err, verification_for: factory)
    assert_equal 1, status
    assert_match(/verify_package: spec version/, err.string)
  end

  private
    def verification(gem_file, runner: ->(_env, *) { true })
      Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: runner, out: @out)
    end

    # Build a real gem from the given files in an isolated source dir and
    # park it in the test's tmpdir.
    def build_fixture(name: "surfguard", version: "0.1.0", files: DEFAULT_FILES, dependencies: [])
      source = File.join(@dir, "src-#{name}-#{version}-#{files.size}-#{dependencies.size}")
      FileUtils.mkdir_p(source)

      built = Dir.chdir(source) do
        files.each do |path, content|
          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, content)
        end

        spec = Gem::Specification.new do |s|
          s.name = name
          s.version = version
          s.summary = "fixture"
          s.authors = [ "test" ]
          s.files = files.keys
          dependencies.each { |dependency| s.add_dependency(dependency) }
        end

        Gem::Package.build(spec, true)
      end

      File.join(source, built)
    end
end
