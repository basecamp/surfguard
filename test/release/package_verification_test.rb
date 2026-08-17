# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../script/release/package_verification"

require "fileutils"
require "stringio"
require "tmpdir"
require "zlib"

# Fixture tests for the build-job package verifier: every check is exercised
# with a real (tiny) gem built in a temp dir — valid, corrupted, misnamed,
# misversioned, dependency-bearing, incomplete, and over-stuffed variants.
# The install/require subprocesses are scripted so failures are testable.
class PackageVerificationTest < Minitest::Test
  Verification = Surfguard::Release::PackageVerification
  FakeStatus = Data.define(:success?)

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
      assert_equal env["GEM_HOME"], env["GEM_PATH"].split(File::PATH_SEPARATOR).first
      assert_nil env["RUBYOPT"]
      assert_nil env["RUBYLIB"]
      assert_nil env["RUBYGEMS_GEMDEPS"]
      if command.first == "gem"
        refute_equal gem_file, command.last
        assert_equal File.binread(gem_file), File.binread(command.last)
      end
      true
    }

    assert Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: runner, out: @out).verify!
    assert_equal 3, commands.size
    assert_equal %w[ gem install --local --no-document ], commands.first.first(4)
    assert_equal %w[ ruby -e ], commands[1].first(2)
    assert_equal %w[ ruby -e ], commands.last.first(2)
    assert_includes commands.last.fetch(2), "installed suite loaded wrong feature"
    assert_equal Verification::CORE_TEST_FILES, commands.last.last(Verification::CORE_TEST_FILES.size)
    assert_match(/passed all checks/, @out.string)
  end

  def test_verification_fails_if_the_source_artifact_changes_after_install
    gem_file = build_fixture
    calls = 0
    runner = lambda { |_env, *|
      calls += 1
      File.binwrite(gem_file, "attacker replacement") if calls == 1
      true
    }

    error = assert_raises(Verification::Failure) { verification(gem_file, runner: runner).verify! }
    assert_match(/source artifact bytes changed during verification/, error.message)
  end

  def test_installed_suite_rejects_an_empty_core_test_set
    files = DEFAULT_FILES.merge(
      "lib/surfguard.rb" => "require_relative \"surfguard/version\"\n",
      "lib/surfguard/version.rb" => "module Surfguard; VERSION = \"0.1.0\"; end\n"
    )
    gem_file = build_fixture(files: files)
    empty_suite = File.join(@dir, "empty-suite")
    FileUtils.mkdir_p(empty_suite)
    runner = ->(env, *command) { Kernel.system(env, *command, out: File::NULL, err: File::NULL) }

    error = assert_raises(Verification::Failure) do
      verification(gem_file, runner: runner, suite_root: empty_suite).verify!
    end
    assert_match(/installed core suite failed/, error.message)
  end

  def test_a_corrupted_archive_fails_the_integrity_check
    gem_file = build_fixture
    File.binwrite(gem_file, File.binread(gem_file).byteslice(0, 100))

    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/raw nested archive structure/, error.message)
  end

  def test_a_different_gem_name_fails
    gem_file = build_fixture(name: "imposter")
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/exact package specification: name/, error.message)
  end

  def test_a_different_version_fails
    gem_file = build_fixture(version: "9.9.9")
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/exact package specification: version/, error.message)
  end

  def test_a_runtime_dependency_fails
    gem_file = build_fixture(dependencies: %w[ rake ])
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/exact package specification: dependencies.*rake/, error.message)
  end

  def test_a_missing_required_file_fails
    gem_file = build_fixture(files: DEFAULT_FILES.except("SECURITY.md"))
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/exact packaged files/, error.message)
  end

  def test_an_unexpected_file_fails
    gem_file = build_fixture(files: DEFAULT_FILES.merge("lib/surfguard/payload.txt" => "!\n"))
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/exact packaged files.*lib\/surfguard\/payload\.txt/, error.message)
  end

  def test_raw_archive_rejects_duplicate_colliding_traversing_symlink_and_abnormal_mode_members
    mutations = {
      duplicate: ->(writer) { writer.add_file_simple("README.md", 0o644, 1) { |io| io.write("x") } },
      collision: ->(writer) { writer.add_file_simple("readme.md", 0o644, 1) { |io| io.write("x") } },
      traversal: ->(writer) { writer.add_file_simple("../escape", 0o644, 1) { |io| io.write("x") } },
      symlink: ->(writer) { writer.add_symlink("payload", "README.md", 0o777) },
      mode: ->(writer) { writer.add_file_simple("payload", 0o755, 1) { |io| io.write("x") } }
    }
    mutations.each_value do |mutation|
      gem_file = mutate_data_tar(build_fixture, &mutation)
      error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
      assert_match(/raw nested archive structure/, error.message)
    end
  end

  def test_raw_archive_rejects_a_second_tar_after_the_logical_end
    gem_file = build_fixture
    tail = StringIO.new
    Gem::Package::TarWriter.new(tail) do |writer|
      writer.add_file_simple("hidden-payload", 0o644, 1) { |io| io.write("x") }
    end
    File.open(gem_file, "ab") { |file| file.write(tail.string) }

    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/data after its logical end/, error.message)
  end

  def test_raw_archive_rejects_a_second_nested_tar_after_the_logical_end
    gem_file = build_fixture
    tail = StringIO.new
    Gem::Package::TarWriter.new(tail) do |writer|
      writer.add_file_simple("hidden-payload", 0o644, 1) { |io| io.write("x") }
    end
    mutate_outer_member(gem_file, "data.tar.gz") do |bytes|
      data_tar = Zlib::GzipReader.wrap(StringIO.new(bytes), &:read)
      gzip(data_tar + tail.string)
    end

    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/data after its logical end/, error.message)
  end

  def test_raw_archive_rejects_trailing_data_after_every_gzip_stream
    %w[metadata.gz data.tar.gz checksums.yaml.gz].each do |member|
      gem_file = build_fixture
      mutate_outer_member(gem_file, member) { |bytes| bytes + gzip("hidden") }

      error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
      assert_match(/#{Regexp.escape(member)} contains trailing gzip data/, error.message)
    end
  end

  def test_raw_archive_rejects_unread_trailing_data_at_a_gzip_buffer_boundary
    gem_file = build_fixture
    mutate_outer_member(gem_file, "metadata.gz") do |bytes|
      metadata = Zlib::GzipReader.wrap(StringIO.new(bytes), &:read)
      gzip_with_size(metadata, 2048) + "X"
    end

    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/metadata\.gz contains trailing gzip data/, error.message)
  end

  def test_raw_archive_bounds_physical_and_expanded_sizes
    gem_file = build_fixture
    File.truncate(gem_file, Verification::MAX_GEM_BYTES + 1)
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/gem exceeds/, error.message)

    gem_file = build_fixture
    mutate_outer_member(gem_file, "metadata.gz") do |_bytes|
      gzip("x" * (Verification::MAX_METADATA_BYTES + 1))
    end
    error = assert_raises(Verification::Failure) { verification(gem_file).verify! }
    assert_match(/metadata\.gz expands beyond/, error.message)
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

  def test_immutable_source_byte_and_mode_mismatches_fail
    gem_file = build_fixture
    bad_bytes = ->(path) { [ path == "README.md" ? "different" : DEFAULT_FILES.fetch(path), 0o644 ] }
    error = assert_raises(Verification::Failure) do
      Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: ->(_env, *) { true },
        source_reader: bad_bytes, out: @out).verify!
    end
    assert_match(/"README\.md" bytes differ/, error.message)

    bad_mode = ->(path) { [ DEFAULT_FILES.fetch(path), path == "LICENSE" ? 0o755 : 0o644 ] }
    error = assert_raises(Verification::Failure) do
      Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: ->(_env, *) { true },
        source_reader: bad_mode, out: @out).verify!
    end
    assert_match(/"LICENSE" mode differs/, error.message)
  end

  def test_source_identity_must_name_a_commit_object_not_a_tree
    tree, status = Open3.capture2("git", "rev-parse", "HEAD^{tree}")
    assert status.success?
    gem_file = build_fixture
    verifier = Verification.new(gem_file, name: "surfguard", version: "0.1.0",
      runner: ->(_env, *) { true }, source_commit: tree.strip, out: @out)

    error = assert_raises(Verification::Failure) { verifier.verify! }
    assert_match(/immutable source commit identity: source identity is not an immutable commit object/, error.message)
  end

  def test_live_factory_owns_suite_root_and_uses_the_kernel_runner
    original_root = ENV["SURFGUARD_SUITE_ROOT"]
    ENV["SURFGUARD_SUITE_ROOT"] = @dir
    calls = []
    with_singleton_method(Kernel, :system, ->(*arguments) { calls << arguments; :ran }) do
      live = Verification.live("artifact.gem", name: "surfguard", version: "1.2.3", source_commit: "a" * 40,
        out: @out)
      assert_equal @dir, live.instance_variable_get(:@suite_root)
      assert_equal :ran, live.instance_variable_get(:@runner).call({ "A" => "B" }, "command", "argument")
    end
    assert_equal [ [ { "A" => "B" }, "command", "argument" ] ], calls

    ENV.delete("SURFGUARD_SUITE_ROOT")
    assert_equal ".", Verification.live("artifact.gem", name: "surfguard", version: "1.2.3",
      source_commit: "a" * 40, out: @out).instance_variable_get(:@suite_root)
  ensure
    ENV["SURFGUARD_SUITE_ROOT"] = original_root
  end

  def test_private_snapshot_rejects_symlinks_open_races_and_zero_progress_writes
    source = File.join(@dir, "artifact.gem")
    File.binwrite(source, "original")
    symlink = File.join(@dir, "artifact-link.gem")
    File.symlink(source, symlink)
    verifier = verification(symlink)
    error = assert_raises(RuntimeError) { verifier.send(:with_private_snapshot) { flunk } }
    assert_match(/not a regular file/, error.message)

    replacement = File.join(@dir, "replacement.gem")
    File.binwrite(replacement, "replacement")
    original_open = File.method(:open)
    replaced = false
    wrapper = lambda do |path, *arguments, &block|
      if path == source && !replaced
        replaced = true
        File.rename(replacement, source)
      end
      original_open.call(path, *arguments, &block)
    end
    with_singleton_method(File, :open, wrapper) do
      error = assert_raises(RuntimeError) { verification(source).send(:with_private_snapshot) { flunk } }
      assert_match(/changed while opening/, error.message)
    end

    fake = Object.new
    fake.define_singleton_method(:binmode) { }
    fake.define_singleton_method(:write) { |_bytes| 0 }
    snapshot_path = File.join(@dir, "snapshot")
    wrapper = lambda do |path, *arguments, &block|
      path == snapshot_path ? block.call(fake) : original_open.call(path, *arguments, &block)
    end
    with_singleton_method(File, :open, wrapper) do
      error = assert_raises(RuntimeError) do
        verification(source).send(:write_private_snapshot, snapshot_path, "bytes")
      end
      assert_match(/made no progress/, error.message)
    end
  end

  def test_snapshot_end_checks_reject_each_identity_and_byte_change
    assert_snapshot_change(:source_identity, /source artifact identity/) do |fixture|
      replacement = "#{fixture.fetch(:source_path)}.replacement"
      File.binwrite(replacement, fixture.fetch(:bytes))
      File.rename(replacement, fixture.fetch(:source_path))
    end
    assert_snapshot_change(:private_identity, /private snapshot identity/) do |fixture|
      replacement = "#{fixture.fetch(:snapshot_path)}.replacement"
      File.binwrite(replacement, fixture.fetch(:bytes))
      File.rename(replacement, fixture.fetch(:snapshot_path))
    end
    assert_snapshot_change(:private_bytes, /private snapshot bytes/) do |fixture|
      File.binwrite(fixture.fetch(:snapshot_path), "changed")
    end
  end

  def test_archive_helpers_cover_invalid_compression_member_limits_and_padding
    verifier = verification(build_fixture)
    error = assert_raises(RuntimeError) { verifier.send(:inspect_raw_archive, "\xff".b * 1024) }
    assert_match(/invalid archive/, error.message)

    assert_equal false, verifier.send(:valid_tar_padding?, nil)
    assert_equal false, verifier.send(:valid_tar_padding?, "\0" * 511)
    assert_equal false, verifier.send(:valid_tar_padding?, "\0" * 513)
    assert_equal false, verifier.send(:valid_tar_padding?, "x" + ("\0" * 511))
    assert_equal true, verifier.send(:valid_tar_padding?, "\0" * 512)

    error = assert_raises(Zlib::Error) do
      verifier.send(:read_gzip, "not gzip", limit: 100, label: "fixture")
    end
    assert_match(/not in gzip format/, error.message)

    error = assert_raises(RuntimeError) { verifier.send(:read_tar, "x", outer: false, limit: 0) }
    assert_match(/tar exceeds/, error.message)

    outer = tar_entries(File.binread(build_fixture))
    outer.delete("metadata.gz")
    missing_outer = File.join(@dir, "missing-outer.gem")
    write_outer(missing_outer, outer)
    error = assert_raises(RuntimeError) do
      verifier.send(:inspect_raw_archive, File.binread(missing_outer))
    end
    assert_match(/outer members differ/, error.message)

    tar = StringIO.new
    Gem::Package::TarWriter.new(tar) do |writer|
      (Verification::MAX_ARCHIVE_MEMBERS + 1).times do |index|
        writer.add_file_simple("member-#{index}", 0o644, 0) { }
      end
    end
    error = assert_raises(RuntimeError) do
      verifier.send(:read_tar, tar.string, outer: false, limit: Verification::MAX_DATA_TAR_BYTES)
    end
    assert_match(/too many members/, error.message)

    oversized_header = tar_header(name: "oversized", size: 4096) + ("\0" * 1024)
    error = assert_raises(RuntimeError) do
      verifier.send(:read_tar, oversized_header, outer: false, limit: oversized_header.bytesize)
    end
    assert_match(/member "oversized" exceeds/, error.message)

    error = assert_raises(RuntimeError) do
      verifier.send(:read_tar, oversized_header, outer: false, limit: 5000)
    end
    assert_match(/truncated member|unexpected end/, error.message)
  end

  def test_path_validator_rejects_every_noncanonical_shape
    verifier = verification(build_fixture)
    paths = [ "", "/absolute", "back\\slash", "empty//part", "dot/./part", "dotdot/../part", "non-ascii-\u00e9" ]
    paths.concat((0x00..0x1f).map { |byte| "control-#{byte.chr}-path" })
    paths << "control-#{0x7f.chr}-path"
    paths.each do |path|
      error = assert_raises(RuntimeError) { verifier.send(:validate_path!, path) }
      assert_match(/non-canonical/, error.message)
      assert_equal 1, error.message.lines.size
      refute_match(/[\x00-\x1f\x7f]/, error.message)
      assert_includes error.message, path.inspect
    end
    assert_nil verifier.send(:validate_path!, "lib/surfguard.rb")
  end

  def test_spec_verifier_checks_every_identity_and_metadata_field
    gem_file = build_fixture
    valid = Gem::Package.new(gem_file).spec
    verifier = verification(gem_file)
    mutations = {
      /require_paths/ => ->(spec) { spec.require_paths = [ "src" ] },
      /dependencies/ => ->(spec) { spec.add_dependency("rake") },
      /extensions/ => lambda { |spec|
        spec.extensions = [ "extconf.rb" ]
        spec.define_singleton_method(:require_paths) { [ "lib" ] }
      },
      /executables/ => ->(spec) { spec.executables = [ "surfguard" ] },
      /authors/ => ->(spec) { spec.authors = [ "attacker" ] },
      /summary/ => ->(spec) { spec.summary = "wrong" },
      /description/ => ->(spec) { spec.description = "wrong" },
      /license/ => ->(spec) { spec.licenses = [ "GPL" ] },
      /homepage/ => ->(spec) { spec.homepage = "https://example.test" },
      /required Ruby/ => ->(spec) { spec.required_ruby_version = ">= 3.0" },
      /platform/ => ->(spec) { spec.platform = Gem::Platform.new("x86_64-linux") },
      /certificate chain/ => ->(spec) { spec.cert_chain = [ "certificate" ] },
      /metadata/ => ->(spec) { spec.metadata = { "rubygems_mfa_required" => "false" } }
    }
    mutations.each do |message, mutation|
      spec = valid.dup
      mutation.call(spec)
      error = assert_raises(RuntimeError) { verifier.send(:verify_spec, spec) }
      assert_match message, error.message
    end

    other = valid.dup
    other.name = "fixture"
    assert_nil Verification.new(gem_file, name: "fixture", version: "0.1.0", runner: ->(*) { true })
      .send(:verify_spec, other)
  end

  def test_file_set_verifier_checks_metadata_and_archive_lists
    verifier = verification(build_fixture)
    required = Verification::REQUIRED_FILES
    error = assert_raises(RuntimeError) { verifier.send(:verify_file_set, [], required) }
    assert_match(/spec\.files/, error.message)
    error = assert_raises(RuntimeError) { verifier.send(:verify_file_set, required, []) }
    assert_match(/archive files/, error.message)
    assert_nil verifier.send(:verify_file_set, required, required)
  end

  def test_source_commit_validation_covers_status_errors_and_canonical_resolution
    commit = "a" * 40
    [ 39, 41, 63, 65 ].each do |length|
      malformed = private_verifier(source_commit: "a" * length)
      assert_match(/full commit/, assert_raises(RuntimeError) { malformed.send(:verify_source_commit!) }.message)
    end

    [ "", "fatal: missing" ].each do |detail|
      capture = ->(*) { [ "", detail, FakeStatus.new(false) ] }
      error = assert_raises(RuntimeError) do
        private_verifier(source_commit: commit, capture: capture).send(:verify_source_commit!)
      end
      assert_match(/immutable commit object/, error.message)
      assert_includes error.message, detail unless detail.empty?
    end

    [ [ false, "" ], [ false, "fatal: resolve" ], [ true, "" ] ].each do |success, detail|
      responses = [ [ "commit\n", "", FakeStatus.new(true) ],
        [ success ? "b" * 40 : "", detail, FakeStatus.new(success) ] ]
      error = assert_raises(RuntimeError) do
        private_verifier(source_commit: commit, capture: ->(*) { responses.shift }).send(:verify_source_commit!)
      end
      assert_match(/did not resolve canonically/, error.message)
      assert_includes error.message, detail unless detail.empty?
    end

    responses = [ [ "commit\n", "", FakeStatus.new(true) ], [ "#{commit}\n", "", FakeStatus.new(true) ] ]
    assert_nil private_verifier(source_commit: commit, capture: ->(*) { responses.shift }).send(:verify_source_commit!)
  end

  def test_source_entry_rejects_each_git_failure_and_accepts_regular_blob
    commit = "a" * 40
    cases = [
      [ [ [ "", "show failed", false ] ], /git show failed/ ],
      [ [ [ "bytes", "", true ], [ "", "tree failed", false ] ], /git ls-tree failed/ ],
      [ [ [ "bytes", "", true ], [ "", "", true ] ], /source member missing/ ],
      [ [ [ "bytes", "", true ], [ "100755 blob deadbeef\tREADME.md\n", "", true ] ], /abnormal git mode/ ]
    ]
    cases.each do |raw_responses, message|
      responses = raw_responses.map { |stdout, stderr, success| [ stdout, stderr, FakeStatus.new(success) ] }
      verifier = private_verifier(source_commit: commit, capture: ->(*) { responses.shift })
      assert_match message, assert_raises(RuntimeError) { verifier.send(:source_entry, "README.md") }.message
    end

    source_bytes = "security \u2014 policy\n".encode(Encoding::UTF_8)
    responses = [ [ source_bytes, "", FakeStatus.new(true) ],
      [ "100644 blob deadbeef\tREADME.md\n", "", FakeStatus.new(true) ] ]
    entry = private_verifier(source_commit: commit,
      capture: ->(*) { responses.shift }).send(:source_entry, "README.md")
    assert_equal [ source_bytes.b, 0o644 ], entry
    assert_equal Encoding::BINARY, entry.first.encoding
  end

  # --- CLI entry point --------------------------------------------------------

  def test_run_verifies_and_exits_zero
    gem_file = build_fixture
    err = StringIO.new
    built = nil
    factory = lambda { |file, name:, version:, source_commit:, out:|
      built = [ file, name, version ]
      Verification.new(file, name: name, version: version, runner: ->(_env, *) { true }, out: out)
    }

    status = Verification.run([ gem_file, "surfguard", "0.1.0", "a" * 40 ], out: @out, err: err,
      verification_for: factory)
    assert_equal 0, status
    assert_equal [ gem_file, "surfguard", "0.1.0" ], built
  end

  def test_run_usage_error_exits_two
    err = StringIO.new
    assert_equal 2, Verification.run([ "x.gem" ], out: @out, err: err)
    assert_match(/usage/, err.string)

    assert_equal 2, Verification.run([ "x.gem", "surfguard", "0.1.0", nil ], out: @out, err: err)
    [ 39, 41, 63, 65 ].each do |length|
      assert_equal 2, Verification.run([ "x.gem", "surfguard", "0.1.0", "a" * length ], out: @out, err: err)
    end
  end

  def test_run_missing_file_exits_two
    err = StringIO.new
    assert_equal 2, Verification.run(
      [ File.join(@dir, "nope.gem"), "surfguard", "0.1.0", "a" * 40 ], out: @out, err: err
    )
    assert_match(/no such file/, err.string)
  end

  def test_run_failure_exits_one
    gem_file = build_fixture(version: "9.9.9")
    err = StringIO.new
    factory = lambda { |file, name:, version:, source_commit:, out:|
      Verification.new(file, name: name, version: version, runner: ->(_env, *) { true }, out: out)
    }

    status = Verification.run([ gem_file, "surfguard", "0.1.0", "a" * 40 ], out: @out, err: err,
      verification_for: factory)
    assert_equal 1, status
    assert_match(/verify_package: exact package specification: version/, err.string)
  end

  def test_run_escapes_control_and_workflow_command_archive_paths_on_one_stderr_line
    cases = [
      [ "payload\n::error file=README.md::newline", 1 ],
      [ "payload\e::error file=README.md::escape", 1 ],
      [ "payload\x7f::error file=README.md::delete", 1 ],
      [ "::error file=README.md,line=1::workflow-command", 2 ]
    ]
    factory = lambda { |file, name:, version:, source_commit:, out:|
      Verification.new(file, name: name, version: version, runner: ->(_env, *) { true }, out: out)
    }

    cases.each do |path, copies|
      gem_file = mutate_data_tar(build_fixture) do |writer|
        copies.times do
          writer.add_file_simple(path, 0o644, 1) { |io| io.write("x") }
        end
      end
      err = StringIO.new
      status = Verification.run(
        [ gem_file, "surfguard", "0.1.0", "a" * 40 ], out: @out, err: err,
        verification_for: factory
      )

      assert_equal 1, status
      assert_equal 1, err.string.lines.size
      diagnostic = err.string.delete_suffix("\n")
      refute_match(/[\x00-\x1f\x7f]/, diagnostic)
      refute_match(/\A::/, diagnostic)
      assert_includes diagnostic, path.inspect
    end
  end

  private
    def tar_header(name:, size:)
      Gem::Package::TarHeader.new(
        name: name, mode: 0o644, size: size, prefix: "", mtime: 0, typeflag: "0", linkname: "",
        magic: "ustar", version: "00", uname: "", gname: "", uid: 0, gid: 0,
        devmajor: 0, devminor: 0, checksum: 0
      ).to_s
    end

    def private_verifier(source_commit: nil, capture: Open3.method(:capture3))
      Verification.new(File.join(@dir, "artifact.gem"), name: "surfguard", version: "0.1.0",
        runner: ->(*) { true }, source_commit: source_commit, capture: capture, out: @out)
    end

    def assert_snapshot_change(label, message)
      directory = File.join(@dir, label.to_s)
      FileUtils.mkdir_p(directory)
      bytes = "unchanged"
      source_path = File.join(directory, "source.gem")
      snapshot_path = File.join(directory, "snapshot.gem")
      File.binwrite(source_path, bytes)
      File.binwrite(snapshot_path, bytes)
      source = File.open(source_path, "rb")
      snapshot = {
        path: snapshot_path,
        digest: Digest::SHA256.hexdigest(bytes),
        source: source,
        source_identity: File.stat(source_path).then { |stat| [ stat.dev, stat.ino ] },
        snapshot_identity: File.stat(snapshot_path).then { |stat| [ stat.dev, stat.ino ] }
      }
      yield({ source_path: source_path, snapshot_path: snapshot_path, bytes: bytes })
      error = assert_raises(RuntimeError) do
        Verification.new(source_path, name: "surfguard", version: "0.1.0", runner: ->(*) { true })
          .send(:verify_snapshot_unchanged, snapshot)
      end
      assert_match message, error.message
    ensure
      source&.close
    end

    def with_singleton_method(object, name, replacement)
      original = object.method(name)
      object.define_singleton_method(name, replacement)
      yield
    ensure
      object.define_singleton_method(name, original)
    end

    def mutate_data_tar(gem_file)
      outer = tar_entries(File.binread(gem_file))
      original_data = Zlib::GzipReader.wrap(StringIO.new(outer.fetch("data.tar.gz")[:data]), &:read)
      data_entries = tar_entries(original_data)
      rebuilt_data = StringIO.new
      Gem::Package::TarWriter.new(rebuilt_data) do |writer|
        data_entries.each do |path, entry|
          writer.add_file_simple(path, entry[:mode], entry[:data].bytesize) { |io| io.write(entry[:data]) }
        end
        yield writer
      end
      outer["data.tar.gz"] = { data: gzip(rebuilt_data.string), mode: 0o644 }
      write_outer(gem_file, outer)
    end

    def mutate_outer_member(gem_file, member)
      outer = tar_entries(File.binread(gem_file))
      entry = outer.fetch(member)
      outer[member] = entry.merge(data: yield(entry.fetch(:data)))
      write_outer(gem_file, outer)
    end

    def write_outer(gem_file, outer)
      rebuilt = StringIO.new
      Gem::Package::TarWriter.new(rebuilt) do |writer|
        outer.each do |path, entry|
          writer.add_file_simple(path, entry[:mode], entry[:data].bytesize) { |io| io.write(entry[:data]) }
        end
      end
      File.binwrite(gem_file, rebuilt.string)
      gem_file
    end

    def gzip(bytes)
      compressed = StringIO.new(+"".b)
      Zlib::GzipWriter.wrap(compressed) { |writer| writer.write(bytes) }
      compressed.string
    end

    def gzip_with_size(bytes, size)
      (0..size).each do |name_length|
        compressed = StringIO.new(+"".b)
        writer = Zlib::GzipWriter.new(compressed)
        writer.orig_name = "A" * name_length
        writer.write(bytes)
        writer.close
        return compressed.string if compressed.string.bytesize == size
      end
      raise "could not construct a #{size}-byte gzip member"
    end

    def tar_entries(bytes)
      entries = {}
      Gem::Package::TarReader.new(StringIO.new(bytes)) do |reader|
        reader.each do |entry|
          entries[entry.full_name] = { data: entry.read, mode: entry.header.mode }
        end
      end
      entries
    end

    def verification(gem_file, runner: ->(_env, *) { true }, suite_root: ".")
      Verification.new(gem_file, name: "surfguard", version: "0.1.0", runner: runner,
        suite_root: suite_root, out: @out)
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
          s.summary = name == "surfguard" ? Verification::SUMMARY : "fixture"
          s.description = Verification::DESCRIPTION if name == "surfguard"
          s.authors = name == "surfguard" ? [ "37signals" ] : [ "test" ]
          s.license = "MIT" if name == "surfguard"
          s.homepage = "https://github.com/basecamp/surfguard" if name == "surfguard"
          s.required_ruby_version = ">= 3.4.5" if name == "surfguard"
          s.metadata = {
            "bug_tracker_uri" => "https://github.com/basecamp/surfguard/issues",
            "changelog_uri" => "https://github.com/basecamp/surfguard/releases",
            "rubygems_mfa_required" => "true"
          } if name == "surfguard"
          s.files = files.keys
          dependencies.each { |dependency| s.add_dependency(dependency) }
        end

        Gem::Package.build(spec, true)
      end

      File.join(source, built)
    end
end
