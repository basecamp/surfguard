# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../.github/scripts/validate_dependabot_lockfile"

require "stringio"
require "tempfile"

class DependabotValidatorTest < Minitest::Test
  VALIDATOR = File.expand_path("../../.github/scripts/validate_dependabot_lockfile.rb", __dir__)
  LOCK = File.expand_path("../../Gemfile.lock", __dir__)
  CHECK = Surfguard::DependabotLockfileValidator
  Status = Data.define(:exitstatus) do
    def success? = exitstatus.zero?
  end

  def validate(head, update = "version-update:semver-patch", ecosystem: "bundler")
    validate_pair(File.binread(LOCK), head, update, ecosystem: ecosystem)
  end

  def validate_pair(base, head, update = "version-update:semver-patch", ecosystem: "bundler")
    Tempfile.create("base.lock") do |base_file|
      base_file.binmode
      base_file.write(base)
      base_file.flush
      Tempfile.create("head.lock") do |file|
        file.binmode
        file.write(head)
        file.flush
        out = StringIO.new
        err = StringIO.new
        status = CHECK.run([ base_file.path, file.path, ecosystem, update ], out: out, err: err)
        [ out.string, err.string, Status.new(status) ]
      end
    end
  end

  def updated(name, from, to)
    File.read(LOCK).gsub("    #{name} (#{from})", "    #{name} (#{to})")
      .gsub("  #{name} (#{from}) sha256=", "  #{name} (#{to}) sha256=")
      .sub(/(  #{Regexp.escape(name)} \(#{Regexp.escape(to)}\) sha256=)[0-9a-f]{64}/, "\\1#{'a' * 64}")
  end

  def test_accepts_one_patch_and_independently_checks_update_type
    _out, _err, status = validate(updated("rake", "13.4.2", "13.4.3"))
    assert_predicate status, :success?
  end

  def test_accepts_one_minor_update
    out, err, status = validate(updated("rake", "13.4.2", "13.5.0"), "version-update:semver-minor")

    assert_predicate status, :success?, err
    assert_match(/semver-minor/, out)
  end

  def test_rejects_major_prerelease_source_and_structural_changes
    cases = [
      updated("ast", "2.4.3", "3.0.0"),
      updated("ast", "2.4.3", "2.4.4.rc1"),
      updated("ast", "2.4.3", "2.4.4").sub("remote: https://rubygems.org/", "remote: http://rubygems.org/"),
      updated("ast", "2.4.3", "2.4.4").sub("GEM\n", "GIT\n")
    ]
    cases.each do |head|
      _out, _err, status = validate(head)
      refute_predicate status, :success?
    end
  end

  def test_rejects_grouped_or_transitive_changes_and_metadata_mismatch
    grouped = updated("ast", "2.4.3", "2.4.4")
      .gsub("    rainbow (3.1.1)", "    rainbow (3.1.2)")
      .gsub("  rainbow (3.1.1) sha256=", "  rainbow (3.1.2) sha256=")
    _out, _err, status = validate(grouped)
    refute_predicate status, :success?

    _out, _err, status = validate(updated("ast", "2.4.3", "2.4.4"), "version-update:semver-minor")
    refute_predicate status, :success?
  end

  def test_rejects_stale_changed_checksum_and_unrelated_checksum_mutation
    stale = File.read(LOCK).gsub("    ast (2.4.3)", "    ast (2.4.4)")
    _out, err, status = validate(stale)
    refute_predicate status, :success?
    assert_match(/matching head checksum/, err)

    unrelated = updated("ast", "2.4.3", "2.4.4")
      .sub(/(  rack \(3\.2\.6\) sha256=)[0-9a-f]{64}/, "\\1#{'b' * 64}")
    _out, err, status = validate(unrelated)
    refute_predicate status, :success?
    assert_match(/unrelated checksum/, err)
  end

  def test_rejects_duplicate_or_malformed_checksum_records
    valid = updated("ast", "2.4.3", "2.4.4")
    record = valid[/^  ast \(.+$/]
    duplicate = valid.sub("\nBUNDLED WITH", "\n#{record}\nBUNDLED WITH")
    _out, err, status = validate(duplicate)
    refute_predicate status, :success?
    assert_match(/checksum/, err)

    malformed = updated("ast", "2.4.3", "2.4.4").sub(/sha256=[0-9a-f]{64}/, "sha256=xyz")
    _out, err, status = validate(malformed)
    refute_predicate status, :success?
    assert_match(/checksum/, err)
  end

  def test_rejects_git_plugin_path_and_alternate_registry_sources
    valid = updated("ast", "2.4.3", "2.4.4")
    cases = [
      [ "forbidden lockfile source", valid.sub("GEM\n", "GIT\n") ],
      [ "forbidden lockfile source", valid.sub("GEM\n", "PLUGIN\n") ],
      [ "unexpected local path", valid.sub("  remote: .\n", "  remote: ../attacker\n") ],
      [ "canonical RubyGems", valid.sub("https://rubygems.org/", "https://gems.example/") ]
    ]
    cases.each do |message, head|
      _out, err, status = validate(head)
      refute_predicate status, :success?
      assert_match(/#{Regexp.escape(message)}/, err)
    end
  end

  def test_rejects_added_removed_ambiguous_and_dependency_edge_changes
    valid = updated("ast", "2.4.3", "2.4.4")
    added = valid.sub("    ast (2.4.4)\n", "    ast (2.4.4)\n    attacker (1.0.0)\n")
      .sub("CHECKSUMS\n", "CHECKSUMS\n  attacker (1.0.0) sha256=#{'c' * 64}\n")
    removed = valid.sub(/^    rainbow \(3\.1\.1\)\n/, "")
    duplicate = valid.sub("    ast (2.4.4)\n", "    ast (2.4.4)\n    ast (2.4.4)\n")
    edge = valid.sub("      json (~> 2.3)", "      json (~> 2.4)")

    [ added, removed, duplicate, edge ].each do |head|
      _out, _err, status = validate(head)
      refute_predicate status, :success?
    end
  end

  def test_rejects_equivalent_version_respelling_of_a_second_dependency
    respelled = updated("rake", "13.4.2", "13.4.3")
      .sub("    rainbow (3.1.1)", "    rainbow (3.1.1.0)")
    _out, err, status = validate(respelled)

    refute_predicate status, :success?
    assert_match(/exactly one/, err)
  end

  def test_parses_platform_qualified_specs_per_bundler_lockfile_grammar
    platformed = lambda do |text|
      text.sub("    racc (1.8.1)", "    racc (1.8.1-x86_64-linux)")
        .sub("  racc (1.8.1) sha256=", "  racc (1.8.1-x86_64-linux) sha256=")
    end
    base = platformed.call(File.binread(LOCK))
    head = platformed.call(updated("rake", "13.4.2", "13.4.3"))
    _out, err, status = validate_pair(base, head)
    assert_predicate status, :success?, err

    platform_flip = platformed.call(File.binread(LOCK))
    _out, err, status = validate(platform_flip)
    refute_predicate status, :success?
    assert_match(/platform changed/, err)

    bump_with_flip = File.read(LOCK)
      .sub("    rake (13.4.2)", "    rake (13.4.3-x86_64-linux)")
      .sub("  rake (13.4.2) sha256=", "  rake (13.4.3-x86_64-linux) sha256=")
      .sub(/(  rake \(13\.4\.3-x86_64-linux\) sha256=)[0-9a-f]{64}/, "\\1#{'a' * 64}")
    _out, err, status = validate(bump_with_flip)
    refute_predicate status, :success?
    assert_match(/platform changed/, err)
  end

  def test_rejects_checksum_shaped_lines_outside_the_checksums_section
    injected = updated("rake", "13.4.2", "13.4.3")
      .sub("  specs:\n    activesupport",
        "  specs:\n  attacker (1.0.0) sha256=#{'e' * 64}\n    activesupport")
    _out, err, status = validate(injected)

    refute_predicate status, :success?
    assert_match(/outside version\/checksum/, err)
  end

  def test_rejects_wrong_ecosystem_and_missing_or_duplicate_structural_sections
    head = updated("ast", "2.4.3", "2.4.4")
    _out, err, status = validate(head, ecosystem: "npm")
    refute_predicate status, :success?
    assert_match(/ecosystem/, err)

    [
      head.sub("CHECKSUMS\n", ""),
      head.sub("CHECKSUMS\n", "CHECKSUMS\n\nCHECKSUMS\n")
    ].each do |structurally_invalid|
      _out, _err, status = validate(structurally_invalid)
      refute_predicate status, :success?
    end
  end

  def test_rejects_an_otherwise_valid_transitive_update
    _out, err, status = validate(updated("ast", "2.4.3", "2.4.4"))

    refute_predicate status, :success?
    assert_match(/transitive dependency/, err)
  end

  def test_rejects_malformed_and_duplicate_top_level_dependency_records
    valid = updated("rake", "13.4.2", "13.4.3")
    malformed = valid.sub("  minitest\n", " invalid dependency\n")
    duplicate = valid.sub("  minitest\n", "  minitest\n  minitest\n")

    [ malformed, duplicate ].each do |head|
      _out, _err, status = validate(head)
      refute_predicate status, :success?
    end
  end

  def test_top_level_dependency_parser_ignores_blank_records_and_excludes_path_dependencies
    dependencies = CHECK.send(:parse_direct_dependencies, "\n  minitest\n  surfguard!\n")

    assert_equal [ "minitest" ], dependencies
    assert_predicate dependencies, :frozen?
  end

  def test_run_rejects_wrong_arity_and_unreadable_files
    out = StringIO.new
    err = StringIO.new
    assert_equal 2, CHECK.run([], out: out, err: err)
    assert_empty out.string
    assert_match(/usage:/, err.string)

    missing = File.join(Dir.tmpdir, "surfguard-missing-#{Process.pid}")
    refute_path_exists missing
    err = StringIO.new
    assert_equal 1, CHECK.run([ missing, missing, "bundler", "version-update:semver-patch" ],
      out: StringIO.new, err: err)
    assert_match(/could not be read/, err.string)
  end

  def test_rejects_top_level_platform_path_and_dependency_edge_changes
    valid = updated("ast", "2.4.3", "2.4.4")
    cases = {
      "top-level dependency" => valid.sub("  minitest\n", "  minitest (= 6.0.6)\n"),
      "platform structure" => valid.sub("  ruby\n", "  ruby\n  arm64-darwin\n"),
      "local path source" => valid.sub("surfguard (0.1.3)", "surfguard (0.1.4)"),
      "outside version/checksum" => valid.sub("      base64\n", "      base64 (>= 0)\n")
    }

    cases.each do |message, head|
      _out, err, status = validate(head)
      refute_predicate status, :success?
      assert_match(/#{Regexp.escape(message)}/, err)
    end
  end

  def test_rejects_no_change_decrease_and_prerelease_base
    base = File.binread(LOCK)
    _out, err, status = validate(base)
    refute_predicate status, :success?
    assert_match(/exactly one/, err)

    _out, err, status = validate(updated("ast", "2.4.3", "2.4.2"))
    refute_predicate status, :success?
    assert_match(/did not increase/, err)

    prerelease_base = base.gsub("    ast (2.4.3)", "    ast (2.4.3.pre)")
      .gsub("  ast (2.4.3) sha256=", "  ast (2.4.3.pre) sha256=")
    release_head = prerelease_base.gsub("    ast (2.4.3.pre)", "    ast (2.4.4)")
      .gsub("  ast (2.4.3.pre) sha256=", "  ast (2.4.4) sha256=")
      .sub(/(  ast \(2\.4\.4\) sha256=)[0-9a-f]{64}/, "\\1#{'d' * 64}")
    _out, err, status = validate_pair(prerelease_base, release_head)
    refute_predicate status, :success?
    assert_match(/prerelease/, err)
  end

  def test_rejects_invalid_encoding_and_malformed_section_cardinality
    valid = updated("ast", "2.4.3", "2.4.4")
    invalid_encoding = valid.b + "\xFF".b
    cases = [
      invalid_encoding,
      valid.sub("GEM\n", ""),
      valid.sub("GEM\n", "GEM\n\nGEM\n"),
      valid.sub("PATH\n", ""),
      valid.sub("PATH\n", "PATH\n\nPATH\n")
    ]

    cases.each do |head|
      _out, _err, status = validate(head)
      refute_predicate status, :success?
    end
  end

  def test_rejects_empty_specs_checksums_and_missing_structural_sections
    valid = updated("ast", "2.4.3", "2.4.4")
    empty_specs = valid.sub(/(GEM\n  remote: https:\/\/rubygems\.org\/\n  specs:)\n.*?(?=\nPLATFORMS\n)/m, '\\1\n')
    empty_checksums = valid.sub(/CHECKSUMS\n.*?(?=\nBUNDLED WITH\n)/m, "CHECKSUMS\n")
    cases = [
      empty_specs,
      empty_checksums,
      valid.sub(/DEPENDENCIES\n.*?(?=\nCHECKSUMS\n)/m, ""),
      valid.sub(/PLATFORMS\n.*?(?=\nDEPENDENCIES\n)/m, "")
    ]

    cases.each do |head|
      _out, _err, status = validate(head)
      refute_predicate status, :success?
    end
  end

  def test_rejects_invalid_dependency_versions_and_every_changed_checksum_failure
    valid = updated("ast", "2.4.3", "2.4.4")
    invalid_version = valid.gsub("ast (2.4.4)", "ast (!)")
    no_base_checksum = File.binread(LOCK).sub(/^  ast .+\n/, "")
    no_head_checksum = valid.sub(/^  ast .+\n/, "")
    missing_digest = valid.sub(/(  ast \(2\.4\.4\)) sha256=[0-9a-f]{64}/, '\\1')
    old_digest = File.binread(LOCK)[/^  ast \(2\.4\.3\) sha256=([0-9a-f]{64})$/, 1]
    unchanged_digest = valid.sub(/(  ast \(2\.4\.4\) sha256=)[0-9a-f]{64}/, "\\1#{old_digest}")

    [
      [ File.binread(LOCK), invalid_version, /invalid dependency version/ ],
      [ no_base_checksum, valid, /matching base checksum/ ],
      [ File.binread(LOCK), no_head_checksum, /matching head checksum/ ],
      [ File.binread(LOCK), missing_digest, /checksum is missing/ ],
      [ File.binread(LOCK), unchanged_digest, /did not change/ ]
    ].each do |base, head, message|
      _out, err, status = validate_pair(base, head)
      refute_predicate status, :success?
      assert_match message, err
    end
  end

  def test_cli_guard_exits_with_run_status
    _out, err = capture_io do
      error = assert_raises(SystemExit) do
        CHECK.main(program_name: VALIDATOR, file: VALIDATOR, argv: [])
      end
      assert_equal 2, error.status
    end
    assert_match(/usage:/, err)
  end
end
