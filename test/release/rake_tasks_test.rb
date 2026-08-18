# frozen_string_literal: true

require_relative "../test_helper"

require "fileutils"
require "open3"
require "tmpdir"

# Guard tests for the release-critical rake tasks, run against the real
# Rakefile in a throwaway git repository with a local bare "origin" — fully
# offline. Every rejection must leave the tree untouched.
class RakeTasksTest < Minitest::Test
  RAKEFILE = File.expand_path("../../Rakefile", __dir__)
  BOOTSTRAP = File.expand_path("../support/rake_coverage_bootstrap", __dir__)
  FAKE_GIT = File.expand_path("../support/fake_release_git.rb", __dir__)
  REAL_GIT = ENV.fetch("PATH").split(File::PATH_SEPARATOR)
    .map { |directory| File.join(directory, "git") }.find { |path| File.executable?(path) }

  def setup
    @dir = Dir.mktmpdir("rake-tasks-test")
    @work = File.join(@dir, "work")
    @origin = File.join(@dir, "origin.git")
    @fake_bin = File.join(@dir, "bin")

    FileUtils.mkdir_p(File.join(@work, "lib/surfguard"))
    FileUtils.mkdir_p(@fake_bin)
    FileUtils.copy_file(FAKE_GIT, File.join(@fake_bin, "git"))
    File.chmod(0o755, File.join(@fake_bin, "git"))
    FileUtils.copy_file(RAKEFILE, File.join(@work, "Rakefile"))
    write_version("0.1.0")

    git "init", "--quiet", "--initial-branch=main"
    git "config", "user.email", "test@example.com"
    git "config", "user.name", "Test"
    git "config", "tag.gpgSign", "false"
    git "add", "-A"
    git "commit", "--quiet", "--message", "init"

    system("git", "clone", "--quiet", "--bare", @work, @origin, exception: true)
    git "remote", "add", "origin", @origin
    git "fetch", "--quiet", "origin"
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  # --- bump guards ------------------------------------------------------------

  def test_bump_rejects_a_malformed_version_with_zero_writes
    [ "banana", "01.2.3", "1.02.3", "00.2.0", "1.2", "1.2.3.4" ].each do |version|
      status, output = run_rake("bump[#{version}]")
      refute_predicate status, :success?, version
      assert_match(/must be exact semver/, output)
      assert_untouched
    end
  end

  def test_bump_rejects_a_dirty_tree_with_zero_writes
    File.write(File.join(@work, "scratch.txt"), "dirt\n")
    status, output = run_rake("bump[0.2.0]")
    refute_predicate status, :success?
    assert_match(/working tree must be clean/, output)
    assert_equal "0.1.0", read_version
  end

  def test_bump_rejects_a_non_increasing_version_with_zero_writes
    status, output = run_rake("bump[0.1.0]")
    refute_predicate status, :success?
    assert_match(/strictly greater/, output)
    assert_untouched

    status, output = run_rake("bump[0.0.9]")
    refute_predicate status, :success?
    assert_match(/strictly greater/, output)
    assert_untouched
  end

  def test_bump_rejects_a_malformed_repository_version
    write_version("01.2.3")
    git "add", "-A"
    git "commit", "--quiet", "--message", "malformed repository version"

    status, output = run_rake("bump[1.2.4]")
    refute_predicate status, :success?
    assert_match(/repository version is not exact semver/, output)
    assert_equal "01.2.3", read_version
  end

  def test_bump_rewrites_version_and_refreshes_the_lockfile
    add_bundler_fixture

    status, output = run_rake("bump[0.2.0]")
    assert_predicate status, :success?, -> { output }
    assert_equal "0.2.0", read_version
    assert_includes File.read(File.join(@work, "Gemfile.lock")), "surfguard (0.2.0)"
  end

  def test_bump_ignores_inherited_bundler_configuration
    add_bundler_fixture

    status, output = run_rake("bump[0.2.0]", env: {
      "BUNDLE_GEMFILE" => File.join(@dir, "missing-gemfile"),
      "BUNDLE_PATH" => File.join(@dir, "attacker-bundle-path"),
      "BUNDLER_VERSION" => "99.99.99"
    })
    assert_predicate status, :success?, -> { output }
    assert_equal "0.2.0", read_version
  end

  def test_bump_restores_version_and_lockfile_when_bundle_fails
    add_bundler_fixture(fail_during_bump: true)
    original_version = File.binread(File.join(@work, "lib/surfguard/version.rb"))
    original_lock = File.binread(File.join(@work, "Gemfile.lock"))

    status, output = run_rake("bump[0.2.0]", env: { "SURFGUARD_BUMP_FAILURE" => "1" })
    refute_predicate status, :success?
    assert_match(/simulated bump failure/, output)
    assert_equal original_version, File.binread(File.join(@work, "lib/surfguard/version.rb"))
    assert_equal original_lock, File.binread(File.join(@work, "Gemfile.lock"))
  end

  def test_bump_rejects_a_lockfile_inconsistent_with_the_current_version
    add_bundler_fixture
    lockfile = File.join(@work, "Gemfile.lock")
    File.write(lockfile, File.read(lockfile).sub("surfguard (0.1.0)", "surfguard (9.9.9)"))
    git "add", "-A"
    git "commit", "--quiet", "--message", "inconsistent lockfile"
    original_version = File.binread(File.join(@work, "lib/surfguard/version.rb"))
    original_lock = File.binread(lockfile)

    status, output = run_rake("bump[0.2.0]")

    refute_predicate status, :success?
    assert_match(/lockfile did not record exactly the current surfguard/, output)
    assert_equal original_version, File.binread(File.join(@work, "lib/surfguard/version.rb"))
    assert_equal original_lock, File.binread(lockfile)
  end

  def test_bump_rejects_a_nonliteral_version_declaration
    add_bundler_fixture
    File.write(File.join(@work, "lib/surfguard/version.rb"), <<~RUBY)
      module Surfguard
        VERSION = String.new("0.1.0")
      end
    RUBY
    original = File.binread(File.join(@work, "lib/surfguard/version.rb"))
    git "add", "-A"
    git "commit", "--quiet", "--message", "nonliteral version"

    status, output = run_rake("bump[0.2.0]")
    refute_predicate status, :success?
    assert_match(/version declaration was not exact/, output)
    assert_equal original, File.binread(File.join(@work, "lib/surfguard/version.rb"))
  end

  def test_bump_rejects_a_staged_lockfile_that_did_not_take_the_new_version
    add_bundler_fixture
    gemspec = File.join(@work, "surfguard.gemspec")
    File.write(gemspec, File.read(gemspec).sub("spec.version = Surfguard::VERSION", 'spec.version = "0.1.0"'))
    git "add", "-A"
    git "commit", "--quiet", "--message", "hardcoded gem version"

    status, output = run_rake("bump[0.2.0]")
    refute_predicate status, :success?
    assert_match(/lockfile did not record exactly surfguard 0\.2\.0/, output)
    assert_equal "0.1.0", read_version
  end

  def test_bump_rejects_unexpected_untracked_state_in_final_validation
    add_bundler_fixture

    status, output = run_rake("bump[0.2.0]", env: { "SURFGUARD_INJECT_UNTRACKED_ON_STATUS" => "1" })
    refute_predicate status, :success?
    assert_match(/unexpected working tree state/, output)
    assert_equal "0.1.0", read_version
    assert_path_exists File.join(@work, "unexpected-untracked")
  end

  def test_bump_rejects_a_version_file_that_changes_meaning_outside_the_staging_directory
    add_bundler_fixture
    File.write(File.join(@work, "lib/surfguard/version.rb"), <<~RUBY)
      module Surfguard
        VERSION = "0.1.0"
        VERSION = "0.1.0" unless File.expand_path(__dir__).include?("surfguard-bump")
      end
    RUBY
    git "add", "-A"
    git "commit", "--quiet", "--message", "path-dependent version"

    status, output = run_rake("bump[0.2.0]")
    refute_predicate status, :success?
    assert_match(/resulting version is invalid/, output)
    assert_equal "0.1.0", read_version
  end

  # --- tag guards -------------------------------------------------------------

  def test_tag_rejects_a_dirty_tree
    File.write(File.join(@work, "scratch.txt"), "dirt\n")
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/working tree must be clean/, output)
    assert_no_tags
  end

  def test_tag_rejects_running_off_main
    git "checkout", "--quiet", "-b", "feature"
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/must be on main/, output)
    assert_no_tags
  end

  def test_tag_rejects_an_unpushed_head
    File.write(File.join(@work, "new.txt"), "ahead\n")
    git "add", "-A"
    git "commit", "--quiet", "--message", "ahead of origin"
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/reconcile first/, output)
    assert_no_tags
  end

  def test_tag_rejects_an_existing_local_tag
    git "tag", "v0.1.0"
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/not the exact retryable annotated tag/, output)
    assert_empty tags_on_origin
  end

  def test_tag_rejects_an_existing_remote_tag
    git "tag", "v0.1.0"
    git "push", "--quiet", "origin", "refs/tags/v0.1.0"
    git "tag", "--delete", "v0.1.0"
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/already exists on origin/, output)
  end

  def test_tag_rejects_a_noncanonical_or_mismatched_origin
    git "remote", "set-url", "origin", "ext::sh -c exploit"
    git "remote", "set-url", "--push", "origin", "ext::sh -c exploit"

    status, output = run_rake("tag", env: { "SURFGUARD_EXPOSE_REMOTE" => "1" })
    refute_predicate status, :success?
    assert_match(/canonical basecamp\/surfguard/, output)
    assert_no_tags
  end

  def test_tag_rejects_different_fetch_and_push_urls
    status, output = run_rake("tag", env: { "SURFGUARD_MISMATCH_REMOTE" => "1" })

    refute_predicate status, :success?
    assert_match(/fetch\/push URLs differ/, output)
    assert_no_tags
  end

  def test_tag_rejects_git_command_failure
    status, output = run_rake("tag", env: { "SURFGUARD_FAIL_GIT_STATUS" => "1" })

    refute_predicate status, :success?
    assert_match(/git status failed/, output)
    assert_no_tags
  end

  def test_tag_rejects_a_malformed_repository_version
    write_version("01.2.3")
    git "add", "-A"
    git "commit", "--quiet", "--message", "malformed tag version"

    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/repository version is not exact semver/, output)
    assert_no_tags
  end

  def test_hostile_preload_cannot_override_the_canonical_push_url
    preload = File.join(@dir, "hostile-preload.rb")
    File.write(preload, 'CANONICAL_PUSH_URL = "https://attacker.invalid"')
    rubyopt = "-r#{BOOTSTRAP} -r#{preload}"

    status, output = run_rake("tag", env: { "RUBYOPT" => rubyopt })
    assert_predicate status, :success?, -> { output }
    assert_includes tags_on_origin, "v0.1.0"
    assert_match(/already initialized constant CANONICAL_PUSH_URL/, output)
  end

  def test_tag_pushes_main_then_the_tag_on_success
    status, output = run_rake("tag")
    assert_predicate status, :success?, -> { output }
    assert_includes tags_on_origin, "v0.1.0"
    assert_match(/release workflow takes it from here/, output)
  end

  def test_tag_retries_an_exact_local_annotated_tag_when_remote_is_absent
    git "tag", "--annotate", "v0.1.0", "--message", "surfguard v0.1.0"
    status, output = run_rake("tag")
    assert_predicate status, :success?, -> { output }
    assert_includes tags_on_origin, "v0.1.0"
  end

  def test_tag_explicitly_creates_the_accepted_unsigned_tag_even_if_signing_is_configured
    git "config", "tag.gpgSign", "true"

    status, output = run_rake("tag")

    assert_predicate status, :success?, -> { output }
    object = capture_git("cat-file", "tag", "v0.1.0")
    assert_includes object, "\nsurfguard v0.1.0\n"
    refute_includes object, "BEGIN PGP SIGNATURE"
  end

  def test_tag_rejects_annotated_retry_with_extra_message_whitespace
    git "tag", "--annotate", "v0.1.0", "--message", "surfguard v0.1.0", "--message", "extra"
    status, output = run_rake("tag")
    refute_predicate status, :success?
    assert_match(/not the exact retryable annotated tag/, output)
    assert_empty tags_on_origin
  end

  def test_rubocop_task_uses_the_argv_form_even_when_the_fixture_has_no_bundle
    status, output = run_rake("rubocop")

    refute_predicate status, :success?
    assert_match(/bundle.*exec.*rubocop|Could not locate Gemfile/, output)
  end

  def test_rakefile_assignment_is_covered_without_the_test_override
    had_original = Object.const_defined?(:CANONICAL_PUSH_URL)
    original = Object.const_get(:CANONICAL_PUSH_URL) if had_original
    Object.send(:remove_const, :CANONICAL_PUSH_URL) if had_original

    load RAKEFILE
    assert_equal "https://github.com/basecamp/surfguard", CANONICAL_PUSH_URL
  ensure
    Object.send(:remove_const, :CANONICAL_PUSH_URL) if Object.const_defined?(:CANONICAL_PUSH_URL)
    Object.const_set(:CANONICAL_PUSH_URL, original) if had_original
  end

  private
    def git(*args)
      system("git", "-C", @work, *args, exception: true, out: File::NULL)
    end

    def capture_git(*args)
      output, status = Open3.capture2e("git", "-C", @work, *args)
      raise output unless status.success?

      output
    end

    # A minimal gemspec + Gemfile + lock so bump's `bundle install` has a
    # real lockfile to refresh. No remote dependencies, so this stays offline.
    def add_bundler_fixture(fail_during_bump: false)
      File.write(File.join(@work, "surfguard.gemspec"), <<~RUBY)
        # frozen_string_literal: true

        require_relative "lib/surfguard/version"
        raise "simulated bump failure" if #{fail_during_bump} && ENV["SURFGUARD_BUMP_FAILURE"]

        Gem::Specification.new do |spec|
          spec.name    = "surfguard"
          spec.version = Surfguard::VERSION
          spec.summary = "fixture"
          spec.authors = [ "test" ]
        end
      RUBY
      File.write(File.join(@work, "Gemfile"), <<~RUBY)
        # frozen_string_literal: true

        source "https://rubygems.org"

        gemspec
      RUBY
      system(clean_env, "bundle", "install", "--quiet", chdir: @work, exception: true)
      git "add", "-A"
      git "commit", "--quiet", "--message", "bundler fixture"
    end

    # Scrub every bundler/ruby knob the surrounding `bundle exec` exported,
    # so subprocesses see the fixture repo the way a developer's shell would.
    def clean_env
      env = ENV.keys.grep(/\ABUNDLE/).to_h { |key| [ key, nil ] }
      env.merge(
        "RUBYOPT" => "-r#{BOOTSTRAP}", "RUBYLIB" => nil, "RUBYGEMS_GEMDEPS" => nil,
        "PATH" => "#{@fake_bin}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}",
        "SURFGUARD_REAL_GIT" => REAL_GIT, "SURFGUARD_TEST_ORIGIN" => @origin,
        "SURFGUARD_COVERAGE_ROOT" => (File.expand_path("../..", __dir__) if ENV["COVERAGE"])
      )
    end

    def run_rake(task, env: {})
      # Invoke rake as a library, not via its binstub: with the bundler
      # fixture's Gemfile.lock in place, RubyGems' binstub activation would
      # restrict `rake` to the fixture bundle (which has no rake).
      output, status = Open3.capture2e(
        clean_env.merge(env), Gem.ruby, "-rrake", "-e", "Rake.application.run",
        "--", "--rakefile", RAKEFILE, task, chdir: @work
      )
      [ status, output ]
    end

    def write_version(version)
      File.write(File.join(@work, "lib/surfguard/version.rb"), <<~RUBY)
        # frozen_string_literal: true

        module Surfguard
          VERSION = "#{version}"
        end
      RUBY
    end

    def read_version
      File.read(File.join(@work, "lib/surfguard/version.rb"))[/VERSION = "([^"]+)"/, 1]
    end

    def assert_untouched
      assert_equal "0.1.0", read_version
      output, status = Open3.capture2e("git", "-C", @work, "status", "--porcelain")
      assert_predicate status, :success?
      assert_empty output
    end

    def assert_no_tags
      output, status = Open3.capture2e("git", "-C", @work, "tag", "--list")
      assert_predicate status, :success?
      assert_empty output
      assert_empty tags_on_origin
    end

    def tags_on_origin
      output, status = Open3.capture2e("git", "-C", @origin, "tag", "--list")
      raise output unless status.success?

      output.split("\n")
    end
end
