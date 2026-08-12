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

  def setup
    @dir = Dir.mktmpdir("rake-tasks-test")
    @work = File.join(@dir, "work")
    @origin = File.join(@dir, "origin.git")

    FileUtils.mkdir_p(File.join(@work, "lib/surfguard"))
    FileUtils.cp(RAKEFILE, File.join(@work, "Rakefile"))
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
    status, output = run_rake("bump[banana]")
    refute_predicate status, :success?
    assert_match(/must be exact semver/, output)
    assert_untouched
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
    assert_match(/already exists locally/, output)
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

  def test_tag_pushes_main_then_the_tag_on_success
    status, output = run_rake("tag")
    assert_predicate status, :success?, -> { output }
    assert_includes tags_on_origin, "v0.1.0"
    assert_match(/release workflow takes it from here/, output)
  end

  private
    def git(*args)
      system("git", "-C", @work, *args, exception: true, out: File::NULL)
    end

    def run_rake(task)
      env = {
        "BUNDLE_GEMFILE" => nil, "BUNDLE_PATH" => nil, "BUNDLE_BIN" => nil,
        "RUBYOPT" => nil, "RUBYLIB" => nil
      }
      output, status = Open3.capture2e(env, Gem.ruby, "-S", "rake", "--rakefile", "Rakefile", task, chdir: @work)
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
      assert_empty `git -C #{@work} status --porcelain`
    end

    def assert_no_tags
      assert_empty `git -C #{@work} tag --list`
      assert_empty tags_on_origin
    end

    def tags_on_origin
      `git -C #{@origin} tag --list`.split("\n")
    end
end
