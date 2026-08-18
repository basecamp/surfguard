# frozen_string_literal: true

require_relative "../test_helper"

require "base64"
require "fileutils"
require "json"
require "open3"
require "tmpdir"
require "yaml"

class DependabotWorkflowHarnessTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  WORKFLOW = File.join(ROOT, ".github/workflows/dependabot-auto-merge.yml")
  HEAD_SHA = "a" * 40
  BASE_SHA = "b" * 40
  REPOSITORY = "basecamp/surfguard"
  PR_NUMBER = "17"

  FAKE_GH = <<~'RUBY'
    #!/usr/bin/env ruby
    # frozen_string_literal: true

    require "base64"
    require "json"

    begin
    fixture = JSON.parse(File.binread(ENV.fetch("GH_FIXTURE")))
    state_path = ENV.fetch("GH_STATE")
    state = File.exist?(state_path) ? JSON.parse(File.binread(state_path)) : {}
    File.open(ENV.fetch("GH_LOG"), "ab") { |file| file.puts(JSON.generate(ARGV)) }

    take = lambda do |key|
      values = fixture.fetch(key)
      index = state.fetch(key, 0)
      state[key] = index + 1
      values.fetch([ index, values.length - 1 ].min)
    end

    if ARGV.first == "api"
      endpoint = ARGV.find { |argument| argument.start_with?("repos/") }
      abort "missing API endpoint" unless endpoint

      case endpoint
      when %r{/pulls/\d+\z}
        puts JSON.generate(take.call("prs"))
      when %r{/pulls/\d+/commits\z}
        puts JSON.generate([ take.call("commits") ])
      when %r{/pulls/\d+/files\z}
        puts fixture.fetch("files").join("\n")
      when %r{/contents/(.+)\?ref=(.+)\z}
        # Exact-ref fetching is the trust boundary: serve only the validator at
        # the base SHA and the two lockfiles at their own SHAs, each with a
        # distinguishable body the served validator itself asserts, so a
        # workflow that fetched from the wrong ref or swapped base/head fails.
        path = Regexp.last_match(1)
        ref = Regexp.last_match(2)
        base_sha = "b" * 40
        head_sha = "a" * 40
        content = case [ path, ref ]
        when [ ".github/scripts/validate_dependabot_lockfile.rb", base_sha ]
          "abort 'unexpected validator arguments' unless ARGV.length == 4\n" \
          "abort 'wrong base lockfile bytes' unless File.read(ARGV[0]) == \"base lock@#{base_sha}\\n\"\n" \
          "abort 'wrong head lockfile bytes' unless File.read(ARGV[1]) == \"head lock@#{head_sha}\\n\"\n"
        when [ "Gemfile.lock", base_sha ]
          "base lock@#{base_sha}\n"
        when [ "Gemfile.lock", head_sha ]
          "head lock@#{head_sha}\n"
        else
          abort "unexpected contents fetch: #{path} at #{ref}"
        end
        puts Base64.strict_encode64(content)
      when %r{/pulls/\d+/reviews\z}
        puts '{"id":1}'
      else
        abort "unexpected API endpoint: #{endpoint}"
      end
    elsif ARGV.first(2) == [ "pr", "merge" ]
      puts "merge enabled"
    else
      abort "unexpected gh invocation: #{ARGV.inspect}"
    end
    ensure
      File.binwrite(state_path, JSON.generate(state)) if state_path && state
    end
  RUBY

  def setup
    @directory = Dir.mktmpdir("dependabot-workflow-harness")
    @bin = File.join(@directory, "bin")
    FileUtils.mkdir(@bin)
    fake_gh = File.join(@bin, "gh")
    File.binwrite(fake_gh, FAKE_GH)
    File.chmod(0o755, fake_gh)

    steps = YAML.safe_load_file(WORKFLOW, aliases: false).fetch("jobs").fetch("automerge").fetch("steps")
    @initial_script = steps.find { |step| step["name"]&.start_with?("Re-validate the PR") }.fetch("run")
    @boundary_script = steps.find { |step| step["name"]&.start_with?("Approve at the validated head") }.fetch("run")
    @fixture_path = File.join(@directory, "fixture.json")
    @state_path = File.join(@directory, "state.json")
    @log_path = File.join(@directory, "gh.jsonl")
    @github_output = File.join(@directory, "github-output")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def test_initial_validation_accepts_only_the_exact_trusted_shape
    write_fixture
    _stdout, stderr, status = run_script(@initial_script)

    assert_predicate status, :success?, stderr
    assert_includes File.binread(@github_output), "base_sha=#{BASE_SHA}\n"
  end

  def test_initial_validation_rejects_untrusted_pr_and_base_identities
    mutations = {
      closed: ->(pr) { pr["state"] = "closed" },
      draft: ->(pr) { pr["draft"] = true },
      author: ->(pr) { pr.dig("user")["login"] = "attacker" },
      base_repository: ->(pr) { pr.dig("base", "repo")["full_name"] = "attacker/fork" },
      base_ref: ->(pr) { pr.dig("base")["ref"] = "unprotected" },
      head_repository: ->(pr) { pr.dig("head", "repo")["full_name"] = "attacker/fork" },
      head_ref: ->(pr) { pr.dig("head")["ref"] = "feature/not-dependabot" },
      moved_head: ->(pr) { pr.dig("head")["sha"] = "c" * 40 },
      malformed_base_sha: ->(pr) { pr.dig("base")["sha"] = "b" * 40 + "\nINJECTED=1" }
    }

    mutations.each do |name, mutate|
      pr = valid_pr
      mutate.call(pr)
      write_fixture(prs: [ pr ])
      _stdout, _stderr, status = run_script(@initial_script)
      refute_predicate status, :success?, name
      refute privileged_call_logged?, name
    end
  end

  def test_initial_validation_rejects_file_and_commit_identity_failures
    commit_mutations = {
      wrong_tip: ->(commit) { commit["sha"] = "c" * 40 },
      author: ->(commit) { commit.dig("author")["login"] = "attacker" },
      committer: ->(commit) { commit.dig("committer")["login"] = "attacker" },
      committer_not_github_signer: ->(commit) { commit.dig("committer")["login"] = "dependabot[bot]" },
      signature: ->(commit) { commit.dig("commit", "verification")["verified"] = false }
    }

    commit_mutations.each do |name, mutate|
      commit = valid_commit
      mutate.call(commit)
      write_fixture(commits: [ [ commit ] ])
      _stdout, _stderr, status = run_script(@initial_script)
      refute_predicate status, :success?, name
      refute privileged_call_logged?, name
    end

    write_fixture(files: [ "Gemfile.lock", "Gemfile" ])
    _stdout, _stderr, status = run_script(@initial_script)
    refute_predicate status, :success?
    refute privileged_call_logged?
  end

  def test_valid_identity_is_rechecked_before_approval_and_merge
    write_fixture(prs: [ valid_pr, valid_pr ], commits: [ [ valid_commit ], [ valid_commit ] ])
    _stdout, stderr, status = run_script(@boundary_script, "VALIDATED_BASE_SHA" => BASE_SHA)

    assert_predicate status, :success?, stderr
    calls = logged_calls
    assert_equal 2, calls.count { |call| pull_request_read?(call) }
    assert_equal 2, calls.count { |call| commits_read?(call) }
    assert_equal 1, calls.count { |call| review_created?(call) }
    assert_equal 1, calls.count { |call| call.first(2) == [ "pr", "merge" ] }
  end

  def test_each_identity_guard_fails_closed_before_approval
    mutations = {
      closed: ->(pr) { pr["state"] = "closed" },
      draft: ->(pr) { pr["draft"] = true },
      author: ->(pr) { pr.dig("user")["login"] = "attacker" },
      base_repository: ->(pr) { pr.dig("base", "repo")["full_name"] = "attacker/fork" },
      base_ref: ->(pr) { pr.dig("base")["ref"] = "unprotected" },
      base_sha: ->(pr) { pr.dig("base")["sha"] = "c" * 40 },
      head_repository: ->(pr) { pr.dig("head", "repo")["full_name"] = "attacker/fork" },
      head_ref: ->(pr) { pr.dig("head")["ref"] = "feature/not-dependabot" },
      head_sha: ->(pr) { pr.dig("head")["sha"] = "c" * 40 }
    }

    mutations.each do |name, mutate|
      pr = valid_pr
      mutate.call(pr)
      write_fixture(prs: [ pr ])
      _stdout, _stderr, status = run_script(@boundary_script, "VALIDATED_BASE_SHA" => BASE_SHA)
      refute_predicate status, :success?, name
      refute privileged_call_logged?, name
    end
  end

  def test_commit_identity_guards_fail_closed_before_approval
    mutations = {
      wrong_tip: ->(commit) { commit["sha"] = "c" * 40 },
      author: ->(commit) { commit.dig("author")["login"] = "attacker" },
      committer: ->(commit) { commit.dig("committer")["login"] = "attacker" },
      signature: ->(commit) { commit.dig("commit", "verification")["verified"] = false }
    }

    mutations.each do |name, mutate|
      commit = valid_commit
      mutate.call(commit)
      write_fixture(commits: [ [ commit ] ])
      _stdout, _stderr, status = run_script(@boundary_script, "VALIDATED_BASE_SHA" => BASE_SHA)
      refute_predicate status, :success?, name
      refute privileged_call_logged?, name
    end
  end

  def test_identity_or_signature_change_after_approval_prevents_merge
    second_pr = valid_pr
    second_pr.dig("base")["ref"] = "unprotected"
    second_commit = valid_commit
    second_commit.dig("commit", "verification")["verified"] = false

    fixtures = [
      { prs: [ valid_pr, second_pr ], commits: [ [ valid_commit ] ] },
      { prs: [ valid_pr, valid_pr ], commits: [ [ valid_commit ], [ second_commit ] ] }
    ]
    fixtures.each do |fixture|
      write_fixture(**fixture)
      _stdout, _stderr, status = run_script(@boundary_script, "VALIDATED_BASE_SHA" => BASE_SHA)
      refute_predicate status, :success?
      assert logged_calls.any? { |call| review_created?(call) }
      refute logged_calls.any? { |call| call.first(2) == [ "pr", "merge" ] }
    end
  end

  private
    def valid_pr
      {
        "state" => "open",
        "draft" => false,
        "user" => { "login" => "dependabot[bot]" },
        "head" => {
          "ref" => "dependabot/bundler/rack-3.2.7",
          "sha" => HEAD_SHA,
          "repo" => { "full_name" => REPOSITORY }
        },
        "base" => {
          "ref" => "main",
          "sha" => BASE_SHA,
          "repo" => { "full_name" => REPOSITORY }
        }
      }
    end

    def valid_commit
      # Live Dependabot commits are authored by the bot but committed by
      # GitHub's signer (web-flow); the workflow requires exactly that shape.
      {
        "sha" => HEAD_SHA,
        "author" => { "login" => "dependabot[bot]" },
        "committer" => { "login" => "web-flow" },
        "commit" => { "verification" => { "verified" => true } }
      }
    end

    def write_fixture(prs: [ valid_pr ], commits: [ [ valid_commit ] ], files: [ "Gemfile.lock" ])
      File.binwrite(@fixture_path, JSON.generate("prs" => prs, "commits" => commits, "files" => files))
      [ @state_path, @log_path, @github_output ].each { |path| FileUtils.rm_f(path) }
      File.binwrite(@github_output, "")
    end

    def run_script(script, extra_environment = {})
      environment = {
        "PATH" => "#{@bin}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}",
        "GH_FIXTURE" => @fixture_path,
        "GH_STATE" => @state_path,
        "GH_LOG" => @log_path,
        "GITHUB_OUTPUT" => @github_output,
        "GH_TOKEN" => "fixture",
        "REPO" => REPOSITORY,
        "PR_NUMBER" => PR_NUMBER,
        "PR_URL" => "https://github.com/#{REPOSITORY}/pull/#{PR_NUMBER}",
        "EVENT_HEAD_SHA" => HEAD_SHA,
        "EVENT_ACTOR" => "dependabot[bot]",
        "EVENT_TRIGGERING_ACTOR" => "dependabot[bot]",
        "METADATA_ECOSYSTEM" => "bundler",
        "METADATA_UPDATE_TYPE" => "version-update:semver-patch"
      }.merge(extra_environment)
      Open3.capture3(environment, "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script,
        chdir: @directory)
    end

    def logged_calls
      return [] unless File.exist?(@log_path)

      File.readlines(@log_path, chomp: true).map { |line| JSON.parse(line) }
    end

    def pull_request_read?(call)
      call.first == "api" && call.any? { |argument| argument.end_with?("/pulls/#{PR_NUMBER}") }
    end

    def commits_read?(call)
      call.first == "api" && call.any? { |argument| argument.end_with?("/pulls/#{PR_NUMBER}/commits") }
    end

    def review_created?(call)
      call.first == "api" && call.include?("POST") &&
        call.any? { |argument| argument.end_with?("/pulls/#{PR_NUMBER}/reviews") }
    end

    def privileged_call_logged?
      logged_calls.any? { |call| review_created?(call) || call.first(2) == [ "pr", "merge" ] }
    end
end
