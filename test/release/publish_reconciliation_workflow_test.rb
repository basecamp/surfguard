# frozen_string_literal: true

require_relative "../test_helper"

require "json"
require "open3"
require "rbconfig"
require "tmpdir"
require "yaml"

# Executes the publish job's workflow-owned registry reconciliation verbatim.
# A minimal PATH makes accidentally reaching the network impossible through the
# named curl command, while scripted curl and sleep executables make every
# state-machine transition deterministic and fast.
class PublishReconciliationWorkflowTest < Minitest::Test
  STEP_ID = "reconcile"
  STEP_NAME = "Reconcile with the registry (total state machine; fails closed)"
  WORKFLOW_PATH = File.expand_path("../../.github/workflows/release.yml", __dir__)

  VERSION = "0.1.0"
  GEM_SHA256 = ("a" * 64).freeze
  OTHER_SHA256 = ("b" * 64).freeze
  REGISTRY_URL = "https://rubygems.org/api/v2/rubygems/surfguard/versions/0.1.0.json"

  RunResult = Struct.new(:stdout, :stderr, :status, :github_output, :curl_calls, :sleeps,
    keyword_init: true)

  def self.load_reconciliation_script
    workflow = YAML.safe_load(File.read(WORKFLOW_PATH), aliases: false)
    steps = workflow.fetch("jobs").fetch("publish").fetch("steps")
    matches = steps.select do |step|
      step.is_a?(Hash) && step["id"] == STEP_ID && step["name"] == STEP_NAME
    end

    raise "expected exactly one #{STEP_ID.inspect} / #{STEP_NAME.inspect} workflow step" unless matches.one?

    matches.first.fetch("run").freeze
  end
  private_class_method :load_reconciliation_script

  RECONCILIATION_SCRIPT = load_reconciliation_script

  def test_404_means_push
    result = run_reconciliation([ response(404) ])

    assert_success(result)
    assert_equal "decision=push\n", result.github_output
    assert_equal 1, result.curl_calls
    assert_empty result.sleeps
  end

  def test_matching_200_means_skip_and_normalizes_digest_case
    result = run_reconciliation([
      response(200, metadata(sha: GEM_SHA256.upcase))
    ])

    assert_success(result)
    assert_equal "decision=skip\n", result.github_output
    assert_equal 1, result.curl_calls
  end

  def test_conflicting_digest_fails_closed
    result = run_reconciliation([
      response(200, metadata(sha: OTHER_SHA256))
    ])

    assert_failure(result, /already published with sha256 #{OTHER_SHA256}/)
    assert_equal 1, result.curl_calls
  end

  def test_malformed_json_fails_closed
    result = run_reconciliation([ response(200, "not JSON") ])

    assert_failure(result, /RubyGems returned malformed version metadata/)
    assert_equal 1, result.curl_calls
  end

  def test_malformed_json_shape_fails_closed
    result = run_reconciliation([ response(200, JSON.generate([ VERSION, GEM_SHA256 ])) ])

    assert_failure(result, /RubyGems returned malformed version metadata/)
    assert_equal 1, result.curl_calls
  end

  def test_metadata_for_a_different_version_fails_closed
    result = run_reconciliation([
      response(200, metadata(version: "9.9.9"))
    ])

    assert_failure(result, /metadata for a different version; expected #{VERSION}/)
    assert_equal 1, result.curl_calls
  end

  def test_unexpected_status_fails_without_retrying
    result = run_reconciliation([ response(403) ])

    assert_failure(result, /Unexpected HTTP 403/)
    assert_equal 1, result.curl_calls
    assert_empty result.sleeps
  end

  def test_retryable_statuses_back_off_then_succeed
    result = run_reconciliation([
      response(429),
      response(503),
      response(404)
    ])

    assert_success(result)
    assert_equal "decision=push\n", result.github_output
    assert_equal 3, result.curl_calls
    assert_equal [ 2, 4 ], result.sleeps
  end

  def test_persistent_retryable_status_fails_after_five_attempts
    result = run_reconciliation(Array.new(5) { response(503) })

    assert_failure(result, /RubyGems unavailable after 5 attempts \(HTTP 503\)/)
    assert_equal 5, result.curl_calls
    assert_equal [ 2, 4, 6, 8 ], result.sleeps
  end

  def test_persistent_network_failure_fails_after_five_attempts
    result = run_reconciliation(Array.new(5) { network_failure })

    assert_failure(result, /RubyGems unavailable after 5 attempts \(network failure\)/)
    assert_equal 5, result.curl_calls
    assert_equal [ 2, 4, 6, 8 ], result.sleeps
  end

  private

  def run_reconciliation(fixtures)
    Dir.mktmpdir("surfguard-reconcile-test") do |directory|
      bin_directory = File.join(directory, "bin")
      Dir.mkdir(bin_directory)
      install_real_commands(bin_directory)
      install_fake_curl(bin_directory)
      install_fake_sleep(bin_directory)

      fixtures_path = File.join(directory, "curl-fixtures")
      curl_index_path = File.join(directory, "curl-index")
      sleep_log_path = File.join(directory, "sleep-log")
      github_output_path = File.join(directory, "github-output")
      File.binwrite(fixtures_path, Marshal.dump(fixtures))
      File.write(curl_index_path, "0")
      File.write(sleep_log_path, "")
      File.write(github_output_path, "")

      stdout, stderr, status = Open3.capture3(
        isolated_environment(
          directory: directory,
          bin_directory: bin_directory,
          fixtures_path: fixtures_path,
          curl_index_path: curl_index_path,
          sleep_log_path: sleep_log_path,
          github_output_path: github_output_path
        ),
        executable("bash"), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
        RECONCILIATION_SCRIPT,
        chdir: directory,
        unsetenv_others: true
      )

      RunResult.new(
        stdout: stdout,
        stderr: stderr,
        status: status,
        github_output: File.read(github_output_path),
        curl_calls: Integer(File.read(curl_index_path)),
        sleeps: File.readlines(sleep_log_path, chomp: true).map(&:to_i)
      )
    end
  end

  def isolated_environment(directory:, bin_directory:, fixtures_path:, curl_index_path:,
    sleep_log_path:, github_output_path:)
    {
      "PATH" => bin_directory,
      "HOME" => directory,
      "TMPDIR" => directory,
      "VERSION" => VERSION,
      "GEM_SHA256" => GEM_SHA256,
      "GITHUB_OUTPUT" => github_output_path,
      "CURL_FIXTURES" => fixtures_path,
      "CURL_INDEX" => curl_index_path,
      "SLEEP_LOG" => sleep_log_path,
      "EXPECTED_REGISTRY_URL" => REGISTRY_URL,
      # Defense in depth if a future edit bypasses the fake curl by using an
      # absolute path: external HTTP(S) still cannot leave through a proxy.
      "HTTP_PROXY" => "http://127.0.0.1:1",
      "HTTPS_PROXY" => "http://127.0.0.1:1",
      "ALL_PROXY" => "http://127.0.0.1:1"
    }
  end

  def install_real_commands(bin_directory)
    %w[jq mktemp rm].each do |command|
      File.symlink(executable(command), File.join(bin_directory, command))
    end
  end

  def install_fake_curl(bin_directory)
    write_executable(File.join(bin_directory, "curl"), <<~RUBY)
      #!#{RbConfig.ruby}
      fixtures = Marshal.load(File.binread(ENV.fetch("CURL_FIXTURES")))
      index_path = ENV.fetch("CURL_INDEX")
      index = Integer(File.read(index_path))
      fixture = fixtures.fetch(index)
      File.write(index_path, (index + 1).to_s)

      output_index = ARGV.index("--output")
      abort "fake curl requires --output" unless output_index
      abort "unexpected registry URL" unless ARGV.last == ENV.fetch("EXPECTED_REGISTRY_URL")

      File.binwrite(ARGV.fetch(output_index + 1), fixture.fetch(:body, ""))
      $stderr.write(fixture.fetch(:stderr, ""))
      $stdout.write(fixture.fetch(:status, "").to_s)
      exit fixture.fetch(:exit_status, 0)
    RUBY
  end

  def install_fake_sleep(bin_directory)
    write_executable(File.join(bin_directory, "sleep"), <<~RUBY)
      #!#{RbConfig.ruby}
      abort "fake sleep requires one argument" unless ARGV.length == 1
      File.open(ENV.fetch("SLEEP_LOG"), "a") { |file| file.puts(ARGV.first) }
    RUBY
  end

  def write_executable(path, contents)
    File.write(path, contents)
    File.chmod(0o700, path)
  end

  def executable(command)
    ENV.fetch("PATH").split(File::PATH_SEPARATOR).each do |directory|
      path = File.join(directory, command)
      return File.realpath(path) if File.file?(path) && File.executable?(path)
    end

    raise "required executable not found: #{command}"
  end

  def response(status, body = "")
    { status: status.to_s, body: body }
  end

  def network_failure
    {
      status: "000",
      stderr: "curl: simulated network failure\n",
      exit_status: 7
    }
  end

  def metadata(version: VERSION, sha: GEM_SHA256)
    JSON.generate("number" => version, "sha" => sha)
  end

  def assert_success(result)
    assert result.status.success?, failure_diagnostics(result)
  end

  def assert_failure(result, message_pattern)
    refute result.status.success?, "expected workflow step to fail"
    assert_empty result.github_output
    assert_match message_pattern, result.stdout
  end

  def failure_diagnostics(result)
    <<~MESSAGE
      workflow step unexpectedly failed (#{result.status.exitstatus})
      stdout:
      #{result.stdout}
      stderr:
      #{result.stderr}
    MESSAGE
  end
end
