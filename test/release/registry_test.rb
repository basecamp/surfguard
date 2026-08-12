# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../script/release/registry"

require "digest"
require "json"
require "stringio"
require "tmpdir"

# Fixture tests for every transition of the registry state machine. The HTTP
# layer is scripted: each test declares the exact sequence of responses (or
# network faults) the registry will see, and asserts the one defined outcome.
class RegistryTest < Minitest::Test
  Registry = Surfguard::Release::Registry

  NAME = "surfguard"
  VERSION = "0.1.0"
  BYTES = "canonical gem bytes"
  DIGEST = Digest::SHA256.hexdigest(BYTES)
  OTHER_SHA = ("f" * 64).freeze

  VERSION_URL = "https://rubygems.org/api/v2/rubygems/surfguard/versions/0.1.0.json"
  GEM_URL = "https://rubygems.org/gems/surfguard-0.1.0.gem"

  # --- check: the publish job's decision ------------------------------------

  def test_check_404_means_version_absent_so_push
    registry = scripted(res(404))
    assert_equal :push, registry.check(VERSION, DIGEST)
    assert_equal [ VERSION_URL ], @requests
  end

  def test_check_200_with_our_sha_means_already_published_so_skip
    registry = scripted(res(200, version_json))
    assert_equal :skip, registry.check(VERSION, DIGEST)
  end

  def test_check_normalizes_sha_case
    registry = scripted(res(200, version_json))
    assert_equal :skip, registry.check(VERSION, DIGEST.upcase)
  end

  def test_check_200_with_different_sha_fails_closed
    registry = scripted(res(200, version_json(sha: OTHER_SHA)))
    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_match(/already published/, error.message)
  end

  def test_check_200_for_a_different_version_fails_closed
    registry = scripted(res(200, version_json(number: "9.9.9")))
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_malformed_json_fails_closed
    registry = scripted(res(200, "<html>surprise!</html>"))
    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_match(/malformed JSON/, error.message)
  end

  def test_check_non_hash_json_fails_closed
    registry = scripted(res(200, [ 1, 2 ].to_json))
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_missing_sha_fails_closed
    registry = scripted(res(200, { "number" => VERSION }.to_json))
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_unusable_sha_fails_closed
    registry = scripted(res(200, version_json(sha: "not-a-digest")))
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_rejects_invalid_input_sha
    registry = scripted
    assert_raises(Registry::Error) { registry.check(VERSION, "banana") }
    assert_empty @requests
  end

  def test_check_retries_through_429_with_backoff
    registry = scripted(res(429), res(429), res(404))
    assert_equal :push, registry.check(VERSION, DIGEST)
    assert_equal [ 2, 4 ], @slept
  end

  def test_check_retries_through_5xx_and_network_faults
    registry = scripted(res(503), Net::ReadTimeout.new, res(404))
    assert_equal :push, registry.check(VERSION, DIGEST)
  end

  def test_check_persistent_429_fails_after_bounded_retries
    registry = scripted([ res(429) ] * Registry::MAX_ATTEMPTS)
    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_match(/after #{Registry::MAX_ATTEMPTS} attempts/, error.message)
    assert_equal Registry::MAX_ATTEMPTS, @requests.size
  end

  def test_check_persistent_5xx_fails_after_bounded_retries
    registry = scripted([ res(500) ] * Registry::MAX_ATTEMPTS)
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_persistent_network_fault_fails_after_bounded_retries
    registry = scripted([ Net::OpenTimeout.new ] * Registry::MAX_ATTEMPTS)
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
  end

  def test_check_unexpected_status_fails_closed_without_retry
    registry = scripted(res(403))
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_equal 1, @requests.size
  end

  # --- confirm: bounded poll, then canonical-bytes verification -------------

  def test_confirm_polls_through_404_then_verifies_canonical_bytes
    registry = scripted(
      res(404), res(404),
      res(200, version_json),        # poll sees our version + sha
      res(200, version_json),        # verified_download re-reads metadata
      res(200, BYTES)                # canonical bytes
    )
    assert_equal BYTES, registry.confirm(VERSION, DIGEST)
    assert_equal [ VERSION_URL, VERSION_URL, VERSION_URL, VERSION_URL, GEM_URL ], @requests
  end

  def test_confirm_times_out_when_version_never_appears
    registry = scripted([ res(404) ] * 10)
    error = assert_raises(Registry::Error) { registry.confirm(VERSION, DIGEST, deadline: 12) }
    assert_match(/gave up waiting/, error.message)
  end

  def test_confirm_fails_immediately_on_different_published_sha
    registry = scripted(res(200, version_json(sha: OTHER_SHA)))
    error = assert_raises(Registry::Error) { registry.confirm(VERSION, DIGEST) }
    assert_match(/stopping for a human/, error.message)
  end

  def test_confirm_retries_malformed_bodies_within_bounds
    registry = scripted(
      res(200, "not json"), res(200, "still not json"),
      res(200, version_json),
      res(200, version_json), res(200, BYTES)
    )
    assert_equal BYTES, registry.confirm(VERSION, DIGEST)
  end

  def test_confirm_fails_after_persistent_malformed_bodies
    registry = scripted([ res(200, "not json") ] * Registry::MALFORMED_LIMIT)
    error = assert_raises(Registry::Error) { registry.confirm(VERSION, DIGEST) }
    assert_match(/malformed JSON/, error.message)
  end

  def test_confirm_malformed_tolerance_is_consecutive_not_cumulative
    # MALFORMED_LIMIT malformed bodies arrive, but interleaved with healthy
    # non-malformed outcomes — the counter must reset each time.
    registry = scripted(
      res(200, "not json"), res(404),
      res(200, "not json"), res(503),
      res(200, "not json"), Net::ReadTimeout.new,
      res(200, version_json),
      res(200, version_json), res(200, BYTES)
    )
    assert_equal BYTES, registry.confirm(VERSION, DIGEST)
  end

  def test_confirm_backs_off_through_429_5xx_and_network_faults_while_polling
    registry = scripted(
      res(429), res(503), Net::ReadTimeout.new,
      res(200, version_json),
      res(200, version_json), res(200, BYTES)
    )
    assert_equal BYTES, registry.confirm(VERSION, DIGEST)
  end

  def test_confirm_fails_closed_on_unexpected_status_while_polling
    registry = scripted(res(302, "", location: "https://elsewhere.example/"))
    assert_raises(Registry::Error) { registry.confirm(VERSION, DIGEST) }
  end

  def test_confirm_fails_when_registry_flips_sha_between_poll_and_download
    flipped_bytes = "someone else's bytes"
    flipped = version_json(sha: Digest::SHA256.hexdigest(flipped_bytes))
    registry = scripted(
      res(200, version_json),   # poll: matches ours
      res(200, flipped),        # verified_download: registry now says otherwise
      res(200, flipped_bytes)
    )
    error = assert_raises(Registry::Error) { registry.confirm(VERSION, DIGEST) }
    assert_match(/does not match our artifact digest/, error.message)
  end

  # --- verified_download: the recovery path ---------------------------------

  def test_verified_download_returns_bytes_and_digest
    registry = scripted(res(200, version_json), res(200, BYTES))
    assert_equal [ BYTES, DIGEST ], registry.verified_download(VERSION)
    assert_equal [ VERSION_URL, GEM_URL ], @requests
  end

  def test_verified_download_requires_the_version_to_be_published
    registry = scripted(res(404))
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/expected surfguard 0\.1\.0 to be published/, error.message)
  end

  def test_verified_download_fails_when_bytes_do_not_match_registry_sha
    registry = scripted(res(200, version_json), res(200, "tampered bytes"))
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/does not match registry-reported/, error.message)
  end

  def test_verified_download_follows_https_redirects
    registry = scripted(
      res(200, version_json),
      res(302, "", location: "https://cdn.example/surfguard-0.1.0.gem"),
      res(200, BYTES)
    )
    assert_equal [ BYTES, DIGEST ], registry.verified_download(VERSION)
    assert_equal "https://cdn.example/surfguard-0.1.0.gem", @requests.last
  end

  def test_verified_download_bounds_redirects
    hops = [ res(200, version_json) ]
    (Registry::MAX_REDIRECTS + 1).times { hops << res(301, "", location: "https://cdn.example/hop") }
    registry = scripted(hops)
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/too many redirects/, error.message)
  end

  def test_verified_download_resolves_relative_redirects_against_the_current_uri
    registry = scripted(
      res(200, version_json),
      res(302, "", location: "/downloads/surfguard-0.1.0.gem"),
      res(200, BYTES)
    )
    assert_equal [ BYTES, DIGEST ], registry.verified_download(VERSION)
    assert_equal "https://rubygems.org/downloads/surfguard-0.1.0.gem", @requests.last
  end

  def test_verified_download_resolves_scheme_relative_redirects_as_https
    registry = scripted(
      res(200, version_json),
      res(302, "", location: "//cdn.example/surfguard-0.1.0.gem"),
      res(200, BYTES)
    )
    assert_equal [ BYTES, DIGEST ], registry.verified_download(VERSION)
    assert_equal "https://cdn.example/surfguard-0.1.0.gem", @requests.last
  end

  def test_verified_download_rejects_unparseable_redirect_location
    registry = scripted(res(200, version_json), res(302, "", location: "http://["))
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/unusable redirect location/, error.message)
  end

  def test_verified_download_rejects_redirect_without_location
    registry = scripted(res(200, version_json), res(302, ""))
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
  end

  def test_verified_download_rejects_redirect_with_empty_location
    registry = scripted(res(200, version_json), res(302, "", location: ""))
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
  end

  def test_verified_download_rejects_non_https_redirect
    registry = scripted(res(200, version_json), res(302, "", location: "http://cdn.example/gem"))
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/non-https/, error.message)
  end

  def test_verified_download_fails_closed_on_unexpected_download_status
    registry = scripted(res(200, version_json), res(403))
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
  end

  # --- CLI entry points ------------------------------------------------------

  def test_run_check_prints_the_decision_and_exits_zero
    registry = scripted(res(404))
    out, err = capture
    status = Registry.run_check([ NAME, VERSION, DIGEST ], out: out, err: err, registry_for: for_name(registry))
    assert_equal 0, status
    assert_equal "push\n", out.string
  end

  def test_run_check_usage_error_exits_two
    out, err = capture
    status = Registry.run_check([ NAME ], out: out, err: err, registry_for: for_name(scripted))
    assert_equal 2, status
    assert_match(/usage/, err.string)
    assert_empty @requests
  end

  def test_run_check_failure_exits_one
    registry = scripted(res(200, version_json(sha: OTHER_SHA)))
    out, err = capture
    status = Registry.run_check([ NAME, VERSION, DIGEST ], out: out, err: err, registry_for: for_name(registry))
    assert_equal 1, status
    assert_match(/registry check failed/, err.string)
  end

  def test_run_confirm_succeeds_without_explicit_deadline
    registry = scripted(res(200, version_json), res(200, version_json), res(200, BYTES))
    out, err = capture
    status = Registry.run_confirm([ NAME, VERSION, DIGEST ], out: out, err: err, registry_for: for_name(registry))
    assert_equal 0, status
    assert_match(/confirmed/, out.string)
  end

  def test_run_confirm_accepts_a_numeric_deadline
    registry = scripted(res(200, version_json), res(200, version_json), res(200, BYTES))
    out, err = capture
    status = Registry.run_confirm([ NAME, VERSION, DIGEST, "60" ], out: out, err: err, registry_for: for_name(registry))
    assert_equal 0, status
  end

  def test_run_confirm_rejects_a_malformed_deadline
    out, err = capture
    status = Registry.run_confirm([ NAME, VERSION, DIGEST, "soonish" ], out: out, err: err, registry_for: for_name(scripted))
    assert_equal 2, status
    assert_match(/usage/, err.string)
  end

  def test_run_confirm_rejects_too_many_arguments
    out, err = capture
    status = Registry.run_confirm([ NAME, VERSION, DIGEST, "60", "extra" ], out: out, err: err, registry_for: for_name(scripted))
    assert_equal 2, status
  end

  def test_run_confirm_failure_exits_one
    registry = scripted(res(200, version_json(sha: OTHER_SHA)))
    out, err = capture
    status = Registry.run_confirm([ NAME, VERSION, DIGEST ], out: out, err: err, registry_for: for_name(registry))
    assert_equal 1, status
    assert_match(/registry confirmation failed/, err.string)
  end

  def test_run_download_writes_the_file_and_prints_the_digest
    registry = scripted(res(200, version_json), res(200, BYTES))
    out, err = capture
    Dir.mktmpdir do |dir|
      destination = File.join(dir, "surfguard-0.1.0.gem")
      status = Registry.run_download([ NAME, VERSION, destination ], out: out, err: err, registry_for: for_name(registry))
      assert_equal 0, status
      assert_equal BYTES, File.binread(destination)
      assert_equal "#{DIGEST}\n", out.string
    end
  end

  def test_run_download_usage_error_exits_two
    out, err = capture
    status = Registry.run_download([ NAME, VERSION ], out: out, err: err, registry_for: for_name(scripted))
    assert_equal 2, status
    assert_match(/usage/, err.string)
  end

  def test_run_download_failure_exits_one
    registry = scripted(res(404))
    out, err = capture
    Dir.mktmpdir do |dir|
      status = Registry.run_download([ NAME, VERSION, File.join(dir, "x.gem") ], out: out, err: err, registry_for: for_name(registry))
      assert_equal 1, status
      assert_match(/registry download failed/, err.string)
    end
  end

  private
    # Build a registry whose HTTP layer replays exactly these steps: a
    # Response is returned, an Exception is raised. Sleeps advance the fake
    # clock so deadline behavior is testable.
    def scripted(*steps)
      @requests = []
      @slept = []
      @now = 0.0
      queue = steps.flatten

      http = lambda do |uri|
        @requests << uri.to_s
        raise "HTTP script exhausted at request #{@requests.size}: #{uri}" if queue.empty?
        step = queue.shift
        step.is_a?(Exception) ? raise(step) : step
      end

      Registry.new(
        NAME,
        http: http,
        sleeper: lambda { |seconds|
          @slept << seconds
          @now += seconds
        },
        clock: -> { @now }
      )
    end

    def res(status, body = "", location: nil)
      Registry::Response.new(status, body, location)
    end

    def version_json(number: VERSION, sha: DIGEST)
      { "number" => number, "sha" => sha }.to_json
    end

    def capture
      [ StringIO.new, StringIO.new ]
    end

    def for_name(registry)
      lambda { |name|
        assert_equal NAME, name
        registry
      }
    end
end
