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

  class FakeNetResponse
    attr_reader :code

    def initialize(status, chunks = [], headers = {}, before_chunk: nil)
      @code = status.to_s
      @chunks = chunks
      @headers = headers.transform_keys(&:downcase)
      @before_chunk = before_chunk
    end

    def [](name)
      @headers[name.downcase]
    end

    def read_body
      @chunks.each do |chunk|
        @before_chunk&.call
        yield chunk
      end
    end
  end

  class FakeHTTPClient
    attr_accessor :use_ssl, :verify_mode, :verify_hostname, :ipaddr, :open_timeout, :read_timeout
    attr_reader :requests

    def initialize(queue)
      @queue = queue
      @requests = []
    end

    def start
      yield self
    end

    def request(request)
      @requests << request
      step = @queue.shift
      raise "fake HTTP queue exhausted" unless step

      step = step.call if step.respond_to?(:call)
      raise step if step.is_a?(Exception)

      yield step
    end
  end

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

  def test_metadata_declared_and_actual_lengths_are_bounded
    declared = Registry::Response.new(200, version_json, nil, (Registry::METADATA_LIMIT + 1).to_s)
    assert_raises(Registry::Error) { scripted(declared).check(VERSION, DIGEST) }
    oversized = res(200, "x" * (Registry::METADATA_LIMIT + 1))
    assert_raises(Registry::Error) { scripted(oversized).check(VERSION, DIGEST) }
  end

  def test_declared_length_must_be_strict_digits_and_match_actual_bytes
    body = version_json
    [ "-1", "+1", " 1", "1, 1", "1x" ].each do |declared|
      response = Registry::Response.new(200, body, nil, declared)
      assert_raises(Registry::Error, declared) { scripted(response).check(VERSION, DIGEST) }
    end

    response = Registry::Response.new(200, body, nil, (body.bytesize + 1).to_s)
    error = assert_raises(Registry::Error) { scripted(response).check(VERSION, DIGEST) }
    assert_match(/does not match/, error.message)

    response = Registry::Response.new(200, body, nil, nil, body.bytesize + 1)
    error = assert_raises(Registry::Error) { scripted(response).check(VERSION, DIGEST) }
    assert_match(/reported actual/, error.message)
  end

  def test_request_that_finishes_after_the_absolute_deadline_cannot_succeed
    now = 0.0
    registry = Registry.new(
      NAME,
      http: lambda { |_uri|
        now = 2.0
        res(404)
      },
      sleeper: ->(*) { },
      clock: -> { now }
    )

    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST, budget: 1) }
    assert_match(/monotonic budget/, error.message)
  end

  def test_expired_deadline_does_not_spawn_an_orphan_worker
    clock_calls = 0
    clock = lambda do
      clock_calls += 1
      clock_calls == 1 ? 0.0 : 2.0
    end
    deadline = Registry::Deadline.new(clock, 1)
    before = Thread.list
    ran = false

    assert_raises(Registry::Error) { deadline.run { ran = true } }
    assert_equal false, ran
    assert_empty Thread.list - before
  end

  def test_deadline_cleans_a_worker_if_expiry_is_observed_after_spawn
    clock_calls = 0
    clock = lambda do
      clock_calls += 1
      clock_calls <= 2 ? 0.0 : 2.0
    end
    deadline = Registry::Deadline.new(clock, 1)
    before = Thread.list
    gate = Queue.new

    assert_raises(Registry::Error) { deadline.run { gate.pop } }
    assert_empty Thread.list - before
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
    assert_match(/monotonic budget/, error.message)
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

  def test_verified_download_rejects_cross_origin_https_redirects
    registry = scripted(
      res(200, version_json),
      res(302, "", location: "https://cdn.example/surfguard-0.1.0.gem")
    )
    error = assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    assert_match(/exact https:\/\/rubygems\.org:443 origin/, error.message)
  end

  def test_verified_download_bounds_redirects
    hops = [ res(200, version_json) ]
    (Registry::MAX_REDIRECTS + 1).times { hops << res(301, "", location: "https://rubygems.org/hop") }
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

  def test_verified_download_rejects_cross_origin_scheme_relative_redirects
    registry = scripted(
      res(200, version_json),
      res(302, "", location: "//cdn.example/surfguard-0.1.0.gem")
    )
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
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
    assert_match(/exact https:\/\/rubygems\.org:443 origin/, error.message)
  end

  def test_verified_download_rejects_userinfo_fragment_and_alternate_port_redirects
    [
      "https://user@rubygems.org/gem",
      "https://rubygems.org/gem#fragment",
      "https://rubygems.org:444/gem"
    ].each do |location|
      registry = scripted(res(200, version_json), res(302, "", location: location))
      assert_raises(Registry::Error) { registry.verified_download(VERSION) }
    end
  end

  def test_gem_body_limit_is_enforced
    registry = scripted(res(200, version_json), res(200, "x" * (Registry::GEM_LIMIT + 1)))
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
  end

  def test_verified_download_fails_closed_on_unexpected_download_status
    registry = scripted(res(200, version_json), res(403))
    assert_raises(Registry::Error) { registry.verified_download(VERSION) }
  end

  # --- live Net::HTTP adapter -------------------------------------------------

  def test_live_adapter_disables_proxies_pins_the_ip_and_preserves_tls_identity
    response = live_response(200, version_json)
    registry, trace = live_registry(response)

    assert_equal :skip, registry.check(VERSION, DIGEST)
    assert_equal 1, trace[:resolver_calls]
    assert_equal [ [ "rubygems.org", 443, nil ] ], trace[:new_arguments]
    client = trace[:clients].fetch(0)
    assert_equal true, client.use_ssl
    assert_equal OpenSSL::SSL::VERIFY_PEER, client.verify_mode
    assert_equal true, client.verify_hostname
    assert_equal "93.184.216.34", client.ipaddr
    request = client.requests.fetch(0)
    assert_equal "rubygems.org", request["Host"]
    assert_equal "identity", request["Accept-Encoding"]
  end

  def test_live_adapter_caches_only_fully_validated_strict_dns_answers
    responses = [ live_response(404, ""), live_response(404, "") ]
    registry, trace = live_registry(*responses)

    2.times { assert_equal :push, registry.check(VERSION, DIGEST) }
    assert_equal 1, trace[:resolver_calls]

    [ [ "127.0.0.1" ], [ "93.184.216.34/24" ], [ "not-an-address" ], [] ].each do |answers|
      blocked, blocked_trace = live_registry(live_response(404, ""), answers: answers)
      assert_raises(Registry::Error) { blocked.check(VERSION, DIGEST) }
      assert_empty blocked_trace[:clients]
    end
  end

  def test_live_adapter_owns_cached_dns_answer_strings
    answer = +"93.184.216.34"
    registry, trace = live_registry(live_response(404, ""), live_response(404, ""), answers: [ answer ])

    assert_equal :push, registry.check(VERSION, DIGEST)
    answer.replace("127.0.0.1")
    assert_equal :push, registry.check(VERSION, DIGEST)
    assert_equal 1, trace[:resolver_calls]
    assert_equal [ "93.184.216.34", "93.184.216.34" ], trace[:clients].map(&:ipaddr)
  end

  def test_live_adapter_rejects_lazy_answer_collections_without_enumerating_them
    enumerated = false
    answers = Enumerator.new do |yielder|
      enumerated = true
      yielder << "93.184.216.34"
    end
    registry, trace = live_registry(live_response(404, ""), answers: answers)

    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_match(/invalid answer collection/, error.message)
    refute enumerated
    assert_empty trace[:clients]
  end

  def test_live_adapter_uses_a_trusted_answer_type_predicate
    coerced = false
    answer = Object.new
    answer.define_singleton_method(:is_a?) { |_klass| true }
    answer.define_singleton_method(:instance_of?) { |_klass| true }
    answer.define_singleton_method(:to_str) do
      coerced = true
      "93.184.216.34"
    end
    registry, trace = live_registry(live_response(404, ""), answers: [ answer ])

    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    assert_match(/malformed address/, error.message)
    refute coerced
    assert_empty trace[:clients]
  end

  def test_live_adapter_copies_real_arrays_and_strings_through_trusted_core_methods
    hooks = []
    answer = +"93.184.216.34"
    answer.define_singleton_method(:is_a?) { |_klass| false }
    answer.define_singleton_method(:instance_of?) { |_klass| false }
    answer.define_singleton_method(:valid_encoding?) do
      hooks << :answer_validation
      raise "resolver-owned string hook must not run"
    end
    answers = [ answer ]
    answers.define_singleton_method(:dup) do
      hooks << :array_dup
      raise "resolver-owned array hook must not run"
    end
    answers.define_singleton_method(:[]) do |*_arguments|
      hooks << :array_slice
      raise "resolver-owned array hook must not run"
    end
    answers.define_singleton_method(:each) do |*_arguments|
      hooks << :array_each
      raise "resolver-owned array hook must not run"
    end
    registry, trace = live_registry(live_response(404, ""), answers: answers)

    assert_equal :push, registry.check(VERSION, DIGEST)
    assert_empty hooks
    assert_equal [ "93.184.216.34" ], trace[:clients].map(&:ipaddr)
  end

  def test_live_adapter_rechecks_the_deadline_after_dns_and_each_chunk
    now = 0.0
    registry, trace = live_registry(live_response(404, ""), now: -> { now }, resolver_hook: -> { now = 2.0 })
    assert_raises(Registry::Error) { registry.check(VERSION, DIGEST, budget: 1) }
    assert_empty trace[:clients]

    now = 0.0
    response = live_response(200, version_json, before_chunk: -> { now = 2.0 })
    registry, = live_registry(response, now: -> { now })
    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST, budget: 1) }
    assert_match(/monotonic budget/, error.message)
  end

  def test_live_adapter_rechecks_the_deadline_before_trying_another_address
    now = 0.0
    first_address = lambda do
      now = 2.0
      raise SocketError, "first address failed"
    end
    registry, trace = live_registry(first_address, live_response(404, ""),
      answers: [ "93.184.216.34", "8.8.8.8" ], now: -> { now })

    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST, budget: 1) }
    assert_match(/monotonic budget/, error.message)
    assert_equal 1, trace[:clients].size
  end

  def test_live_adapter_rechecks_the_deadline_while_validating_each_answer
    clock_calls = 0
    cutoff = 24
    clock = lambda do
      clock_calls += 1
      clock_calls >= cutoff ? 2.0 : 0.0
    end
    answers = Array.new(Surfguard::MAX_ADDRESSES, "93.184.216.34")
    registry, trace = live_registry(live_response(404, ""), answers: answers, now: clock)

    error = assert_raises(Registry::Error) { registry.check(VERSION, DIGEST, budget: 1) }
    assert_match(/monotonic budget/, error.message)
    assert_operator clock_calls, :>=, cutoff
    assert_empty trace[:clients]
  end

  def test_live_adapter_rejects_encoded_ambiguous_and_length_mismatched_responses
    cases = [
      FakeNetResponse.new(200, [ version_json ], { "content-encoding" => "gzip" }),
      FakeNetResponse.new(200, [ version_json ], {
        "content-length" => version_json.bytesize.to_s, "transfer-encoding" => "chunked"
      }),
      FakeNetResponse.new(200, [ version_json ], { "content-length" => (version_json.bytesize + 1).to_s })
    ]
    cases.each do |response|
      registry, = live_registry(response)
      assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    end
  end

  def test_live_adapter_streams_gem_chunks_to_the_atomic_mode_0600_destination
    metadata = live_response(200, version_json)
    gem = FakeNetResponse.new(200, [ "canonical ", "gem bytes" ], { "content-length" => BYTES.bytesize.to_s })
    registry, trace = live_registry(metadata, gem)

    Dir.mktmpdir do |dir|
      destination = File.join(dir, "canonical.gem")
      assert_equal DIGEST, registry.verified_download_to(VERSION, destination)
      assert_equal BYTES, File.binread(destination)
      assert_equal 0o600, File.stat(destination).mode & 0o777
      assert_empty Dir.children(dir).grep(/\.tmp\z/)
    end
    assert_equal 1, trace[:resolver_calls]
    assert_equal 2, trace[:clients].size
  end

  def test_streaming_retry_discards_partial_bytes_before_trying_again
    now = 0.0
    steps = [
      res(200, version_json),
      lambda { |_uri, _deadline, _limit, sink|
        sink.write("partial")
        raise Net::ReadTimeout
      },
      res(200, BYTES)
    ]
    http = lambda do |uri, deadline, limit, sink|
      step = steps.shift
      step.respond_to?(:call) ? step.call(uri, deadline, limit, sink) : step
    end
    registry = Registry.new(NAME, http: http, sleeper: ->(seconds) { now += seconds }, clock: -> { now })

    Dir.mktmpdir do |dir|
      destination = File.join(dir, "retry.gem")
      assert_equal DIGEST, registry.verified_download_to(VERSION, destination)
      assert_equal BYTES, File.binread(destination)
    end
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

  def test_atomic_download_refuses_existing_destination_without_overwriting
    registry = scripted(res(200, version_json), res(200, BYTES))
    out, err = capture
    Dir.mktmpdir do |dir|
      destination = File.join(dir, "existing.gem")
      File.write(destination, "keep")
      status = Registry.run_download([ NAME, VERSION, destination ], out: out, err: err,
        registry_for: for_name(registry))
      assert_equal 1, status
      assert_equal "keep", File.read(destination)
    end
  end

  def test_atomic_download_refuses_symlink_parent
    registry = scripted(res(200, version_json), res(200, BYTES))
    out, err = capture
    Dir.mktmpdir do |dir|
      real = File.join(dir, "real")
      link = File.join(dir, "link")
      Dir.mkdir(real)
      File.symlink(real, link)
      status = Registry.run_download([ NAME, VERSION, File.join(link, "new.gem") ], out: out, err: err,
        registry_for: for_name(registry))
      assert_equal 1, status
      refute_path_exists File.join(real, "new.gem")
    end
  end

  def test_atomic_download_rolls_back_if_the_verified_temp_changes_before_link
    registry = scripted(res(200, version_json), res(200, BYTES))
    original_link = File.method(:link)
    replacement = "X" * BYTES.bytesize
    replace_before_link = lambda do |source, target|
      File.binwrite(source, replacement)
      File.chmod(0o600, source)
      original_link.call(source, target)
    end

    Dir.mktmpdir do |dir|
      destination = File.join(dir, "changed.gem")
      error = with_file_link_stub(replace_before_link) do
        assert_raises(Registry::Error) { registry.verified_download_to(VERSION, destination) }
      end
      assert_match(/published download digest changed/, error.message)
      refute_path_exists destination
      assert_empty Dir.children(dir)
    end
  end

  def test_atomic_download_rolls_back_if_link_finishes_after_the_deadline
    now = 0.0
    responses = [ res(200, version_json), res(200, BYTES) ]
    registry = Registry.new(NAME, http: ->(_uri) { responses.shift }, sleeper: ->(*) { }, clock: -> { now })
    original_link = File.method(:link)
    expire_after_link = lambda do |source, target|
      result = original_link.call(source, target)
      now = 2.0
      result
    end

    Dir.mktmpdir do |dir|
      destination = File.join(dir, "expired.gem")
      error = with_file_link_stub(expire_after_link) do
        assert_raises(Registry::Error) { registry.verified_download_to(VERSION, destination, budget: 1) }
      end
      assert_match(/monotonic budget/, error.message)
      refute_path_exists destination
      assert_empty Dir.children(dir)
    end
  end

  def test_confirm_can_atomically_save_the_canonical_registry_gem
    registry = scripted(res(200, version_json), res(200, version_json), res(200, BYTES))
    out, err = capture
    Dir.mktmpdir do |dir|
      destination = File.join(dir, "canonical.gem")
      status = Registry.run_confirm([ NAME, VERSION, DIGEST, destination, "60" ], out: out, err: err,
        registry_for: for_name(registry))
      assert_equal 0, status
      assert_equal BYTES, File.binread(destination)
      assert_equal 0o600, File.stat(destination).mode & 0o777
    end
  end

  def test_streamed_confirmation_never_publishes_unverified_partial_or_wrong_bytes
    registry = scripted(res(200, version_json), res(200, version_json), res(200, "tampered"))
    Dir.mktmpdir do |dir|
      destination = File.join(dir, "canonical.gem")
      assert_raises(Registry::Error) { registry.confirm_to(VERSION, DIGEST, destination) }
      refute_path_exists destination
      assert_empty Dir.children(dir)
    end
  end

  def test_budget_must_be_within_one_and_six_hundred_seconds
    [ 0, 601, "not-a-number" ].each do |budget|
      assert_raises(Registry::Error) { scripted.check(VERSION, DIGEST, budget: budget) }
    end
  end

  def test_deadline_watchdog_kills_a_worker_that_does_not_finish
    deadline = Registry::Deadline.new(-> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }, 0.01)

    error = assert_raises(Registry::Error) { deadline.run { sleep 1 } }
    assert_match(/monotonic budget/, error.message)
  end

  def test_digesting_sink_checks_types_limits_progress_and_optional_deadline
    output = StringIO.new
    sink = Registry::DigestingSink.new(output, 3)
    assert_equal 1, sink.write("a")
    assert_equal Digest::SHA256.hexdigest("a"), sink.hexdigest
    assert_raises(Registry::Error) { sink.write(Object.new) }
    assert_raises(Registry::Error) { sink.write("too long") }

    stalled = Object.new
    stalled.define_singleton_method(:write) { |_bytes| 0 }
    sink = Registry::DigestingSink.new(stalled, 3)
    assert_match(/made no progress/, assert_raises(Registry::Error) { sink.write("a") }.message)
  end

  def test_live_adapter_bounds_raw_answers_and_exhausts_network_addresses_without_a_sink
    too_many, = live_registry(live_response(404, ""),
      answers: Array.new(Surfguard::MAX_ADDRESSES + 1, "93.184.216.34"))
    assert_match(/too many addresses/, assert_raises(Registry::Error) {
      too_many.check(VERSION, DIGEST)
    }.message)

    queue = [ SocketError.new("network failed") ]
    http_class = Class.new
    http_class.define_singleton_method(:new) { |*| FakeHTTPClient.new(queue) }
    adapter = Registry::LiveHTTP.new(resolver: ->(_host) { [ "93.184.216.34" ] }, http_class: http_class)
    deadline = Registry::Deadline.new(-> { 0.0 }, 300)
    error = assert_raises(SocketError) do
      adapter.call(URI(VERSION_URL), deadline, Registry::METADATA_LIMIT, nil)
    end
    assert_match(/network failed/, error.message)

    file = StringIO.new
    sink = Registry::DigestingSink.new(file, 100)
    sink.write("partial")
    queue = [ SocketError.new("reset me") ]
    adapter = Registry::LiveHTTP.new(resolver: ->(_host) { [ "93.184.216.34" ] }, http_class: http_class)
    assert_raises(SocketError) { adapter.call(URI(VERSION_URL), deadline, Registry::METADATA_LIMIT, sink) }
    assert_equal 0, sink.bytesize

    resolver = ->(_host) { raise Resolv::ResolvError }
    adapter = Registry::LiveHTTP.new(resolver: resolver, http_class: http_class)
    assert_match(/resolution failed/, assert_raises(SocketError) {
      adapter.send(:addresses_for, "rubygems.org", deadline)
    }.message)
  end

  def test_live_adapter_supports_clients_without_verify_hostname_writer_and_bounds_streams
    response = live_response(404, "")
    queue = [ response ]
    client_class = Class.new(FakeHTTPClient) { undef_method :verify_hostname= }
    http_class = Class.new
    http_class.define_singleton_method(:new) { |*| client_class.new(queue) }
    adapter = Registry::LiveHTTP.new(resolver: ->(_host) { [ "93.184.216.34" ] }, http_class: http_class)
    registry = Registry.new(NAME, http: adapter.method(:call), sleeper: ->(*) { }, clock: -> { 0.0 })
    assert_equal :push, registry.check(VERSION, DIGEST)

    oversized = FakeNetResponse.new(200, [ "x" * 11 ], {})
    queue = [ oversized ]
    adapter = Registry::LiveHTTP.new(resolver: ->(_host) { [ "93.184.216.34" ] }, http_class: http_class)
    deadline = Registry::Deadline.new(-> { 0.0 }, 300)
    assert_match(/response exceeds/, assert_raises(Registry::Error) {
      adapter.call(URI(VERSION_URL), deadline, 10, nil)
    }.message)
  end

  def test_live_factory_builds_monotonic_clock_and_sleeper
    registry = Registry.live(NAME)
    assert_kind_of Numeric, registry.instance_variable_get(:@clock).call
    assert_equal 0, registry.instance_variable_get(:@sleeper).call(0)
    assert_instance_of Registry::LiveHTTP, registry.instance_variable_get(:@http).receiver
  end

  def test_atomic_target_rejects_empty_bad_parent_and_both_collision_phases
    [ nil, "" ].each do |destination|
      assert_match(/destination is empty/, assert_raises(Registry::Error) {
        Registry.atomic_publish(destination, "bytes")
      }.message)
    end

    missing = File.join(Dir.tmpdir, "surfguard-missing-parent-#{Process.pid}", "artifact.gem")
    refute_path_exists File.dirname(missing)
    assert_match(/atomic publication failed/, assert_raises(Registry::Error) {
      Registry.atomic_publish(missing, "bytes")
    }.message)

    Dir.mktmpdir do |directory|
      parent_file = File.join(directory, "parent-file")
      File.binwrite(parent_file, "not a directory")
      destination = File.join(parent_file, "artifact.gem")
      assert_match(/not a directory/, assert_raises(Registry::Error) {
        Registry.atomic_publish(destination, "bytes")
      }.message)
    end

    Dir.mktmpdir do |directory|
      destination = File.join(directory, "artifact.gem")
      temporary = File.join(directory, ".artifact.gem.fixed.tmp")
      File.binwrite(temporary, "occupied")
      with_singleton_method(SecureRandom, :hex, ->(_length) { "fixed" }) do
        assert_match(/temporary path collision/, assert_raises(Registry::Error) {
          Registry.atomic_publish(destination, "bytes")
        }.message)
      end
    end

    Dir.mktmpdir do |directory|
      destination = File.join(directory, "artifact.gem")
      with_singleton_method(File, :link, ->(*) { raise Errno::EEXIST }) do
        assert_match(/destination already exists/, assert_raises(Registry::Error) {
          Registry.atomic_publish(destination, "bytes")
        }.message)
      end
      assert_empty Dir.children(directory)
    end
  end

  def test_atomic_identity_helpers_reject_changed_parent_file_mode_size_digest_and_open_identity
    Dir.mktmpdir do |directory|
      other = Dir.mktmpdir
      assert_match(/parent changed/, assert_raises(Registry::Error) {
        Registry.send(:verify_parent_identity!, directory, File.stat(other), nil)
      }.message)

      path = File.join(directory, "artifact.gem")
      File.binwrite(path, BYTES)
      File.chmod(0o600, path)
      other_path = File.join(directory, "other.gem")
      File.binwrite(other_path, BYTES)
      File.chmod(0o600, other_path)
      assert_raises(Registry::Error) do
        Registry.send(:verify_regular_identity!, path, File.stat(other_path), nil, message: "identity failed")
      end
      assert_match(/size changed/, assert_raises(Registry::Error) {
        Registry.send(:verify_linked_target!, path, File.stat(path), BYTES.bytesize + 1, DIGEST, nil)
      }.message)
      assert_match(/digest changed/, assert_raises(Registry::Error) {
        Registry.send(:verify_linked_target!, path, File.stat(path), BYTES.bytesize, OTHER_SHA, nil)
      }.message)
      assert_match(/changed while opening/, assert_raises(Registry::Error) {
        Registry.send(:digest_regular_file, path, File.stat(other_path), nil)
      }.message)
    ensure
      FileUtils.remove_entry(other) if other && File.directory?(other)
    end
  end

  def test_digest_reader_enforces_limit_and_safe_unlink_requires_exact_identity
    identity = Struct.new(:dev, :ino).new(1, 2)
    identity.define_singleton_method(:file?) { true }
    fake = Object.new
    fake.define_singleton_method(:stat) { identity }
    chunks = [ "x" * (Registry::GEM_LIMIT + 1), nil ]
    fake.define_singleton_method(:read) { |_length| chunks.shift }
    with_singleton_method(File, :open, ->(_path, _flags, &block) { block.call(fake) }) do
      assert_match(/exceeds/, assert_raises(Registry::Error) {
        Registry.send(:digest_regular_file, "fake", identity, nil)
      }.message)
    end

    Dir.mktmpdir do |directory|
      path = File.join(directory, "artifact")
      File.binwrite(path, "bytes")
      assert_nil Registry.send(:safe_unlink_expected, path, nil)
      assert_nil Registry.send(:safe_unlink_expected, path, File.stat(directory))
      assert_path_exists path
    end
  end

  def test_constructor_nested_budget_version_and_http_response_guards
    assert_raises(Registry::Error) do
      Registry.new("Invalid.Name", http: ->(*) { }, sleeper: ->(*) { }, clock: -> { 0.0 })
    end

    registry = scripted(res(404))
    active = Registry::Deadline.new(-> { 0.0 }, 300)
    registry.instance_variable_set(:@deadline, active)
    assert_equal :nested, registry.send(:within_budget, 1) { :nested }
    registry.instance_variable_set(:@deadline, nil)
    assert_raises(Registry::Error) { registry.check("01.0.0", DIGEST) }

    two_argument_http = ->(_uri, remaining) {
      assert_operator remaining, :>, 0
      res(404)
    }
    registry = Registry.new(NAME, http: two_argument_http, sleeper: ->(*) { }, clock: -> { 0.0 })
    assert_equal :push, registry.check(VERSION, DIGEST)

    [
      Object.new,
      res(200, Object.new),
      Registry::Response.new(404, "", nil, nil, -1),
      Registry::Response.new("not-an-integer", "", nil)
    ].each do |response|
      registry = Registry.new(NAME, http: ->(*) { response }, sleeper: ->(*) { }, clock: -> { 0.0 })
      assert_raises(Registry::Error) { registry.check(VERSION, DIGEST) }
    end
  end

  def test_verified_download_in_memory_detects_oversize_and_post_verification_change
    registry = Registry.new(NAME, http: ->(*) { }, sleeper: ->(*) { }, clock: -> { 0.0 })
    registry.define_singleton_method(:stream_verified_download) do |_version, destination, required_sha: nil|
      File.binwrite(destination, "x" * (Registry::GEM_LIMIT + 1))
      required_sha || DIGEST
    end
    assert_match(/exceeds/, assert_raises(Registry::Error) {
      registry.verified_download(VERSION)
    }.message)

    registry.define_singleton_method(:stream_verified_download) do |_version, destination, required_sha: nil|
      File.binwrite(destination, "changed")
      required_sha || DIGEST
    end
    assert_match(/changed after verification/, assert_raises(Registry::Error) {
      registry.verified_download(VERSION)
    }.message)
  end

  def test_cli_argument_type_guards_fail_closed
    out, err = capture
    assert_equal 2, Registry.run_check([ NAME, VERSION, DIGEST, nil ], out: out, err: err)
    assert_equal 2, Registry.run_download([ NAME, VERSION, "x.gem", nil ], out: out, err: err)
    assert_equal 2, Registry.run_confirm([ NAME, VERSION, DIGEST, Object.new ], out: out, err: err)
  end

  private
    def with_singleton_method(object, name, replacement)
      original = object.method(name)
      object.define_singleton_method(name, replacement)
      yield
    ensure
      object.define_singleton_method(name, original)
    end

    def with_file_link_stub(replacement)
      singleton = File.singleton_class
      original = File.method(:link)
      singleton.send(:define_method, :link, replacement)
      yield
    ensure
      singleton&.send(:define_method, :link, original) if original
    end

    def live_response(status, body, before_chunk: nil)
      FakeNetResponse.new(status, [ body ], { "content-length" => body.bytesize.to_s },
        before_chunk: before_chunk)
    end

    def live_registry(*responses, answers: [ "93.184.216.34" ], now: -> { 0.0 }, resolver_hook: nil)
      queue = responses.dup
      trace = { resolver_calls: 0, new_arguments: [], clients: [] }
      http_class = Class.new
      http_class.define_singleton_method(:new) do |*arguments|
        trace[:new_arguments] << arguments
        FakeHTTPClient.new(queue).tap { |client| trace[:clients] << client }
      end
      resolver = lambda do |_host|
        trace[:resolver_calls] += 1
        resolver_hook&.call
        answers
      end
      adapter = Registry::LiveHTTP.new(resolver: resolver, http_class: http_class)
      registry = Registry.new(NAME, http: adapter.method(:call), sleeper: ->(*) { }, clock: now)
      [ registry, trace ]
    end

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
