# frozen_string_literal: true

require_relative "test_helper"
require "net/http"
require "openssl"
require "socket"
if ENV["SURFGUARD_INSTALLED_SUITE"]
  require "surfguard"
else
  require_relative "../lib/surfguard"
end

class ReadmeRecipeTest < Minitest::Test
  README = File.expand_path("../README.md", __dir__)

  FakeHTTP = Struct.new(
    :hostname, :port, :handler, :requests, :use_ssl, :ipaddr, :verify_mode,
    :verify_hostname, :open_timeout, :read_timeout, :write_timeout,
    keyword_init: true
  ) do
    def request(request)
      requests << request
      result = handler.call(self, request)
      raise result if result.is_a?(Exception)

      yield result
      result
    end
  end

  def test_net_http_recipe_is_valid_ruby_and_contains_the_pinning_invariants
    recipe = read_recipe
    refute_nil recipe
    RubyVM::InstructionSequence.compile(recipe)
    assert_includes recipe, "uri.hostname"
    assert_includes recipe, "Net::HTTP.new(hostname, uri.port, nil)"
    assert_includes recipe, "http.ipaddr = address"
    assert_includes recipe, "OpenSSL::SSL::VERIFY_PEER"
    assert_includes recipe, "http.verify_hostname = true"
    assert_includes recipe, "candidate.read_body"
    assert_includes recipe, "URI.join(base, value)"
    assert_equal 1, recipe.scan("resolve_public_ips").length
  end

  def test_recipe_retries_only_pinned_addresses_and_revalidates_redirects
    events = [
      IOError.new("first address failed"),
      response(Net::HTTPFound, "302", chunks: [ "redirect" ], location: "https://next.example/final"),
      response(Net::HTTPOK, "200", chunks: [ "o", "k" ])
    ]
    resolver = {
      "feeds.example" => %w[93.184.216.34 93.184.216.35],
      "next.example" => [ "93.184.216.36" ]
    }

    with_fake_recipe_network(resolver: resolver, handler: ->(_http, _request) { events.shift }) do |client, state|
      http_response, body = client.pinned_get("https://feeds.example/feed")

      assert_instance_of Net::HTTPOK, http_response
      assert_equal "ok", body
      assert_predicate body, :frozen?
      assert_equal [
        [ "feeds.example", :default ],
        [ "next.example", :default ]
      ], state[:resolver_calls]
      assert_equal %w[feeds.example feeds.example next.example], state[:http].map(&:hostname)
      assert_equal [ 443, 443, 443 ], state[:http].map(&:port)
      assert_equal [ nil, nil, nil ], state[:proxies]
      assert_equal %w[93.184.216.34 93.184.216.35 93.184.216.36], state[:http].map(&:ipaddr)
      assert state[:http].all?(&:use_ssl)
      assert state[:http].all?(&:verify_hostname)
      assert state[:http].all? { |http| http.verify_mode == OpenSSL::SSL::VERIFY_PEER }
      assert_equal %w[/feed /feed /final], state[:requests].map(&:path)
      assert state[:requests].all? { |request| request["accept-encoding"] == "identity" }
    end
  end

  def test_recipe_uses_unbracketed_ipv6_hostname_and_pins_the_literal
    resolver = { "2606:4700:4700::1111" => [ "2606:4700:4700::1111" ] }
    handler = ->(_http, _request) { response(Net::HTTPOK, "200", chunks: [ "ipv6" ]) }

    with_fake_recipe_network(resolver: resolver, handler: handler) do |client, state|
      _http_response, body = client.pinned_get("https://[2606:4700:4700::1111]:444/path")

      assert_equal "ipv6", body
      assert_equal [ [ "2606:4700:4700::1111", :default ] ], state[:resolver_calls]
      assert_equal "2606:4700:4700::1111", state[:http].first.hostname
      assert_equal "2606:4700:4700::1111", state[:http].first.ipaddr
      assert_equal 444, state[:http].first.port
    end
  end

  def test_recipe_enforces_streamed_byte_limit_without_retrying
    resolver = { "large.example" => %w[93.184.216.34 93.184.216.35] }
    handler = ->(_http, _request) { response(Net::HTTPOK, "200", chunks: %w[abc def]) }

    with_fake_recipe_network(resolver: resolver, handler: handler) do |client, state, recipe_module|
      error = assert_raises(recipe_module.const_get(:PinnedResponseTooLarge)) do
        client.pinned_get("https://large.example/file", max_bytes: 5)
      end
      assert_equal "response body exceeds limit", error.message
      assert_equal 1, state[:http].length
      assert_equal 1, state[:resolver_calls].length
    end
  end

  def test_recipe_bounds_redirects_and_rejects_an_unsafe_redirect_before_resolution
    redirect = response(Net::HTTPFound, "302", chunks: [], location: "http://internal.example/")
    resolver = { "start.example" => [ "93.184.216.34" ] }

    with_fake_recipe_network(resolver: resolver, handler: ->(_http, _request) { redirect }) do |client, state|
      error = assert_raises(ArgumentError) { client.pinned_get("https://start.example/", max_redirects: 1) }
      assert_equal "HTTPS required", error.message
      assert_equal [ [ "start.example", :default ] ], state[:resolver_calls]
    end

    with_fake_recipe_network(resolver: resolver, handler: ->(_http, _request) { redirect }) do |client, _state, recipe_module|
      error = assert_raises(recipe_module.const_get(:PinnedRedirectError)) do
        client.pinned_get("https://start.example/", max_redirects: 0)
      end
      assert_equal "redirect limit exceeded", error.message
    end
  end

  def test_recipe_hard_caps_caller_configurable_bounds
    client, = recipe_client

    assert_raises(ArgumentError) { client.pinned_get("https://example.com", max_redirects: 11) }
    assert_raises(ArgumentError) { client.pinned_get("https://example.com", max_redirects: -1) }
    assert_raises(ArgumentError) { client.pinned_get("https://example.com", max_bytes: 0) }
    assert_raises(ArgumentError) { client.pinned_get("https://example.com", max_bytes: 16 * 1024 * 1024 + 1) }
  end

  def test_recipe_fixed_url_and_limit_errors_discard_causes_and_attacker_input
    client, = recipe_client
    ambient = "attacker-controlled-ambient-detail"
    credential = "attacker-controlled-credential"
    malformed_url = "https://alice:#{credential}@example.invalid/ bad"
    cases = [
      [ -> { client.pinned_get(malformed_url) }, ArgumentError, "malformed URL", credential ],
      [ -> { client.pinned_get("https://alice:#{credential}@example.invalid/") },
        ArgumentError, "userinfo forbidden", credential ],
      [ -> { client.pinned_get("http://example.invalid/") }, ArgumentError, "HTTPS required", nil ],
      [ -> { client.pinned_get("https:///path") }, ArgumentError, "host required", nil ],
      [ -> { client.pinned_get("https://example.invalid/", max_redirects: -1) },
        ArgumentError, "invalid redirect limit", nil ],
      [ -> { client.pinned_get("https://example.invalid/", max_bytes: 0) },
        ArgumentError, "invalid response limit", nil ]
    ]

    cases.each do |call, type, message, input_detail|
      error = capture_during_rescue(ambient, &call)
      assert_sanitized_exception(error, type, message, ambient, input_detail)
    end
  end

  def test_recipe_fixed_network_and_redirect_errors_discard_causes
    ambient = "attacker-controlled-ambient-detail"

    with_fake_recipe_network(resolver: { "blocked.example" => [] }, handler: ->(*) { flunk }) do |client|
      error = capture_during_rescue(ambient) { client.pinned_get("https://blocked.example/") }
      assert_sanitized_exception(error, Surfguard::Violation, Surfguard::BLOCKED_MESSAGE, ambient)
    end

    network_detail = "attacker-controlled-network-detail"
    handler = ->(*) { IOError.new(network_detail) }
    with_fake_recipe_network(resolver: { "retry.example" => [ "93.184.216.34" ] }, handler: handler) do |client|
      error = capture_during_rescue(ambient) { client.pinned_get("https://retry.example/") }
      assert_sanitized_exception(
        error, Surfguard::Unresolvable, Surfguard::UNRESOLVABLE_MESSAGE, ambient, network_detail
      )
    end

    large = ->(*) { response(Net::HTTPOK, "200", chunks: [ "too large" ]) }
    with_fake_recipe_network(resolver: { "large.example" => [ "93.184.216.34" ] }, handler: large) do |client, _state, recipe_module|
      error = capture_during_rescue(ambient) do
        client.pinned_get("https://large.example/", max_bytes: 1)
      end
      assert_sanitized_exception(
        error, recipe_module.const_get(:PinnedResponseTooLarge), "response body exceeds limit", ambient
      )
    end

    redirect = ->(location) { response(Net::HTTPFound, "302", chunks: [], location: location) }
    resolver = { "start.example" => [ "93.184.216.34" ] }
    with_fake_recipe_network(resolver: resolver, handler: ->(*) { redirect.call("https://next.example/") }) do |client, _state, recipe_module|
      error = capture_during_rescue(ambient) do
        client.pinned_get("https://start.example/", max_redirects: 0)
      end
      assert_sanitized_exception(
        error, recipe_module.const_get(:PinnedRedirectError), "redirect limit exceeded", ambient
      )
    end

    with_fake_recipe_network(resolver: resolver, handler: ->(*) { redirect.call(nil) }) do |client, _state, recipe_module|
      error = capture_during_rescue(ambient) { client.pinned_get("https://start.example/") }
      assert_sanitized_exception(
        error, recipe_module.const_get(:PinnedRedirectError), "redirect location missing", ambient
      )
    end

    redirect_detail = "attacker-controlled-redirect-detail"
    malformed_redirect = "https://alice:#{redirect_detail}@next.example/ bad"
    with_fake_recipe_network(resolver: resolver, handler: ->(*) { redirect.call(malformed_redirect) }) do |client|
      error = capture_during_rescue(ambient) { client.pinned_get("https://start.example/") }
      assert_sanitized_exception(error, ArgumentError, "malformed URL", ambient, redirect_detail)
    end
  end

  def test_real_net_http_retains_host_sni_and_certificate_identity_while_pinning
    hostname = "origin.test"
    ca_certificate, server_certificate, server_key = certificates_for(hostname)
    tcp_server = begin
      TCPServer.new("127.0.0.1", 0)
    rescue Errno::EACCES, Errno::EPERM
      raise if ENV["CI"]

      skip "local TCP sockets are unavailable"
    end
    port = tcp_server.local_address.ip_port
    server_result = nil
    server_name = nil
    context = OpenSSL::SSL::SSLContext.new
    context.cert = server_certificate
    context.key = server_key
    # Ruby's OpenSSL invokes servername_cb with a single [socket, hostname] array.
    context.servername_cb = lambda do |(_socket, hostname)|
      server_name = hostname
      nil
    end
    server = Thread.new do
      socket = tcp_server.accept
      ssl = OpenSSL::SSL::SSLSocket.new(socket, context)
      ssl.sync_close = true
      ssl.accept
      request = String.new(encoding: Encoding::BINARY)
      request << ssl.readpartial(1024) until request.include?("\r\n\r\n")
      host = request[/\r\nHost:\s*([^\r\n]+)/i, 1]
      server_result = [ server_name, host ]
      ssl.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      ssl.close
    end

    client, = recipe_client
    original_resolver = Surfguard.method(:resolve_public_ips)
    original_http_new = Net::HTTP.method(:new)
    constructors = []
    Surfguard.define_singleton_method(:resolve_public_ips) do |host, policy:|
      raise "wrong host or policy" unless host == hostname && policy == :iana_special_use

      [ "127.0.0.1" ]
    end
    Net::HTTP.define_singleton_method(:new) do |host, requested_port, proxy|
      constructors << [ host, requested_port, proxy ]
      http = original_http_new.call(host, requested_port, proxy)
      store = OpenSSL::X509::Store.new
      store.add_cert(ca_certificate)
      http.cert_store = store
      http
    end

    response_value, body = client.pinned_get(
      "https://#{hostname}:#{port}/secure", policy: :iana_special_use
    )
    assert_instance_of Net::HTTPOK, response_value
    assert_equal "ok", body
    assert server.join(5), "TLS test server did not finish"
    server.value
    assert_equal [ hostname, "#{hostname}:#{port}" ], server_result
    assert_equal [ [ hostname, port, nil ] ], constructors
  ensure
    Surfguard.define_singleton_method(:resolve_public_ips, original_resolver) if original_resolver
    Net::HTTP.define_singleton_method(:new, original_http_new) if original_http_new
    tcp_server&.close
    server&.kill if server&.alive?
  end

  private
    def assert_sanitized_exception(error, type, message, *forbidden_details)
      assert_instance_of type, error
      assert_equal message, error.message
      assert_nil error.cause
      forbidden_details.compact.each { |detail| refute_includes error.full_message, detail }
    end

    def capture_during_rescue(detail)
      raise RuntimeError, detail
    rescue RuntimeError
      begin
        yield
      rescue StandardError => error
        error
      end
    end

    def read_recipe
      markdown = File.read(README)
      markdown[/<!-- net-http-recipe:start -->\s*```ruby\n(.*?)```\s*<!-- net-http-recipe:end -->/m, 1]
    end

    def recipe_client
      recipe_module = Module.new
      recipe_module.module_eval(read_recipe.gsub(/^require .+\n/, ""))
      [ Class.new { include recipe_module }.new, recipe_module ]
    end

    def response(type, code, chunks:, location: nil)
      value = type.new("1.1", code, "test")
      value["location"] = location if location
      value.define_singleton_method(:read_body) { |&block| chunks.each(&block) }
      value
    end

    def with_fake_recipe_network(resolver:, handler:)
      client, recipe_module = recipe_client
      original_resolver = Surfguard.method(:resolve_public_ips)
      original_http_new = Net::HTTP.method(:new)
      state = { resolver_calls: [], http: [], requests: [], proxies: [] }
      Surfguard.define_singleton_method(:resolve_public_ips) do |host, policy:|
        state[:resolver_calls] << [ host, policy ]
        resolver.fetch(host)
      end
      Net::HTTP.define_singleton_method(:new) do |host, port, proxy|
        state[:proxies] << proxy
        FakeHTTP.new(hostname: host, port: port, handler: handler, requests: state[:requests]).tap do |http|
          state[:http] << http
        end
      end

      yield client, state, recipe_module
    ensure
      Surfguard.define_singleton_method(:resolve_public_ips, original_resolver) if original_resolver
      Net::HTTP.define_singleton_method(:new, original_http_new) if original_http_new
    end

    def certificates_for(hostname)
      now = Time.now
      ca_key = OpenSSL::PKey::RSA.new(2048)
      ca = OpenSSL::X509::Certificate.new
      ca.version = 2
      ca.serial = 1
      ca.subject = OpenSSL::X509::Name.parse("/CN=Surfguard Recipe Test CA")
      ca.issuer = ca.subject
      ca.public_key = ca_key.public_key
      ca.not_before = now - 60
      ca.not_after = now + 3600
      ca_factory = OpenSSL::X509::ExtensionFactory.new(nil, ca)
      ca.add_extension(ca_factory.create_extension("basicConstraints", "CA:TRUE", true))
      ca.add_extension(ca_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true))
      ca.sign(ca_key, OpenSSL::Digest::SHA256.new)

      server_key = OpenSSL::PKey::RSA.new(2048)
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 2
      certificate.subject = OpenSSL::X509::Name.parse("/CN=#{hostname}")
      certificate.issuer = ca.subject
      certificate.public_key = server_key.public_key
      certificate.not_before = now - 60
      certificate.not_after = now + 3600
      factory = OpenSSL::X509::ExtensionFactory.new(ca, certificate)
      certificate.add_extension(factory.create_extension("basicConstraints", "CA:FALSE", true))
      certificate.add_extension(factory.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
      certificate.add_extension(factory.create_extension("extendedKeyUsage", "serverAuth"))
      certificate.add_extension(factory.create_extension("subjectAltName", "DNS:#{hostname}"))
      certificate.sign(ca_key, OpenSSL::Digest::SHA256.new)

      [ ca, certificate, server_key ]
    end
end
