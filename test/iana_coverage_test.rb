# frozen_string_literal: true

require_relative "test_helper"

require "digest"
require "fileutils"
require "json"
require "stringio"
require "tmpdir"

require_relative "../script/check_iana_drift"
require_relative "../script/generate_iana_data"

class IanaCoverageTest < Minitest::Test
  Iana = Surfguard::Iana
  Registry = Iana::Registry
  Generator = Iana::Generator
  ROOT = File.expand_path("..", __dir__)
  SNAPSHOTS = File.join(ROOT, "script/iana")
  CHECKER = File.join(ROOT, "script/check_iana_drift.rb")
  GENERATOR_CLI = File.join(ROOT, "script/generate_iana_data.rb")

  def test_http_fetcher_pins_the_owned_origin_and_streams_the_response
    response = http_response(chunks: [ "hello", " world" ])
    http = fake_http(response)
    invocation = nil
    starter = lambda do |*arguments, **keywords, &block|
      invocation = [ arguments, keywords ]
      block.call(http)
    end

    body = stub_singleton(Net::HTTP, :start, starter) do
      Iana::HttpFetcher.new.call(
        "https://www.iana.org/assignments/example.csv", accept: "text/csv"
      )
    end

    assert_equal "hello world", body
    assert_equal Encoding::UTF_8, body.encoding
    assert_equal "text/csv", http.captured_request["Accept"]
    assert_equal [ "www.iana.org", 443, nil, nil, nil, nil ], invocation.first
    assert_equal({ use_ssl: true, open_timeout: 10, read_timeout: 20 }, invocation.last)
  end

  def test_http_fetcher_rejects_every_origin_escape_and_invalid_url
    rejected = [
      "http://www.iana.org/example",
      "https://iana.org/example",
      "https://user@www.iana.org/example",
      "https://www.iana.org:444/example",
      "https://www.iana.org/example?query=1",
      "https://www.iana.org/example#fragment"
    ]
    rejected.each do |url|
      error = assert_raises(Iana::Error) { Iana::HttpFetcher.new.call(url, accept: "text/plain") }
      assert_equal "IANA source must use its code-owned exact HTTPS origin", error.message
    end

    error = assert_raises(Iana::Error) do
      Iana::HttpFetcher.new.call("https://[", accept: "text/plain")
    end
    assert_match(/invalid code-owned IANA URL/, error.message)
  end

  def test_http_fetcher_rejects_status_length_and_streaming_failures
    cases = [
      [ http_response(klass: Net::HTTPNotFound), /HTTP 404/ ],
      [ http_response(length: Iana::HttpFetcher::MAX_BYTES + 1), /declared body exceeds/ ],
      [ http_response(length: -1), /invalid declared body length/ ],
      [ http_response(length: "not-an-integer"), /invalid declared body length/ ],
      [ http_response(chunks: [ "x" * (Iana::HttpFetcher::MAX_BYTES + 1) ]), /body exceeds/ ]
    ]

    cases.each do |response, message|
      error = assert_raises(Iana::Error) do
        with_http_response(response) do
          Iana::HttpFetcher.new.call("https://www.iana.org/example", accept: "text/plain")
        end
      end
      assert_match message, error.message
    end

    body = with_http_response(http_response(length: 2, chunks: [ "ok" ])) do
      Iana::HttpFetcher.new.call("https://www.iana.org/example", accept: "text/plain")
    end
    assert_equal "ok", body
  end

  def test_drift_checker_check_and_run_cover_success_failure_and_fail_closed_paths
    schema = Registry.schema("ipv4_special_use")
    source = csv_for(schema, [ { "Address Block" => "192.0.2.0/24" } ])
    metadata = metadata_xml(schema, "2025-10-09")
    snapshot = parsed_snapshot(schema, [ "192.0.2.0/24" ], source: source)
    calls = []
    fetcher = lambda do |url, accept:|
      calls << [ url, accept ]
      url == schema.source_url ? source : metadata
    end

    result = Iana::DriftChecker.new(fetcher: fetcher).check(snapshot)
    assert_empty result.issues
    assert_equal 1, result.prefix_count
    assert_predicate result, :frozen?
    assert_equal [
      [ schema.source_url, "text/csv" ],
      [ schema.metadata_url, "application/xml" ]
    ], calls

    checker = Iana::DriftChecker.new(snapshot_directory: SNAPSHOTS)
    out = StringIO.new
    err = StringIO.new
    stub_singleton(checker, :check, result) do
      assert_equal 0, checker.run(out: out, err: err)
    end
    assert_equal 3, out.string.lines.length
    assert_empty err.string

    failure = Iana::DriftChecker::Result.new(
      snapshot: snapshot, actual_digest: "0" * 64, prefix_count: 0, issues: [ "changed" ]
    )
    out = StringIO.new
    err = StringIO.new
    stub_singleton(checker, :check, failure) do
      assert_equal 1, checker.run(out: out, err: err)
    end
    assert_empty out.string
    assert_equal 3, err.string.scan(/FAILED/).length
    assert_equal 3, err.string.scan(/changed/).length

    Dir.mktmpdir("iana-drift-empty") do |directory|
      err = StringIO.new
      assert_equal 1, Iana::DriftChecker.new(snapshot_directory: directory).run(err: err)
      assert_match(/failed closed: IANA snapshot files differ/, err.string)
    end
  end

  def test_drift_audit_reports_parser_failures_and_each_semantic_change_shape
    schema = Registry.schema("ipv4_special_use")
    source = csv_for(schema, [ { "Address Block" => "192.0.2.0/24" } ])
    snapshot = parsed_snapshot(schema, [ "192.0.2.0/24" ], source: source)
    result = Iana::DriftChecker.new.audit(snapshot, source: "not,csv", metadata: "not xml")
    assert_equal 0, result.prefix_count
    assert result.issues.any? { |issue| issue.start_with?("semantic registry parse failed:") }
    assert result.issues.any? { |issue| issue.start_with?("registry metadata parse failed:") }

    date_drift = Iana::DriftChecker.new.audit(
      snapshot, source: source, metadata: metadata_xml(schema, "2025-10-10")
    )
    assert_equal [
      "registry update date drift: expected 2025-10-09, got 2025-10-10"
    ], date_drift.issues

    expected = Registry.records_from_cidrs(schema, [ "192.0.2.0/24" ], context: "expected")
    added = Registry.records_from_cidrs(schema, [ "198.51.100.0/24" ], context: "added")
    checker = Iana::DriftChecker.new
    assert_empty checker.send(:semantic_issues, expected, expected)
    assert_match(/added/, checker.send(:semantic_issues, [], added).first)
    assert_match(/removed/, checker.send(:semantic_issues, expected, []).first)
    both = checker.send(:semantic_issues, expected, added).first
    assert_match(/added/, both)
    assert_match(/removed/, both)
  end

  def test_registry_snapshot_envelope_and_owned_string_validation
    schema = Registry.schema("ipv4_special_use")
    source = csv_for(schema, [ { "Address Block" => "192.0.2.0/24" } ])
    valid = snapshot_data(schema, [ "192.0.2.0/24" ], source: source)

    malformed = {
      "[]" => /JSON object/,
      "{" => /malformed snapshot JSON/
    }
    malformed.each do |bytes, message|
      assert_raises_with_message(message) { Registry.parse_snapshot(schema.id, bytes) }
    end

    mutations = {
      "schema_version" => 2,
      "registry" => "other",
      "url" => "https://www.iana.org/other.csv",
      "metadata_url" => "https://www.iana.org/other.xml",
      "selection" => "other",
      "source_sha256" => "ABC",
      "semantic_sha256" => 123,
      "registry_updated" => "2025-02-29",
      "prefixes" => "192.0.2.0/24"
    }
    mutations.each do |field, value|
      data = valid.merge(field => value)
      assert_raises(Iana::Error, field) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }
    end

    invalid_text = String.new("x\xFF", encoding: Encoding::UTF_8)
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, invalid_text) }
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, 123) }
    utf16 = JSON.generate(valid).encode(Encoding::UTF_16LE)
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, utf16) }

    invalid_prefix = valid.merge("prefixes" => [ 123 ])
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(invalid_prefix)) }

    missing_field = valid.dup
    missing_field.delete("url")
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(missing_field)) }

    wrong_semantic_digest = valid.merge("semantic_sha256" => "0" * 64)
    assert_raises(Iana::Error) do
      Registry.parse_snapshot(schema.id, JSON.generate(wrong_semantic_digest))
    end
  end

  def test_registry_file_set_csv_selection_and_endpoint_validation
    Dir.mktmpdir("iana-empty-snapshots") do |directory|
      assert_raises(Iana::Error) { Registry.load_snapshots(directory) }
    end

    assert_raises(Iana::Error) { Registry.parse_csv("") }
    assert_equal [ [ "header" ], [ [ "value" ] ] ], Registry.parse_csv("header\nvalue")

    schema = Registry.schema("ipv6_allocated")
    reserved = csv_for(schema, [ { "Prefix" => "2d00::/8", "Status" => "RESERVED" } ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, reserved) }
    allocated = csv_for(schema, [ { "Prefix" => "2001::/23", "Status" => "ALLOCATED" } ])
    assert_equal [ "2001::/23" ], Registry.parse_registry(schema, allocated).map(&:cidr)
    unknown = csv_for(schema, [ { "Prefix" => "2001::/23", "Status" => "unknown" } ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, unknown) }

    wrong_fields = csv_rows([ schema.headers, [ "2001::/23" ] ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, wrong_fields) }
    unknown_selector = schema.dup
    unknown_selector.selection = :unknown
    assert_raises(Iana::Error) { Registry.parse_registry(unknown_selector, allocated) }
    assert_raises(Iana::Error) { Registry.records_from_cidrs(schema, "2001::/23", context: "fixture") }

    zero = Registry.parse_cidr(
      Registry.schema("ipv4_special_use"), "0.0.0.0/0", context: "fixture"
    )
    assert_equal 0, zero.integer
    assert_raises(Iana::Error) do
      Registry.parse_cidr(schema, "2001:0db8::/32", context: "fixture")
    end

    invalid_cidrs = [
      [ schema, "not-a-cidr" ],
      [ schema, "192.0.2.0/24" ],
      [ schema, "2001::/129" ],
      [ schema, "2001::1/64" ],
      [ schema, "not-an-ip/64" ]
    ]
    invalid_cidrs.each do |entry, cidr|
      assert_raises(Iana::Error, cidr) { Registry.parse_cidr(entry, cidr, context: "fixture") }
    end

    ipv4 = Registry.schema("ipv4_special_use")
    [ nil, 123 ].each do |value|
      assert_raises(Iana::Error) do
        Registry.records_from_cidrs(ipv4, [ value ], context: "fixture")
      end
    end
    invalid = String.new("bad\xFF", encoding: Encoding::UTF_8)
    assert_raises(Iana::Error) do
      Registry.records_from_cidrs(ipv4, [ invalid ], context: "fixture")
    end

    [ nil, 123, String.new("x\xFF", encoding: Encoding::UTF_8) ].each do |body|
      assert_raises(Iana::Error) { Registry.parse_registry(ipv4, body) }
    end

    duplicate = csv_for(ipv4, [
      { "Address Block" => "192.0.2.0/24" },
      { "Address Block" => "192.0.2.0/24" }
    ])
    assert_raises(Iana::Error) { Registry.parse_registry(ipv4, duplicate) }

    annotated = csv_for(ipv4, [ { "Address Block" => "192.0.2.0/24 [1] [2]" } ])
    assert_equal [ "192.0.2.0/24" ], Registry.parse_registry(ipv4, annotated).map(&:cidr)
    unsupported = csv_for(ipv4, [ { "Address Block" => "192.0.2.0/24 [RFC]" } ])
    assert_raises(Iana::Error) { Registry.parse_registry(ipv4, unsupported) }
  end

  def test_registry_csv_state_machine_covers_quoted_and_malformed_transitions
    parsed = Registry.parse_csv(%Q("head,one",head-two\r\n"say ""hi""","line one\nline two"\r\n))
    assert_equal [ "head,one", "head-two" ], parsed.first
    assert_equal [ [ 'say "hi"', "line one\nline two" ] ], parsed.last

    malformed = [
      %(header\r\n"unterminated),
      %(header\r\n"closed"junk\r\n),
      %(header\r\nun"quoted\r\n),
      "header\rvalue\r\n"
    ]
    malformed.each do |body|
      assert_raises(Iana::Error, body.inspect) { Registry.parse_csv(body) }
    end
  end

  def test_registry_address_rendering_covers_every_compression_position
    assert_equal "1.2.3.4", Registry.render_address(Socket::AF_INET, 0x01020304)
    assert_equal "2001:1:2:3:4:5:6:7", render_ipv6("2001:1:2:3:4:5:6:7")
    assert_equal "::", render_ipv6("::")
    assert_equal "::1", render_ipv6("::1")
    assert_equal "2001::", render_ipv6("2001::")
    assert_equal "2001::1", render_ipv6("2001::1")
  end

  def test_registry_metadata_xml_accepts_owned_minimal_forms
    schema = Registry.schema("ipv4_special_use")
    namespace = Iana::IANA_XML_NAMESPACE
    id = schema.metadata_registry_id

    xml = %(<?owned?><registry xmlns = '#{namespace}' id = "#{id}" ><ignored><![CDATA[text]]></ignored><updated>2025-10-09</updated><!--ok--></registry>)
    assert_equal "2025-10-09", Registry.registry_updated(xml, id: schema.id)

    self_closing_update = %(<registry xmlns="#{namespace}" id="#{id}"><updated/></registry>)
    assert_raises(Iana::Error) { Registry.registry_updated(self_closing_update, id: schema.id) }

    self_closing_root = %(<registry xmlns="#{namespace}" id="#{id}"/>)
    assert_raises(Iana::Error) { Registry.registry_updated(self_closing_root, id: schema.id) }

    generic = %(<registry xmlns="#{namespace}"><updated>2025-10-09</updated></registry>)
    assert_equal "2025-10-09", Registry.registry_updated(generic, id: "unregistered")
  end

  def test_registry_metadata_xml_rejects_every_token_and_structure_failure
    schema = Registry.schema("ipv4_special_use")
    root = %(<registry xmlns="#{Iana::IANA_XML_NAMESPACE}" id="#{schema.metadata_registry_id}">)
    invalid = [
      "#{root}<updated><!--bad--></updated></registry>",
      "#{root}<updated><?bad?></updated></registry>",
      "#{root}<updated><![CDATA[bad]]></updated></registry>",
      "<![CDATA[bad]]>",
      "#{root}<![CDATA[",
      "<!DOCTYPE registry>",
      "#{root}<updated><nested/></updated></registry>",
      "#{root}<updated>2025-10-09</wrong></registry>",
      "#{root}<updated>2025-10-09</updated></registry><registry xmlns=\"#{Iana::IANA_XML_NAMESPACE}\"/>",
      root,
      "#{root}<updated>2025-10-09</updated",
      "#{root}<updated>2025-10-09</updated extra></registry>",
      "<!--",
      "<?",
      "<![CDATA[",
      "<registry!>",
      "<registry !>",
      "<registry xmlns>",
      "<registry xmlns=unquoted>",
      "<registry xmlns=\"unterminated>",
      "<registry xmlns=\"bad<value\">",
      "<registry xmlns=\"one\" xmlns=\"two\">"
    ]
    invalid.each do |xml|
      assert_raises(Iana::Error, xml.inspect) { Registry.registry_updated(xml, id: schema.id) }
    end


    wrong_root = %(<wrong xmlns="#{Iana::IANA_XML_NAMESPACE}"/>)
    assert_raises(Iana::Error) { Registry.registry_updated(wrong_root, id: schema.id) }
    wrong_identity = %(<registry xmlns="#{Iana::IANA_XML_NAMESPACE}" id="wrong"/>)
    assert_raises(Iana::Error) { Registry.registry_updated(wrong_identity, id: schema.id) }

    assert_raises(Iana::Error) do
      Registry.send(:parse_xml_start_tag, 'registry xmlns="unterminated', "fixture")
    end
    assert_raises(Iana::Error) { Registry.send(:parse_xml_start_tag, "!", "fixture") }
  end

  def test_registry_json_scanner_rejects_structural_ambiguity
    failures = [
      "{} trailing",
      "{bad}",
      %({"key" 1}),
      %({"key":1]),
      "[1}"
    ]
    failures.each do |json|
      assert_raises(Iana::Error, json) do
        Registry.send(:reject_duplicate_json_keys!, json, "fixture")
      end
    end

    Registry.send(:reject_duplicate_json_keys!, "{}", "fixture")
    Registry.send(:reject_duplicate_json_keys!, "[]", "fixture")
    Registry.send(:reject_duplicate_json_keys!, %(["escaped\\\"string", true, null]), "fixture")
    assert_raises(Iana::Error) do
      Registry.send(:reject_duplicate_json_keys!, %({"same":1,"same":2}), "fixture")
    end
  end

  def test_registry_date_validation_covers_format_year_month_and_leap_centuries
    validate = ->(value) { Registry.send(:valid_iso_date?, value) }
    refute validate.call("not-a-date")
    refute validate.call("0000-01-01")
    refute validate.call("2025-13-01")
    refute validate.call("1900-02-29")
    assert validate.call("2000-02-29")
  end

  def test_generator_cli_is_loadable_and_reports_every_result
    out = StringIO.new
    err = StringIO.new
    stub_singleton(Generator, :check!, true) do
      assert_equal 0, Iana::GeneratorCLI.run([ "--check" ], out: out, err: err)
    end
    assert_equal "IANA generated constants: ok\n", out.string

    [
      [ true, "Updated generated IANA constants; review the diff\n" ],
      [ false, "IANA generated constants already current\n" ]
    ].each do |changed, expected|
      out = StringIO.new
      stub_singleton(Generator, :update!, changed) do
        assert_equal 0, Iana::GeneratorCLI.run([ "--update" ], out: out, err: err)
      end
      assert_equal expected, out.string
    end

    err = StringIO.new
    assert_equal 2, Iana::GeneratorCLI.run([], out: StringIO.new, err: err)
    assert_equal "usage: script/generate_iana_data.rb --check|--update\n", err.string
  end

  def test_generator_rejects_non_files_and_cleans_a_failed_atomic_replacement
    Dir.mktmpdir("iana-generator-coverage") do |directory|
      assert_raises(Iana::Error) { Generator.update!(target: directory) }

      symlink = File.join(directory, "link")
      File.symlink(File.join(ROOT, "lib/surfguard.rb"), symlink)
      assert_raises(Iana::Error) { Generator.update!(target: symlink) }

      target = File.join(directory, "surfguard.rb")
      source = File.binread(File.join(ROOT, "lib/surfguard.rb"))
      File.binwrite(target, source)
      assert Generator.check!(target: target)
      refute Generator.update!(target: target)

      File.binwrite(target, source.sub("2001::/23", "2001::/24"))
      assert_raises(Iana::Error) { Generator.check!(target: target) }
      stub_singleton(File, :rename, ->(*) { raise IOError, "simulated rename failure" }) do
        assert_raises(IOError) { Generator.update!(target: target) }
      end
      assert_empty Dir[File.join(directory, ".iana-generated*")]

      assert Generator.update!(target: target)
      assert_equal source, File.binread(target)
    end
  end

  def test_generator_empty_render_reversed_markers_and_platform_fsync
    rendered = Generator.render_region("EMPTY", [], [])
    assert_includes rendered, "EMPTY = %w["
    assert_includes rendered, "].map"

    opening = "  # iana-generator:begin EMPTY"
    closing = "  # iana-generator:end EMPTY"
    assert_raises(Iana::Error) do
      Generator.send(:replace_region, "#{closing}\n#{opening}\n", "EMPTY", "replacement")
    end
    assert_raises(Iana::Error) do
      Generator.send(:replace_region, "#{closing}\n", "EMPTY", "replacement")
    end

    assert_equal "\n", Generator.send(:source_newline, "one\ntwo\n")
    assert_equal "\r\n", Generator.send(:source_newline, "one\r\ntwo\r\n")
    assert_raises(Iana::Error) { Generator.send(:source_newline, "one\r\ntwo\n") }

    assert_nil Generator.send(:fsync_directory, ROOT, platform: "mingw32")
    stub_singleton(File, :open, ->(*) { raise Errno::ENOTSUP }) do
      assert_nil Generator.send(:fsync_directory, ROOT, platform: "ruby")
    end
  end

  def test_cli_guards_execute_only_when_loaded_as_the_program
    fake_checker = Object.new
    fake_checker.define_singleton_method(:run) { 7 }
    stub_singleton(Iana::DriftChecker, :new, fake_checker) do
      assert_nil Iana::DriftChecker.run_if_main("not-the-program", CHECKER)
      error = assert_raises(SystemExit) { Iana::DriftChecker.run_if_main(CHECKER, CHECKER) }
      assert_equal 7, error.status
    end

    assert_nil Iana::GeneratorCLI.run_if_main("not-the-program", GENERATOR_CLI, [])
    _out, _err = capture_io do
      error = assert_raises(SystemExit) do
        Iana::GeneratorCLI.run_if_main(GENERATOR_CLI, GENERATOR_CLI, [])
      end
      assert_equal 2, error.status
    end
  end

  private
    def http_response(klass: Net::HTTPOK, length: nil, chunks: [])
      response = klass.new("1.1", klass == Net::HTTPNotFound ? "404" : "200", "fixture")
      response["content-length"] = length.to_s unless length.nil?
      response.define_singleton_method(:read_body) do |&consumer|
        chunks.each(&consumer)
      end
      response
    end

    def fake_http(response)
      Object.new.tap do |http|
        http.define_singleton_method(:request) do |request, &consumer|
          @request = request
          consumer.call(response)
        end
        http.define_singleton_method(:captured_request) { @request }
      end
    end

    def with_http_response(response)
      http = fake_http(response)
      starter = ->(*, **, &block) { block.call(http) }
      stub_singleton(Net::HTTP, :start, starter) { yield }
    end

    def csv_for(schema, rows)
      csv_rows([ schema.headers ] + rows.map do |values|
        schema.headers.map { |header| values.fetch(header, "") }
      end)
    end

    def csv_rows(rows)
      rows.map do |fields|
        fields.map do |field|
          value = field.to_s
          value.match?(/[,"\r\n]/) ? %Q("#{value.gsub('"', '""')}") : value
        end.join(",")
      end.join("\r\n") + "\r\n"
    end

    def metadata_xml(schema, date)
      <<~XML
        <registry xmlns="#{Iana::IANA_XML_NAMESPACE}" id="#{schema.metadata_registry_id}">
          <updated>#{date}</updated>
        </registry>
      XML
    end

    def snapshot_data(schema, prefixes, source:)
      records = Registry.records_from_cidrs(schema, prefixes, context: "fixture")
      {
        "schema_version" => Iana::SCHEMA_VERSION,
        "registry" => schema.id,
        "url" => schema.source_url,
        "metadata_url" => schema.metadata_url,
        "registry_updated" => "2025-10-09",
        "source_sha256" => Digest::SHA256.hexdigest(source),
        "selection" => schema.selection.to_s,
        "semantic_sha256" => Registry.semantic_digest(records),
        "prefixes" => prefixes
      }
    end

    def parsed_snapshot(schema, prefixes, source:)
      Registry.parse_snapshot(schema.id, JSON.generate(snapshot_data(schema, prefixes, source: source)))
    end

    def render_ipv6(address)
      Registry.render_address(Socket::AF_INET6, IPAddr.new(address).to_i)
    end

    def assert_raises_with_message(message)
      error = assert_raises(Iana::Error) { yield }
      assert_match message, error.message
    end

    def stub_singleton(object, name, replacement)
      singleton = object.singleton_class
      visibilities = {
        public: singleton.public_instance_methods(false),
        protected: singleton.protected_instance_methods(false),
        private: singleton.private_instance_methods(false)
      }
      visibility = visibilities.find { |_kind, methods| methods.include?(name) }&.first
      original = singleton.instance_method(name) if visibility
      singleton.define_method(name) do |*arguments, **keywords, &block|
        if replacement.respond_to?(:call)
          replacement.call(*arguments, **keywords, &block)
        else
          replacement
        end
      end
      yield
    ensure
      if visibility
        singleton.define_method(name, original)
        singleton.send(visibility, name)
      else
        singleton.remove_method(name)
      end
    end
end
