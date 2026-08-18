# frozen_string_literal: true

require_relative "test_helper"

require "digest"
require "fileutils"
require "json"
require "tmpdir"

require_relative "../lib/surfguard"
require_relative "../script/check_iana_drift"
require_relative "../script/iana/generator"

class IanaSnapshotTest < Minitest::Test
  Iana = Surfguard::Iana
  Registry = Iana::Registry
  Generator = Iana::Generator
  ROOT = File.expand_path("..", __dir__)
  SNAPSHOTS = File.join(ROOT, "script/iana")

  RUNTIME_CONSTANTS = {
    "ipv4_special_use" => Surfguard::IANA_SPECIAL_USE_IPV4,
    "ipv6_allocated" => Surfguard::IANA_ALLOCATED_IPV6_UNICAST,
    "ipv6_special_use" => Surfguard::IANA_SPECIAL_USE_IPV6
  }.freeze

  def test_current_snapshots_are_schema_valid_and_match_exact_runtime_tuples
    snapshots = Registry.load_snapshots(SNAPSHOTS)
    assert_equal Iana::SCHEMAS.map(&:id).sort, snapshots.keys.sort

    snapshots.each do |id, snapshot|
      expected = snapshot.prefixes.map(&:tuple)
      actual = RUNTIME_CONSTANTS.fetch(id).map do |range|
        [ range.ipv4? ? 4 : 6, range.to_i, range.prefix ]
      end
      assert_equal expected, actual, id
      assert_equal snapshot.semantic_sha256, Registry.semantic_digest(snapshot.prefixes), id
    end
  end

  def test_prefix_length_is_part_of_snapshot_identity
    network = IPAddr.new("2001::/23")
    narrowed = IPAddr.new("2001::/128")
    assert_equal network, narrowed # IPAddr#== deliberately ignores the mask.
    refute_equal [ 6, network.to_i, network.prefix ], [ 6, narrowed.to_i, narrowed.prefix ]
  end

  def test_semantic_tuples_use_portable_ip_versions_not_socket_family_numbers
    ipv4 = Registry.records_from_cidrs(
      Registry.schema("ipv4_special_use"), [ "192.0.2.0/24" ], context: "fixture"
    ).first
    ipv6 = Registry.records_from_cidrs(
      Registry.schema("ipv6_allocated"), [ "2001::/23" ], context: "fixture"
    ).first

    assert_equal [ 4, IPAddr.new("192.0.2.0").to_i, 24 ], ipv4.tuple
    assert_equal [ 6, IPAddr.new("2001::").to_i, 23 ], ipv6.tuple
    assert_equal Digest::SHA256.hexdigest(JSON.generate([ ipv4.tuple, ipv6.tuple ])),
      Registry.semantic_digest([ ipv4, ipv6 ])
  end

  def test_generated_regions_exactly_match_snapshots_and_are_deeply_frozen
    assert Generator.check!
    RUNTIME_CONSTANTS.each_value do |ranges|
      assert_predicate ranges, :frozen?
      ranges.each { |range| assert_predicate range, :frozen? }
    end
  end

  def test_allocated_selector_admits_only_exact_allocated_status
    schema = Registry.schema("ipv6_allocated")
    body = csv_for(schema, [
      { "Prefix" => "2001::/23", "Status" => "ALLOCATED" },
      { "Prefix" => "2d00::/8", "Status" => "RESERVED" }
    ])
    assert_equal [ "2001::/23" ], Registry.parse_registry(schema, body).map(&:cidr)

    unknown = csv_for(schema, [ { "Prefix" => "2d00::/8", "Status" => "allocated" } ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, unknown) }
  end

  def test_unknown_selector_schema_and_snapshot_fields_fail_closed
    schema = Registry.schema("ipv6_allocated")
    body = csv_for(schema, [ { "Prefix" => "2001::/23", "Status" => "ALLOCATED" } ])
    bad_schema = schema.dup
    bad_schema.selection = :unknown
    assert_raises(Iana::Error) { Registry.parse_registry(bad_schema, body) }
    assert_raises(Iana::Error) { Registry.schema("not-a-registry") }

    data = snapshot_data(schema, [ "2001::/23" ], source: body)
    data["selection"] = "Status=ALLOCATED"
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }
    data["selection"] = schema.selection.to_s
    data["schema_version"] = 99
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }
    data["schema_version"] = Iana::SCHEMA_VERSION
    data["surprise"] = true
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }
  end

  def test_registry_headers_are_exact_and_code_owned
    schema = Registry.schema("ipv6_allocated")
    missing_headers = schema.headers.reject { |header| header == "Status" }
    missing_header = csv_rows([ missing_headers, [ "2001::/23" ] ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, missing_header) }

    reordered = schema.dup
    reordered.headers = schema.headers.reverse.freeze
    body = csv_for(reordered, [ { "Prefix" => "2001::/23", "Status" => "ALLOCATED" } ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, body) }
  end

  def test_current_footnotes_multi_prefix_fields_and_intentional_overlaps_normalize
    schema = Registry.schema("ipv4_special_use")
    body = csv_for(schema, [
      { "Address Block" => "192.0.0.0/24 [2]" },
      { "Address Block" => "192.0.0.8/32" },
      { "Address Block" => "192.0.0.170/32, 192.0.0.171/32" },
      { "Address Block" => "198.18.0.0/15 [1] [9]" }
    ])
    assert_equal %w[
      192.0.0.0/24 192.0.0.8/32 192.0.0.170/32 192.0.0.171/32 198.18.0.0/15
    ], Registry.parse_registry(schema, body).map(&:cidr)
  end

  def test_invalid_noncanonical_wrong_family_annotated_and_duplicate_prefixes_fail_closed
    schema = Registry.schema("ipv4_special_use")
    invalid = [
      "192.0.2.1/24",
      "192.0.002.0/24",
      "2001:db8::/32",
      "192.0.2.0/33",
      "192.0.2.0/24 [RFC]"
    ]
    invalid.each do |prefix|
      body = csv_for(schema, [ { "Address Block" => prefix } ])
      assert_raises(Iana::Error, prefix) { Registry.parse_registry(schema, body) }
    end

    duplicate = csv_for(schema, [
      { "Address Block" => "192.0.2.0/24" },
      { "Address Block" => "192.0.2.0/24" }
    ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, duplicate) }
  end

  def test_snapshot_semantic_digest_and_metadata_are_validated
    schema = Registry.schema("ipv4_special_use")
    body = csv_for(schema, [ { "Address Block" => "192.0.2.0/24" } ])
    data = snapshot_data(schema, [ "192.0.2.0/24" ], source: body)
    data["semantic_sha256"] = "0" * 64
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }

    data = snapshot_data(schema, [ "192.0.2.0/24" ], source: body)
    data["url"] = "https://www.iana.org/unreviewed.csv"
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }

    data = snapshot_data(schema, [ "192.0.2.0/24" ], source: body)
    valid = JSON.generate(data)
    assert_equal "{", valid.byteslice(0)
    object_body = valid.byteslice(1..)
    duplicate = %({"url":"https://attacker.invalid/decoy.csv",) + object_body
    escaped_duplicate = %({"\\u0075rl":"https://attacker.invalid/decoy.csv",) + object_body
    [ duplicate, escaped_duplicate ].each do |snapshot|
      error = assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, snapshot) }
      assert_match(/duplicate JSON object field/, error.message)
    end
  end

  def test_raw_semantic_and_metadata_drift_are_reported_independently
    schema = Registry.schema("ipv4_special_use")
    original = csv_for(schema, [ { "Address Block" => "192.0.2.0/24", "Name" => "original" } ])
    description_only = csv_for(schema, [ { "Address Block" => "192.0.2.0/24", "Name" => "reworded" } ])
    metadata = metadata_xml(schema, "2025-10-09")
    checker = Iana::DriftChecker.new

    snapshot = parsed_snapshot(schema, [ "192.0.2.0/24" ], source: original)
    result = checker.audit(snapshot, source: description_only, metadata: metadata)
    assert_equal 1, result.issues.length
    assert_match(/raw source SHA-256 drift/, result.issues.first)

    changed_policy = csv_for(schema, [ { "Address Block" => "198.51.100.0/24" } ])
    snapshot = parsed_snapshot(schema, [ "192.0.2.0/24" ], source: changed_policy)
    result = checker.audit(snapshot, source: changed_policy, metadata: metadata)
    assert_equal 1, result.issues.length
    assert_match(/semantic policy drift.*added.*removed/, result.issues.first)

    snapshot = parsed_snapshot(schema, [ "192.0.2.0/24" ], source: original)
    result = checker.audit(snapshot, source: original,
      metadata: metadata_xml(schema, "2025-10-10"))
    assert_equal [ "registry update date drift: expected 2025-10-09, got 2025-10-10" ], result.issues
  end

  def test_registry_metadata_requires_one_update_date
    schema = Registry.schema("ipv4_special_use")
    assert_equal "2025-10-09", Registry.registry_updated(metadata_xml(schema, "2025-10-09"), id: schema.id)
    assert_raises(Iana::Error) { Registry.registry_updated("<registry/>") }
    assert_raises(Iana::Error) { Registry.registry_updated(metadata_xml(schema, "2025-02-29"), id: schema.id) }
    assert_equal "2024-02-29", Registry.registry_updated(metadata_xml(schema, "2024-02-29"), id: schema.id)

    duplicate = metadata_xml(schema, "2025-10-09", extra: "<updated>2025-10-10</updated>")
    assert_raises(Iana::Error) { Registry.registry_updated(duplicate, id: schema.id) }
    assert_raises(Iana::Error) do
      Registry.registry_updated("not XML <updated>2025-10-09</updated> at all")
    end
    assert_raises(Iana::Error) do
      Registry.registry_updated(%(<!DOCTYPE registry><registry xmlns="#{Iana::IANA_XML_NAMESPACE}"/>))
    end
    wrong_identity = metadata_xml(schema, "2025-10-09").sub(schema.metadata_registry_id, "other-registry")
    assert_raises(Iana::Error) { Registry.registry_updated(wrong_identity, id: schema.id) }

    source = csv_for(schema, [ { "Address Block" => "192.0.2.0/24" } ])
    data = snapshot_data(schema, [ "192.0.2.0/24" ], source: source)
    data["registry_updated"] = "2025-02-29"
    assert_raises(Iana::Error) { Registry.parse_snapshot(schema.id, JSON.generate(data)) }
  end

  def test_csv_parser_handles_quoted_content_and_rejects_malformed_records
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

    schema = Registry.schema("ipv6_allocated")
    wrong_field_count = csv_rows([ schema.headers, [ "2001::/23" ] ])
    assert_raises(Iana::Error) { Registry.parse_registry(schema, wrong_field_count) }
  end

  def test_generator_check_is_read_only_and_update_repairs_only_generated_regions
    Dir.mktmpdir("surfguard-iana-generator") do |directory|
      target = File.join(directory, "surfguard.rb")
      source = File.binread(File.join(ROOT, "lib/surfguard.rb"))
      changed = source.sub("2001::/23", "2001::/24")
      File.binwrite(target, changed)
      File.chmod(0o640, target)

      assert_raises(Iana::Error) { Generator.check!(target: target) }
      assert_equal changed, File.binread(target)
      assert Generator.update!(target: target)
      assert_equal source, File.binread(target)
      assert_equal 0o640, File.stat(target).mode & 0o777
      assert Generator.check!(target: target)
      refute Generator.update!(target: target)
      assert_empty Dir[File.join(directory, ".iana-generated*")]
    end
  end

  def test_generator_rejects_duplicate_or_missing_markers
    source = File.binread(File.join(ROOT, "lib/surfguard.rb"))
    marker = "  # iana-generator:begin IANA_ALLOCATED_IPV6_UNICAST"

    assert_raises(Iana::Error) { Generator.generated_source(source.sub(marker, "")) }
    assert_raises(Iana::Error) { Generator.generated_source(source.sub(marker, "#{marker}\n#{marker}")) }
  end

  def test_generator_preserves_crlf_and_rejects_mixed_line_endings
    Dir.mktmpdir("surfguard-iana-generator-crlf") do |directory|
      target = File.join(directory, "surfguard.rb")
      source = File.binread(File.join(ROOT, "lib/surfguard.rb")).gsub("\n", "\r\n")
      File.binwrite(target, source)

      assert Generator.check!(target: target)
      changed = source.sub("2001::/23", "2001::/24")
      File.binwrite(target, changed)
      assert Generator.update!(target: target)
      assert_equal source, File.binread(target)
      assert Generator.check!(target: target)

      mixed = source.sub("\r\n", "\n")
      error = assert_raises(Iana::Error) { Generator.generated_source(mixed) }
      assert_equal "generation target mixes line endings", error.message
    end
  end

  def test_generator_tolerates_filesystems_without_directory_fsync
    original = File.method(:open)
    File.define_singleton_method(:open) { |*| raise Errno::EINVAL }
    assert_nil Generator.send(:fsync_directory, ROOT)
  ensure
    File.define_singleton_method(:open, original) if original
  end

  private
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

    def parsed_snapshot(schema, prefixes, source:)
      Registry.parse_snapshot(schema.id, JSON.generate(snapshot_data(schema, prefixes, source: source)))
    end

    def metadata_xml(schema, date, extra: "")
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <registry xmlns="#{Iana::IANA_XML_NAMESPACE}" id="#{schema.metadata_registry_id}">
          <updated>#{date}</updated>#{extra}
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
end
