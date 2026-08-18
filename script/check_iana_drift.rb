# frozen_string_literal: true

require "digest"
require "net/http"
require "uri"

require_relative "iana/registry"

module Surfguard
  module Iana
    class HttpFetcher
      MAX_BYTES = 1 << 20

      def call(url, accept:)
        uri = URI(url)
        unless uri.is_a?(URI::HTTPS) && uri.host == "www.iana.org" && uri.port == 443 &&
            uri.userinfo.nil? && uri.query.nil? && uri.fragment.nil?
          raise Error, "IANA source must use its code-owned exact HTTPS origin"
        end

        Net::HTTP.start(uri.host, uri.port, nil, nil, nil, nil, use_ssl: true,
          open_timeout: 10, read_timeout: 20) do |http|
          request = Net::HTTP::Get.new(uri)
          request["Accept"] = accept
          body = nil
          http.request(request) do |response|
            raise Error, "#{uri}: HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

            declared = declared_length(response["content-length"], uri)
            raise Error, "#{uri}: declared body exceeds #{MAX_BYTES} bytes" if declared && declared > MAX_BYTES

            body = +""
            response.read_body do |chunk|
              body << chunk
              raise Error, "#{uri}: body exceeds #{MAX_BYTES} bytes" if body.bytesize > MAX_BYTES
            end
            body.force_encoding(Encoding::UTF_8)
          end
          body
        end
      rescue URI::InvalidURIError => error
        raise Error, "invalid code-owned IANA URL: #{error.message}"
      end

      private
        def declared_length(value, uri)
          return unless value

          length = Integer(value, 10)
          raise Error, "#{uri}: invalid declared body length" if length.negative?

          length
        rescue ArgumentError
          raise Error, "#{uri}: invalid declared body length"
        end
    end

    class DriftChecker
      Result = Struct.new(:snapshot, :actual_digest, :prefix_count, :issues, keyword_init: true)

      def self.run_if_main(program_name, file_name)
        return unless program_name == file_name

        exit new.run
      end

      def initialize(fetcher: HttpFetcher.new, snapshot_directory: File.join(__dir__, "iana"))
        @fetcher = fetcher
        @snapshot_directory = snapshot_directory
      end

      def run(out: $stdout, err: $stderr)
        snapshots = Registry.load_snapshots(@snapshot_directory)
        failed = false
        SCHEMAS.each do |schema|
          result = check(snapshots.fetch(schema.id))
          if result.issues.empty?
            out.puts "IANA drift check: #{schema.snapshot_file} ok " \
              "(#{result.prefix_count} prefixes, #{result.actual_digest})"
          else
            failed = true
            err.puts "IANA drift check: #{schema.snapshot_file} FAILED"
            result.issues.each { |issue| err.puts "  - #{issue}" }
          end
        end
        failed ? 1 : 0
      rescue Error => error
        err.puts "IANA drift check failed closed: #{error.message}"
        1
      end

      def check(snapshot)
        source = @fetcher.call(snapshot.schema.source_url, accept: "text/csv")
        metadata = @fetcher.call(snapshot.schema.metadata_url, accept: "application/xml")
        audit(snapshot, source: source, metadata: metadata)
      end

      def audit(snapshot, source:, metadata:)
        issues = []
        actual_digest = Digest::SHA256.hexdigest(source)
        unless actual_digest == snapshot.source_sha256
          issues << "raw source SHA-256 drift: expected #{snapshot.source_sha256}, got #{actual_digest}"
        end

        actual_prefixes = nil
        begin
          actual_prefixes = Registry.parse_registry(snapshot.schema, source)
          semantic_issues(snapshot.prefixes, actual_prefixes).each { |issue| issues << issue }
        rescue Error => error
          issues << "semantic registry parse failed: #{error.message}"
        end

        begin
          actual_updated = Registry.registry_updated(metadata, id: snapshot.schema.id)
          unless actual_updated == snapshot.registry_updated
            issues << "registry update date drift: expected #{snapshot.registry_updated}, got #{actual_updated}"
          end
        rescue Error => error
          issues << "registry metadata parse failed: #{error.message}"
        end

        Result.new(
          snapshot: snapshot,
          actual_digest: actual_digest.freeze,
          prefix_count: actual_prefixes&.length || 0,
          issues: issues.freeze
        ).freeze
      end

      private
        def semantic_issues(expected, actual)
          expected_by_tuple = expected.to_h { |record| [ record.tuple, record.cidr ] }
          actual_by_tuple = actual.to_h { |record| [ record.tuple, record.cidr ] }
          added = actual_by_tuple.keys - expected_by_tuple.keys
          removed = expected_by_tuple.keys - actual_by_tuple.keys
          return [] if added.empty? && removed.empty?

          details = []
          details << "added #{added.map { |tuple| actual_by_tuple.fetch(tuple) }.sort.inspect}" unless added.empty?
          details << "removed #{removed.map { |tuple| expected_by_tuple.fetch(tuple) }.sort.inspect}" unless removed.empty?
          [ "semantic policy drift: #{details.join('; ')}" ]
        end
    end
  end
end

Surfguard::Iana::DriftChecker.run_if_main($PROGRAM_NAME, __FILE__)
