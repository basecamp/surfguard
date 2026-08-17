# frozen_string_literal: true

require "tempfile"

require_relative "registry"

module Surfguard
  module Iana
    module Generator
      ROOT = File.expand_path("../..", __dir__)
      SNAPSHOT_DIRECTORY = File.join(__dir__).freeze
      DEFAULT_TARGET = File.join(ROOT, "lib/surfguard.rb").freeze
      MAX_LINE = 80

      REGIONS = {
        "IANA_ALLOCATED_IPV6_UNICAST" => {
          snapshot: "ipv6_allocated",
          comments: [
            "Generated from IANA IPv6 Global Unicast Status=ALLOCATED rows.",
            "Source provenance is checked in under script/iana."
          ]
        }.freeze,
        "IANA_SPECIAL_USE_IPV4" => {
          snapshot: "ipv4_special_use",
          comments: [
            "Every prefix in the checked-in IANA IPv4 special-purpose snapshot."
          ]
        }.freeze,
        "IANA_SPECIAL_USE_IPV6" => {
          snapshot: "ipv6_special_use",
          comments: [
            "Every prefix in the checked-in IANA IPv6 special-purpose snapshot."
          ]
        }.freeze
      }.freeze

      module_function

      def check!(target: DEFAULT_TARGET, snapshot_directory: SNAPSHOT_DIRECTORY)
        source = File.binread(target)
        expected = generated_source(source, snapshot_directory: snapshot_directory)
        return true if source == expected

        raise Error, "generated IANA constants differ; review snapshots, then run script/generate_iana_data.rb --update"
      end

      def update!(target: DEFAULT_TARGET, snapshot_directory: SNAPSHOT_DIRECTORY)
        stat = File.lstat(target)
        raise Error, "IANA generation target must be a regular non-symlink file" unless stat.file? && !stat.symlink?

        source = File.binread(target)
        generated = generated_source(source, snapshot_directory: snapshot_directory)
        return false if source == generated

        directory = File.dirname(File.expand_path(target))
        Tempfile.create([ ".iana-generated", ".tmp" ], directory) do |temporary|
          temporary.binmode
          temporary.chmod(stat.mode & 0o777)
          temporary.write(generated)
          temporary.flush
          temporary.fsync
          temporary.close
          File.rename(temporary.path, target)
          fsync_directory(directory)
        end
        true
      end

      def generated_source(source, snapshot_directory: SNAPSHOT_DIRECTORY)
        snapshots = Registry.load_snapshots(snapshot_directory)
        newline = source_newline(source)
        REGIONS.reduce(String.new(source)) do |result, (constant, settings)|
          snapshot = snapshots.fetch(settings.fetch(:snapshot))
          replacement = render_region(constant, settings.fetch(:comments), snapshot.prefixes, newline: newline)
          replace_region(result, constant, replacement)
        end
      end

      def render_region(constant, comments, prefixes, newline: "\n")
        lines = [ marker(:begin, constant) ]
        comments.each { |comment| lines << "  # #{comment}" }
        lines << "  #{constant} = %w["
        line = +"    "
        prefixes.each do |record|
          word = record.cidr
          if line.length > 4 && line.length + word.length + 1 > MAX_LINE
            lines << line.rstrip
            line = +"    "
          end
          line << word << " "
        end
        lines << line.rstrip unless line.strip.empty?
        lines << "  ].map { |cidr| IPAddr.new(cidr).freeze }.freeze"
        lines << marker(:end, constant)
        lines.join(newline)
      end

      def replace_region(source, constant, replacement)
        opening = marker(:begin, constant)
        closing = marker(:end, constant)
        opening_count = source.scan(/^#{Regexp.escape(opening)}\r?$/).length
        closing_count = source.scan(/^#{Regexp.escape(closing)}\r?$/).length
        unless opening_count == 1 && closing_count == 1
          raise Error, "expected exactly one generated region for #{constant}"
        end

        pattern = /^#{Regexp.escape(opening)}\r?\n.*?^#{Regexp.escape(closing)}(?=\r?$)/m
        matches = source.scan(pattern)
        raise Error, "expected exactly one generated region for #{constant}" unless matches.one?

        source.sub(pattern, replacement)
      end
      private_class_method :replace_region

      def source_newline(source)
        crlf = source.scan("\r\n").length
        bare_lf = source.scan(/(?<!\r)\n/).length
        raise Error, "generation target mixes line endings" if crlf.positive? && bare_lf.positive?

        crlf.positive? ? "\r\n" : "\n"
      end
      private_class_method :source_newline

      def fsync_directory(directory, platform: RUBY_PLATFORM)
        return if platform.match?(/mswin|mingw/)

        File.open(directory, File::RDONLY, &:fsync)
      rescue Errno::EISDIR, Errno::EINVAL, Errno::ENOTSUP
        # Some otherwise atomic filesystems do not expose directory fsync.
        nil
      end
      private_class_method :fsync_directory

      def marker(position, constant)
        "  # iana-generator:#{position} #{constant}"
      end
      private_class_method :marker
    end
  end
end
