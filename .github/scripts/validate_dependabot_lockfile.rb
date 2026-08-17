# frozen_string_literal: true

require "rubygems"

module Surfguard
  module DependabotLockfileValidator
    class Error < StandardError; end

    module_function

    def run(argv, out: $stdout, err: $stderr)
      unless argv.length == 4
        err.puts "usage: validator BASE_LOCK HEAD_LOCK ECOSYSTEM UPDATE_TYPE"
        return 2
      end

      out.puts validate(*argv)
      0
    rescue Error => error
      err.puts error.message
      1
    end

    def validate(base_path, head_path, ecosystem, expected_update)
      raise Error, "ecosystem must be bundler" unless ecosystem == "bundler"

      base = parse_lock(base_path)
      head = parse_lock(head_path)
      unless base[:specs].keys.sort == head[:specs].keys.sort
        raise Error, "dependency identities were added or removed"
      end
      raise Error, "top-level dependency structure changed" unless base[:dependencies] == head[:dependencies]
      raise Error, "platform structure changed" unless base[:platforms] == head[:platforms]
      raise Error, "local path source changed" unless base[:path] == head[:path]

      changed = base[:specs].keys.select { |name| base[:specs][name] != head[:specs][name] }
      raise Error, "automatic update must change exactly one unambiguous dependency" unless changed.one?

      name = changed.first
      from = base[:specs].fetch(name)
      to = head[:specs].fetch(name)
      raise Error, "dependency did not increase" unless to > from
      raise Error, "prerelease updates require human review" if from.prerelease? || to.prerelease?
      unless from.segments.fetch(0, 0) == to.segments.fetch(0, 0)
        raise Error, "major updates require human review"
      end

      verify_checksums(base, head, name)

      actual_update = if from.segments.fetch(1, 0) == to.segments.fetch(1, 0)
        "version-update:semver-patch"
      else
        "version-update:semver-minor"
      end
      unless expected_update == actual_update
        raise Error, "metadata update type mismatch: #{expected_update} != #{actual_update}"
      end

      # Apart from versions and checksum records, the lockfile grammar must
      # remain byte-identical. This rejects dependency-edge and structural changes.
      unless normalize(base[:text]) == normalize(head[:text])
        raise Error, "lockfile changed outside version/checksum records"
      end
      unless base[:direct_dependencies].include?(name)
        raise Error, "transitive dependency updates require human review"
      end

      "validated bundler #{actual_update}: #{name} #{from} -> #{to}"
    end

    def parse_lock(path)
      text = File.binread(path)
      unless text.valid_encoding? && text.ascii_only? && !text.include?("\0")
        raise Error, "invalid lockfile encoding"
      end
      if text.match?(/\A(?:GIT|PLUGIN)\n|\n(?:GIT|PLUGIN)\n/)
        raise Error, "forbidden lockfile source section"
      end
      raise Error, "lockfile must contain exactly one GEM section" unless text.scan(/^GEM$/).one?
      raise Error, "lockfile must contain exactly one PATH section" unless text.scan(/^PATH$/).one?
      unless text.scan(/^CHECKSUMS$/).one?
        raise Error, "lockfile must contain exactly one CHECKSUMS section"
      end

      gem_section = text[/^GEM\n(.*?)(?=\n[A-Z][A-Z ]+\n|\z)/m, 1]
      remotes = gem_section.scan(/^  remote: (.+)$/).flatten
      unless remotes == [ "https://rubygems.org/" ]
        raise Error, "lockfile must use only canonical RubyGems HTTPS source"
      end
      path_section = text[/^PATH\n(.*?)(?=\n[A-Z][A-Z ]+\n|\z)/m, 1]
      unless path_section.match?(/\A  remote: \.\n  specs:\n    surfguard \([^\n]+\)\n\z/)
        raise Error, "unexpected local path source"
      end

      specs, raw_versions = parse_specs(gem_section)
      raise Error, "lockfile has no RubyGems specs" if specs.empty?

      dependencies = text[/^DEPENDENCIES\n(.*?)(?=\n[A-Z][A-Z ]+\n|\z)/m, 1]
      platforms = text[/^PLATFORMS\n(.*?)(?=\n[A-Z][A-Z ]+\n|\z)/m, 1]
      checksum_section = text[/^CHECKSUMS\n(.*?)(?=\n[A-Z][A-Z ]+\n|\z)/m, 1]
      unless dependencies && platforms
        raise Error, "missing structural section"
      end

      checksums = parse_checksums(checksum_section)
      raise Error, "lockfile has no checksum records" if checksums.empty?
      direct_dependencies = parse_direct_dependencies(dependencies)

      {
        text: text,
        specs: specs,
        raw_versions: raw_versions,
        checksums: checksums,
        direct_dependencies: direct_dependencies,
        dependencies: dependencies,
        platforms: platforms,
        path: path_section
      }
    rescue SystemCallError => error
      raise Error, "lockfile could not be read: #{error.message}"
    end

    def parse_specs(text)
      specs = {}
      raw_versions = {}
      text.scan(/^    ([A-Za-z0-9_.-]+) \(([^ ()]+)(?:-[^ ()]+)?\)$/).each do |name, version|
        raise Error, "ambiguous duplicate dependency #{name}" if specs.key?(name)

        specs[name] = Gem::Version.new(version)
        raw_versions[name] = version
      rescue ArgumentError
        raise Error, "invalid dependency version for #{name}"
      end
      [ specs, raw_versions ]
    end

    def parse_checksums(section)
      checksums = {}
      section.lines.each do |line|
        next if line == "\n"

        match = line.match(/\A  ([A-Za-z0-9_.-]+) \(([^ ()]+)\)(?: sha256=([0-9a-f]{64}))?\n?\z/)
        raise Error, "malformed checksum record" unless match

        name, version, digest = match.captures
        key = [ name, version ]
        raise Error, "ambiguous duplicate checksum #{name} #{version}" if checksums.key?(key)

        checksums[key] = digest
      end
      checksums
    end

    def parse_direct_dependencies(section)
      dependencies = section.lines.map do |line|
        next if line == "\n"

        match = line.match(/\A  ([A-Za-z0-9_.-]+)(?: \([^\n]+\))?(!)?\n?\z/)
        raise Error, "malformed top-level dependency record" unless match

        match[2] ? nil : match[1]
      end.compact
      unless dependencies.uniq == dependencies
        raise Error, "ambiguous duplicate top-level dependency"
      end

      dependencies.freeze
    end

    def verify_checksums(base, head, name)
      base_changed = base[:checksums].select { |(dependency, _version), _digest| dependency == name }
      head_changed = head[:checksums].select { |(dependency, _version), _digest| dependency == name }
      expected_base_key = [ name, base[:raw_versions].fetch(name) ]
      expected_head_key = [ name, head[:raw_versions].fetch(name) ]
      unless base_changed.keys == [ expected_base_key ]
        raise Error, "changed dependency must have exactly one matching base checksum"
      end
      unless head_changed.keys == [ expected_head_key ]
        raise Error, "changed dependency must have exactly one matching head checksum"
      end
      if (base_changed.values + head_changed.values).any?(&:nil?)
        raise Error, "changed dependency checksum is missing"
      end
      if base_changed.values == head_changed.values
        raise Error, "changed dependency checksum did not change"
      end

      base_unchanged = base[:checksums].reject { |(dependency, _version), _digest| dependency == name }
      head_unchanged = head[:checksums].reject { |(dependency, _version), _digest| dependency == name }
      raise Error, "unrelated checksum records changed" unless base_unchanged == head_unchanged
    end

    def normalize(text)
      text.lines.reject { |line| line.match?(/^CHECKSUMS\n|^  [A-Za-z0-9_.-]+ \([^\n]+\) sha256=/) }
        .map { |line| line.sub(/^(    [A-Za-z0-9_.-]+) \([^\n]+\)$/, '\1 (VERSION)') }
        .join
    end

    def main(program_name: $PROGRAM_NAME, file: __FILE__, argv: ARGV)
      return unless program_name == file

      exit run(argv)
    end
  end
end

Surfguard::DependabotLockfileValidator.main
