# frozen_string_literal: true

require "resolv"
require "rubygems"

module SurfguardRelease
  module ResolvVersionCheck
    VULNERABLE_RANGES = [
      [ nil, Gem::Version.new("0.2.3") ],
      [ Gem::Version.new("0.3.0"), Gem::Version.new("0.3.1") ],
      [ Gem::Version.new("0.4.0"), Gem::Version.new("0.6.2") ]
    ].freeze

    module_function

    def vulnerable?(version)
      parsed = Gem::Version.new(version.to_s)
      VULNERABLE_RANGES.any? do |lower, upper|
        (lower.nil? || parsed >= lower) && parsed < upper
      end
    end

    def current_version(loaded_specs: Gem.loaded_specs, available_specs: Gem::Specification.find_all_by_name("resolv"))
      specification = loaded_specs["resolv"] || available_specs.find(&:default_gem?)
      raise "could not identify the effective resolv version" unless specification

      Gem::Version.new(specification.version.to_s)
    end

    def main(version: current_version, output: $stdout, error: $stderr)
      parsed = Gem::Version.new(version.to_s)
      if vulnerable?(parsed)
        error.puts "unsupported vulnerable resolv #{parsed}"
        return 1
      end

      output.puts "resolv #{parsed}: supported"
      0
    end

    def cli(program_name: $PROGRAM_NAME, file: __FILE__)
      return unless program_name == file

      exit main
    end
  end
end

SurfguardRelease::ResolvVersionCheck.cli
