# frozen_string_literal: true

require "rubygems/package"
require "tmpdir"

module Surfguard
  module Release
    # Verifies a freshly built .gem end to end: archive integrity, spec
    # identity, exact contents, zero runtime dependencies, and a real
    # install + require into an isolated GEM_HOME. Run on every build,
    # rehearsals included. Fails closed on the first problem.
    class PackageVerification
      class Failure < StandardError; end

      REQUIRED_FILES = %w[ lib/surfguard.rb lib/surfguard/version.rb README.md LICENSE SECURITY.md ].freeze
      ALLOWED_PATTERNS = [ %r{\Alib/.+\.rb\z}, /\AREADME\.md\z/, /\ALICENSE\z/, /\ASECURITY\.md\z/ ].freeze

      # Keep child processes honest: no bundler, ruby options, or load-path
      # additions leaking in from CI — RUBYLIB especially, which could let
      # `require "surfguard"` resolve from the checkout instead of the
      # installed gem and wave a broken package through.
      CLEAN_ENV = {
        "RUBYOPT" => nil, "RUBYLIB" => nil,
        "BUNDLE_GEMFILE" => nil, "BUNDLE_PATH" => nil
      }.freeze

      # Live wiring: subprocesses run for real. Tests inject a scripted runner.
      # simplecov:disable
      def self.live(gem_file, name:, version:, out: $stdout)
        new(gem_file, name: name, version: version, out: out,
            runner: ->(env, *command) { Kernel.system(env, *command) })
      end
      # simplecov:enable

      # CLI entry point; returns a process exit status.
      def self.run(argv, out: $stdout, err: $stderr, verification_for: method(:live))
        gem_file, name, version = argv
        if argv.size != 3
          err.puts "usage: verify_package.rb GEM_FILE NAME VERSION"
          return 2
        end
        unless File.file?(gem_file)
          err.puts "no such file: #{gem_file}"
          return 2
        end

        verification_for.call(gem_file, name: name, version: version, out: out).verify!
        0
      rescue Failure => e
        err.puts "verify_package: #{e.message}"
        1
      end

      def initialize(gem_file, name:, version:, runner:, out: $stdout)
        @gem_file = gem_file
        @name = name
        @version = version
        @runner = runner
        @out = out
      end

      def verify!
        package = check("archive integrity (Gem::Package#verify)") do
          Gem::Package.new(@gem_file).tap(&:verify)
        end
        spec = package.spec

        check("spec name is #{@name}") do
          raise "got #{spec.name.inspect}" unless spec.name == @name
        end

        check("spec version is #{@version}") do
          raise "got #{spec.version}" unless spec.version.to_s == @version
        end

        check("zero runtime dependencies") do
          deps = spec.runtime_dependencies
          raise "got: #{deps.map(&:name).sort.join(", ")}" unless deps.empty?
        end

        contents = package.contents
        @out.puts "verify: archive contents:"
        contents.sort.each { |path| @out.puts "  #{path}" }

        check("required files all present") do
          missing = REQUIRED_FILES - contents
          raise "missing: #{missing.join(", ")}" unless missing.empty?
        end

        check("no unexpected files") do
          unexpected = contents.reject { |path| ALLOWED_PATTERNS.any? { |pattern| pattern.match?(path) } }
          raise "unexpected: #{unexpected.sort.join(", ")}" unless unexpected.empty?
        end

        check("installs and requires cleanly in an isolated GEM_HOME") do
          Dir.mktmpdir("#{@name}-verify") do |gem_home|
            env = CLEAN_ENV.merge("GEM_HOME" => gem_home, "GEM_PATH" => gem_home)

            unless @runner.call(env, "gem", "install", "--local", "--no-document", @gem_file)
              raise "gem install failed"
            end

            probe = %(require "surfguard"; abort "version mismatch: \#{Surfguard::VERSION}" unless Surfguard::VERSION == ARGV[0])
            unless @runner.call(env, "ruby", "-e", probe, @version)
              raise "require probe failed"
            end
          end
        end

        @out.puts "verify: #{File.basename(@gem_file)} passed all checks"
        true
      end

      private
        def check(description)
          @out.print "verify: #{description}... "
          result = yield
          @out.puts "ok"
          result
        rescue StandardError => e
          @out.puts "FAIL"
          raise Failure, "#{description}: #{e.message}"
        end
    end
  end
end
