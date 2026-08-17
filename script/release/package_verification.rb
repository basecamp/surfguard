# frozen_string_literal: true

require "digest"
require "open3"
require "rubygems/package"
require "stringio"
require "tmpdir"
require "zlib"

module Surfguard
  module Release
    class PackageVerification
      class Failure < StandardError; end

      # RubyGems canonicalizes spec.files lexicographically when serializing.
      REQUIRED_FILES = %w[LICENSE README.md SECURITY.md lib/surfguard.rb lib/surfguard/version.rb].freeze
      OUTER_MEMBERS = %w[metadata.gz data.tar.gz checksums.yaml.gz].freeze
      REGULAR_TYPEFLAGS = [ "0", "\0", "" ].freeze
      TAR_BLOCK_SIZE = 512
      MAX_GEM_BYTES = 16 << 20
      MAX_ARCHIVE_MEMBERS = 64
      MAX_METADATA_BYTES = 1 << 20
      MAX_CHECKSUM_BYTES = 1 << 20
      MAX_DATA_TAR_BYTES = 16 << 20
      CORE_TEST_FILES = %w[test/surfguard_hardening_test.rb test/surfguard_test.rb].freeze
      SUMMARY = "One SSRF address policy: resolve a host and classify special-use IPv4/IPv6 ranges"
      DESCRIPTION = "Surfguard resolves a hostname to the public IP addresses it points at and refuses anything that would reach an internal network: private, loopback, link-local and carrier-grade NAT space, plus the IPv6 transition ranges a naive guard misses (IPv4-mapped, SIIT, NAT64, 6to4, Teredo). It resolves and classifies only; the caller owns the fetch and pins the connection to a returned address so DNS rebinding cannot swap in a blocked one. Standard library only, no runtime dependencies."
      CLEAN_ENV = {
        "RUBYOPT" => nil, "RUBYLIB" => nil, "RUBYGEMS_GEMDEPS" => nil,
        "BUNDLE_GEMFILE" => nil, "BUNDLE_LOCKFILE" => nil, "BUNDLE_PATH" => nil,
        "BUNDLE_APP_CONFIG" => nil, "BUNDLE_BIN_PATH" => nil, "BUNDLER_SETUP" => nil,
        "BUNDLER_VERSION" => nil
      }.freeze

      def self.live(gem_file, name:, version:, source_commit:, out: $stdout)
        new(gem_file, name: name, version: version, source_commit: source_commit, out: out,
          suite_root: ENV.fetch("SURFGUARD_SUITE_ROOT", "."),
          runner: ->(env, *command) { Kernel.system(env, *command) })
      end

      def self.run(argv, out: $stdout, err: $stderr, verification_for: method(:live))
        gem_file, name, version, source_commit = argv
        object_id = /\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/
        unless argv.size == 4 && String === source_commit && source_commit.match?(object_id)
          err.puts "usage: verify_package.rb GEM_FILE NAME VERSION IMMUTABLE_COMMIT_SHA"
          return 2
        end
        unless File.file?(gem_file)
          err.puts "no such file: #{gem_file}"
          return 2
        end

        verification_for.call(gem_file, name: name, version: version,
          source_commit: source_commit, out: out).verify!
        0
      rescue Failure => error
        err.puts "verify_package: #{error.message}"
        1
      end

      def self.run_if_main(program_name, file_name, argv, runner: method(:run))
        return unless program_name == file_name

        exit runner.call(argv)
      end

      def initialize(gem_file, name:, version:, runner:, source_commit: nil, source_reader: nil,
        suite_root: ".", out: $stdout, capture: Open3.method(:capture3))
        @gem_file = gem_file
        @name = name
        @version = version
        @runner = runner
        @source_commit = source_commit
        @source_reader = source_reader
        @suite_root = suite_root
        @out = out
        @capture = capture
      end

      def verify!
        with_private_snapshot do |snapshot|
          entries = check("raw nested archive structure") { inspect_raw_archive(snapshot.fetch(:bytes)) }
          package = check("archive integrity") { Gem::Package.new(snapshot.fetch(:path)).tap(&:verify) }
          spec = package.spec

          check("exact package specification") { verify_spec(spec) }
          check("exact packaged files") { verify_file_set(spec.files, entries.keys) }
          check("immutable source commit identity") { verify_source_commit! } if @source_commit
          if @source_commit || @source_reader
            check("packaged bytes and modes match immutable source") { compare_source(entries) }
          end
          check("isolated install, loaded-feature identity, and installed core suite") do
            verify_installed(snapshot.fetch(:path))
          end
          check("source and private snapshot remained byte-identical") { verify_snapshot_unchanged(snapshot) }
        end

        @out.puts "verify: #{File.basename(@gem_file)} passed all checks"
        true
      rescue Failure
        raise
      rescue StandardError => error
        raise Failure, "private artifact snapshot: #{error.message}"
      end

      private
        def with_private_snapshot
          source_flags = File::RDONLY
          source_lstat = File.lstat(@gem_file)
          raise "source artifact is not a regular file" unless source_lstat.file? && !source_lstat.symlink?

          File.open(@gem_file, source_flags) do |source|
            source.binmode
            source_stat = source.stat
            unless source_stat.file? && same_identity?(source_stat, source_lstat)
              raise "source artifact changed while opening"
            end

            bytes = read_io_bounded(source, MAX_GEM_BYTES, "gem").freeze
            digest = Digest::SHA256.hexdigest(bytes).freeze
            Dir.mktmpdir("surfguard-package-snapshot") do |directory|
              snapshot_path = File.join(directory, "artifact.gem")
              snapshot_stat = write_private_snapshot(snapshot_path, bytes)
              snapshot = {
                path: snapshot_path.freeze,
                bytes: bytes,
                digest: digest,
                source: source,
                source_identity: [ source_stat.dev, source_stat.ino ].freeze,
                snapshot_identity: [ snapshot_stat.dev, snapshot_stat.ino ].freeze
              }.freeze
              yield snapshot
            end
          end
        end

        def write_private_snapshot(path, bytes)
          File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.binmode
            offset = 0
            while offset < bytes.bytesize
              written = file.write(bytes.byteslice(offset..))
              raise "private snapshot write made no progress" unless written.positive?

              offset += written
            end
            file.flush
            file.fsync
            file.stat
          end
        end

        def verify_snapshot_unchanged(snapshot)
          source_stat = File.lstat(@gem_file)
          unless source_stat.file? && !source_stat.symlink? &&
              [ source_stat.dev, source_stat.ino ] == snapshot.fetch(:source_identity)
            raise "source artifact identity changed during verification"
          end
          source_bytes = read_io_bounded(snapshot.fetch(:source), MAX_GEM_BYTES, "gem")
          raise "source artifact bytes changed during verification" unless Digest::SHA256.hexdigest(source_bytes) == snapshot.fetch(:digest)

          snapshot_path = snapshot.fetch(:path)
          snapshot_stat = File.lstat(snapshot_path)
          unless snapshot_stat.file? && !snapshot_stat.symlink? &&
              [ snapshot_stat.dev, snapshot_stat.ino ] == snapshot.fetch(:snapshot_identity)
            raise "private snapshot identity changed during verification"
          end
          File.open(snapshot_path, "rb") do |file|
            private_bytes = read_io_bounded(file, MAX_GEM_BYTES, "private snapshot")
            unless Digest::SHA256.hexdigest(private_bytes) == snapshot.fetch(:digest)
              raise "private snapshot bytes changed during verification"
            end
          end
        end

        def same_identity?(left, right)
          [ left.dev, left.ino ] == [ right.dev, right.ino ]
        end

        def read_io_bounded(file, limit, label)
          file.rewind
          bytes = file.read(limit + 1)
          raise "#{label} exceeds #{limit} bytes" if bytes.bytesize > limit

          bytes
        end

        def inspect_raw_archive(bytes)
          outer = read_tar(bytes, outer: true, limit: MAX_GEM_BYTES)
          raise "outer members differ: #{outer.keys.sort.inspect}" unless outer.keys.sort == OUTER_MEMBERS.sort

          read_gzip(outer.fetch("metadata.gz").fetch(:data), limit: MAX_METADATA_BYTES, label: "metadata.gz")
          read_gzip(outer.fetch("checksums.yaml.gz").fetch(:data), limit: MAX_CHECKSUM_BYTES,
            label: "checksums.yaml.gz")
          compressed = outer.fetch("data.tar.gz").fetch(:data)
          data_tar = read_gzip(compressed, limit: MAX_DATA_TAR_BYTES, label: "data.tar.gz")
          read_tar(data_tar, outer: false, limit: MAX_DATA_TAR_BYTES)
        rescue Gem::Package::TarInvalidError, Zlib::Error, EOFError => error
          raise "invalid archive: #{error.message}"
        end

        def read_gzip(bytes, limit:, label:)
          input = StringIO.new(bytes)
          reader = Zlib::GzipReader.new(input)
          output = +"".b
          while (chunk = reader.read(16_384))
            output << chunk
            raise "#{label} expands beyond #{limit} bytes" if output.bytesize > limit
          end
          trailing = reader.unused
          unread = input.pos < bytes.bytesize
          raise "#{label} contains trailing gzip data" if unread || (trailing && !trailing.empty?)

          output
        ensure
          reader&.close
        end

        def read_tar(bytes, outer:, limit:)
          raise "tar exceeds #{limit} bytes" if bytes.bytesize > limit
          raise "tar length is not block-aligned" unless (bytes.bytesize % TAR_BLOCK_SIZE).zero?

          entries = {}
          canonical = {}
          input = StringIO.new(bytes)
          Gem::Package::TarReader.new(input) do |tar|
            tar.each do |entry|
              raise "archive contains too many members" if entries.size >= MAX_ARCHIVE_MEMBERS

              path = entry.full_name
              validate_path!(path)
              raise "duplicate member #{path.inspect}" if entries.key?(path)
              collision_key = path.unicode_normalize(:nfc).downcase
              raise "colliding member #{path.inspect}" if canonical.key?(collision_key)

              header = entry.header
              typeflag = header.typeflag.to_s
              unless REGULAR_TYPEFLAGS.include?(typeflag)
                raise "non-regular member #{path.inspect} (type #{typeflag.inspect})"
              end
              raise "member #{path.inspect} exceeds archive limit" if header.size > limit
              mode = header.mode & 0o7777
              permitted = outer ? [ 0o444, 0o644 ] : [ 0o644 ]
              unless permitted.include?(mode)
                raise "abnormal mode #{format('%04o', mode)} for #{path.inspect}"
              end

              canonical[collision_key] = path
              data = entry.read
              raise "truncated member #{path.inspect}" unless data.bytesize == header.size

              entries[path] = { data: data, mode: mode }.freeze
            end
          end
          padding = bytes.byteslice(input.pos..)
          raise "tar contains data after its logical end" unless valid_tar_padding?(padding)

          entries.freeze
        end

        def validate_path!(path)
          components = path.split("/", -1)
          control_byte = path.each_byte.any? { |byte| byte < 0x20 || byte == 0x7f }
          invalid = path.empty? || path.start_with?("/") || path.include?("\\") ||
            components.any? { |part| part.empty? || part == "." || part == ".." } ||
            !path.ascii_only? || control_byte
          raise "traversing or non-canonical member #{path.inspect}" if invalid
        end

        def valid_tar_padding?(padding)
          return false unless padding
          return false if padding.bytesize < TAR_BLOCK_SIZE
          return false unless (padding.bytesize % TAR_BLOCK_SIZE).zero?

          padding.each_byte.all?(&:zero?)
        end

        def verify_spec(spec)
          raise "name #{spec.name.inspect}" unless spec.name == @name
          raise "version #{spec.version}" unless spec.version.to_s == @version
          raise "require_paths #{spec.require_paths.inspect}" unless spec.require_paths == [ "lib" ]
          raise "dependencies #{spec.dependencies.map(&:to_s).inspect}" unless spec.dependencies.empty?
          raise "extensions #{spec.extensions.inspect}" unless spec.extensions.empty?
          raise "executables #{spec.executables.inspect}" unless spec.executables.empty?

          return unless @name == "surfguard"

          raise "authors #{spec.authors.inspect}" unless spec.authors == [ "37signals" ]
          raise "summary #{spec.summary.inspect}" unless spec.summary == SUMMARY
          raise "description #{spec.description.inspect}" unless spec.description == DESCRIPTION
          raise "license #{spec.licenses.inspect}" unless spec.licenses == [ "MIT" ]
          raise "homepage #{spec.homepage.inspect}" unless spec.homepage == "https://github.com/basecamp/surfguard"
          raise "required Ruby #{spec.required_ruby_version}" unless spec.required_ruby_version.to_s == ">= 3.4.5"
          raise "platform #{spec.platform}" unless spec.platform == Gem::Platform::RUBY
          raise "certificate chain present" unless spec.cert_chain.empty?
          expected_metadata = {
            "bug_tracker_uri" => "https://github.com/basecamp/surfguard/issues",
            "changelog_uri" => "https://github.com/basecamp/surfguard/releases",
            "rubygems_mfa_required" => "true"
          }
          raise "metadata #{spec.metadata.inspect}" unless spec.metadata == expected_metadata
        end

        def verify_file_set(spec_files, archive_files)
          raise "spec.files #{spec_files.inspect}" unless spec_files == REQUIRED_FILES
          raise "archive files #{archive_files.inspect}" unless archive_files == REQUIRED_FILES
        end

        def compare_source(entries)
          entries.each do |path, entry|
            bytes, mode = source_entry(path)
            raise "#{path.inspect} bytes differ from source" unless entry.fetch(:data) == bytes
            raise "#{path.inspect} mode differs from source" unless entry.fetch(:mode) == mode
          end
        end

        def verify_source_commit!
          commit = @source_commit.to_s
          unless commit.match?(/\A(?:[0-9a-f]{40}|[0-9a-f]{64})\z/)
            raise "source identity is not a full commit object ID"
          end

          type, type_error, type_status = @capture.call("git", "cat-file", "-t", commit)
          unless type_status.success? && type.strip == "commit"
            detail = type_error.strip
            raise "source identity is not an immutable commit object#{detail.empty? ? nil : ": #{detail}"}"
          end
          canonical, resolve_error, resolve_status = @capture.call(
            "git", "rev-parse", "--verify", "#{commit}^{commit}"
          )
          unless resolve_status.success? && canonical.strip == commit
            detail = resolve_error.strip
            raise "source commit did not resolve canonically#{detail.empty? ? nil : ": #{detail}"}"
          end
        end

        def source_entry(path)
          return @source_reader.call(path) if @source_reader

          stdout, stderr, status = @capture.call("git", "show", "#{@source_commit}:#{path}")
          raise "git show failed for #{path.inspect}: #{stderr.strip.inspect}" unless status.success?
          tree, tree_error, tree_status = @capture.call("git", "ls-tree", @source_commit, "--", path)
          unless tree_status.success?
            raise "git ls-tree failed for #{path.inspect}: #{tree_error.strip.inspect}"
          end
          mode_text = tree.split.first
          raise "source member missing: #{path.inspect}" unless mode_text
          unless mode_text == "100644"
            raise "source member has abnormal git mode #{mode_text.inspect}: #{path.inspect}"
          end
          [ stdout.b, 0o644 ]
        end

        def verify_installed(gem_file)
          Dir.mktmpdir("#{@name}-verify") do |gem_home|
            env = CLEAN_ENV.merge("GEM_HOME" => gem_home, "GEM_PATH" => gem_home)
            raise "gem install failed" unless @runner.call(env, "gem", "install", "--local", "--no-document", gem_file)

            probe = <<~'RUBY'
              require "surfguard"
              abort "version mismatch" unless Surfguard::VERSION == ARGV.fetch(0)
              feature = $LOADED_FEATURES.find { |item| item.end_with?("/surfguard.rb") }
              abort "loaded feature missing" unless feature
              expected = File.realpath(ARGV.fetch(1))
              actual = File.realpath(feature)
              abort "loaded outside isolated GEM_HOME: #{actual}" unless actual.start_with?(expected + File::SEPARATOR)
            RUBY
            raise "require probe failed" unless @runner.call(env, "ruby", "-e", probe, @version, gem_home)

            # Development-only test tooling may come from the runner's gem
            # path. The isolated home stays first, and the probe above already
            # proved Surfguard itself loaded from that fresh install.
            suite_path = ([ gem_home ] + Gem.path).uniq.join(File::PATH_SEPARATOR)
            suite_env = env.merge("GEM_PATH" => suite_path, "SURFGUARD_INSTALLED_SUITE" => "1")
            suite = <<~'RUBY'
              root, version, gem_home, *expected = ARGV
              root = File.realpath(root)
              files = Dir[File.join(root, "test/surfguard*_test.rb")].sort
              relative = files.map { |file| file.delete_prefix(root + File::SEPARATOR) }
              abort "core test set mismatch" unless !expected.empty? && relative == expected.sort

              installed_root = File.realpath(File.join(gem_home, "gems", "surfguard-#{version}"))
              installed_lib = File.join(installed_root, "lib")
              $LOAD_PATH.unshift(installed_lib)
              require "surfguard"
              feature = $LOADED_FEATURES.find { |item| item.end_with?("/surfguard.rb") }
              abort "installed suite feature missing" unless feature
              expected_feature = File.realpath(File.join(installed_lib, "surfguard.rb"))
              abort "installed suite loaded wrong feature" unless File.realpath(feature) == expected_feature
              abort "installed suite version mismatch" unless Surfguard::VERSION == version

              files.each { |file| require file }
              abort "installed suite feature changed" unless File.realpath(feature) == expected_feature
              abort "installed suite version changed" unless Surfguard::VERSION == version
            RUBY
            arguments = [ @suite_root, @version, gem_home, *CORE_TEST_FILES ]
            raise "installed core suite failed" unless @runner.call(suite_env, "ruby", "-e", suite, *arguments)
          end
        end

        def check(description)
          @out.print "verify: #{description}... "
          result = yield
          @out.puts "ok"
          result
        rescue StandardError => error
          @out.puts "FAIL"
          raise Failure, "#{description}: #{error.message}"
        end
    end
  end
end
