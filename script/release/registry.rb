# frozen_string_literal: true

require "digest"
require "json"
require "net/http"
require "openssl"
require "pathname"
require "resolv"
require "securerandom"
require "tmpdir"
require "uri"

require_relative "../../lib/surfguard"

module Surfguard
  module Release
    class Registry
      class Error < StandardError; end
      class RetryableFault < StandardError; end

      HOST = "https://rubygems.org"
      ORIGIN_HOST = "rubygems.org"
      MAX_ATTEMPTS = 5
      MALFORMED_LIMIT = 3
      BACKOFF_BASE = 2
      POLL_INTERVAL = 5
      DEFAULT_BUDGET = 300
      MIN_BUDGET = 1
      MAX_BUDGET = 600
      MAX_REDIRECTS = 3
      METADATA_LIMIT = 1 << 20
      GEM_LIMIT = 16 << 20

      Response = Struct.new(:status, :body, :location, :declared_length, :actual_length)

      module BodyLength
        module_function

        def parse(value, limit)
          return nil if value.nil?

          text = value.to_s
          raise Error, "invalid declared response length" unless text.match?(/\A\d+\z/)

          length = Integer(text, 10)
          raise Error, "declared response length exceeds #{limit} bytes" if length > limit

          length
        end
      end

      class Deadline
        def initialize(clock, seconds)
          @clock = clock
          @expires_at = @clock.call + seconds
        end

        def remaining
          seconds = @expires_at - @clock.call
          raise Error, "registry operation exceeded its monotonic budget" unless seconds.positive?

          seconds
        end

        def check!
          remaining
          true
        end

        # A watchdog bounds operations such as DNS and a TLS read even if the
        # underlying library's timeout is inactivity-based rather than absolute.
        def run
          wait = remaining
          worker = Thread.new { yield }
          worker.report_on_exception = false
          begin
            unless worker.join([ wait, remaining ].min)
              worker.kill
              worker.join(0.1)
              raise Error, "registry operation exceeded its monotonic budget"
            end
            check!
            worker.value
          ensure
            if worker.alive?
              worker.kill
              worker.join(0.1)
            end
          end
        end
      end

      class DigestingSink
        attr_reader :bytesize

        def initialize(file, limit, deadline: nil)
          @file = file
          @limit = limit
          @deadline = deadline
          @digest = Digest::SHA256.new
          @bytesize = 0
        end

        def write(chunk)
          raise Error, "response body is not a byte string" unless chunk.is_a?(String)
          raise Error, "response exceeds #{@limit} bytes" if @bytesize + chunk.bytesize > @limit

          offset = 0
          while offset < chunk.bytesize
            written = checked_io { @file.write(chunk.byteslice(offset..)) }
            raise Error, "temporary download write made no progress" unless written.positive?

            offset += written
          end
          @digest.update(chunk)
          @bytesize += chunk.bytesize
        end

        def reset!
          checked_io { @file.flush }
          checked_io { @file.rewind }
          checked_io { @file.truncate(0) }
          @digest = Digest::SHA256.new
          @bytesize = 0
        end

        def hexdigest
          @digest.hexdigest
        end

        def finish!
          checked_io { @file.chmod(0o600) }
          checked_io { @file.flush }
          checked_io { @file.fsync }
        end

        private
          def checked_io
            @deadline&.check!
            result = yield
            @deadline&.check!
            result
          end
      end

      class LiveHTTP
        NETWORK_ERRORS = [ Timeout::Error, OpenSSL::SSL::SSLError, SocketError,
          SystemCallError, EOFError, IOError ].freeze
        TRUSTED_INSTANCE_OF = Object.instance_method(:instance_of?)
        TRUSTED_ARRAY_EACH = Array.instance_method(:each)
        TRUSTED_ARRAY_LENGTH = Array.instance_method(:length)
        TRUSTED_ARRAY_SLICE = Array.instance_method(:[])

        def initialize(resolver: ->(host) { Resolv.getaddresses(host) }, http_class: Net::HTTP)
          @resolver = resolver
          @http_class = http_class
          @address_cache = {}
        end

        def call(uri, deadline, limit, sink)
          deadline.check!
          addresses = addresses_for(uri.host, deadline)
          last_error = nil
          addresses.each do |address|
            deadline.check!
            begin
              response = deadline.run { request(uri, address, deadline, limit, sink) }
              deadline.check!
              return response
            rescue *NETWORK_ERRORS => error
              last_error = error
              sink&.reset!
              deadline.check!
            end
          end
          raise last_error
        end

        private
          def addresses_for(host, deadline)
            cached = @address_cache[host]
            return cached.tap { deadline.check! } if cached

            answers = deadline.run do
              raw = @resolver.call(host)
              unless trusted_instance_of?(raw, Array)
                raise Error, "registry host returned an invalid answer collection"
              end

              raw_length = TRUSTED_ARRAY_LENGTH.bind_call(raw)
              raise Error, "registry host returned too many addresses" if raw_length > Surfguard::MAX_ADDRESSES

              owned_raw = TRUSTED_ARRAY_SLICE.bind_call(raw, 0, Surfguard::MAX_ADDRESSES + 1)
              normalized = []
              TRUSTED_ARRAY_EACH.bind_call(owned_raw) do |answer|
                deadline.check!
                unless trusted_instance_of?(answer, String)
                  raise Error, "registry host returned a malformed address"
                end

                owned = String.new(answer)
                unless owned.valid_encoding? && owned.ascii_only? &&
                    !owned.include?("\0") && !owned.include?("/") && !owned.include?("%")
                  raise Error, "registry host returned a malformed address"
                end

                owned.freeze
                address = IPAddr.new(owned)
                if Surfguard.blocked_address?(address, policy: :iana_special_use)
                  raise Error, "registry host resolved to a blocked address"
                end
                normalized << address.to_s.dup.freeze
                deadline.check!
              rescue IPAddr::InvalidAddressError, ArgumentError, TypeError
                raise Error, "registry host returned a malformed address"
              end
              normalized.uniq!
              raise Error, "registry host resolved to no addresses" if normalized.empty?

              deadline.check!
              normalized.freeze
            end

            deadline.check!
            @address_cache[host] = answers
          rescue Resolv::ResolvError, Timeout::Error, SocketError, SystemCallError, EOFError, IOError
            raise SocketError, "registry host resolution failed"
          end

          def trusted_instance_of?(value, klass)
            TRUSTED_INSTANCE_OF.bind_call(value, klass)
          end

          def request(uri, address, deadline, limit, sink)
            client = @http_class.new(uri.host, uri.port, nil)
            client.use_ssl = true
            client.verify_mode = OpenSSL::SSL::VERIFY_PEER
            client.verify_hostname = true if client.respond_to?(:verify_hostname=)
            client.ipaddr = address
            client.open_timeout = [ deadline.remaining, 10 ].min
            client.read_timeout = [ deadline.remaining, 30 ].min
            request = Net::HTTP::Get.new(uri.request_uri)
            request["Host"] = uri.host
            request["Accept-Encoding"] = "identity"
            result = nil

            deadline.check!
            client.start do |connection|
              deadline.check!
              connection.request(request) do |response|
                deadline.check!
                encoding = response["content-encoding"]
                if encoding && !encoding.casecmp?("identity")
                  raise Error, "refusing encoded registry response"
                end
                declared = BodyLength.parse(response["content-length"], limit)
                if declared && response["transfer-encoding"]
                  raise Error, "response has both Content-Length and Transfer-Encoding"
                end

                actual = 0
                body = +""
                target = response.code.to_i == 200 ? sink : nil
                response.read_body do |chunk|
                  deadline.check!
                  actual += chunk.bytesize
                  raise Error, "response exceeds #{limit} bytes" if actual > limit

                  target ? target.write(chunk) : body << chunk
                  client.read_timeout = [ deadline.remaining, 30 ].min
                  deadline.check!
                end
                deadline.check!
                if declared && declared != actual
                  raise Error, "declared response length does not match received bytes"
                end
                result = Response.new(response.code.to_i, target ? nil : body,
                  response["location"], declared, actual)
              end
              deadline.check!
            end
            deadline.check!
            result
          end
      end

      def self.live(name)
        clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        adapter = LiveHTTP.new
        new(name, http: adapter.method(:call), sleeper: ->(seconds) { Kernel.sleep(seconds) }, clock: clock)
      end

      def self.run_if_main(program_name, file_name, argv, runner:)
        return unless program_name == file_name

        exit runner.call(argv)
      end

      def self.run_check(argv, out: $stdout, err: $stderr, registry_for: method(:live))
        name, version, sha256, budget = argv
        valid = (argv.size == 3) || (argv.size == 4 && String === budget && budget.match?(/\A\d+\z/))
        return usage(err, "registry_check.rb NAME VERSION SHA256 [BUDGET_SECONDS]") unless valid

        out.puts registry_for.call(name).check(version, sha256, budget: budget || DEFAULT_BUDGET)
        0
      rescue Error => error
        err.puts "registry check failed: #{error.message}"
        1
      end

      def self.run_confirm(argv, out: $stdout, err: $stderr, registry_for: method(:live))
        name, version, sha256, destination, budget = argv
        if argv.size == 4 && String === destination && destination.match?(/\A\d+\z/)
          budget = destination
          destination = nil
        end
        valid_destination = destination.nil? || (String === destination && destination.end_with?(".gem"))
        valid_budget = budget.nil? || (String === budget && budget.match?(/\A\d+\z/))
        valid = (3..5).cover?(argv.size) && valid_destination && valid_budget
        return usage(err, "registry_confirm.rb NAME VERSION SHA256 [DESTINATION [BUDGET_SECONDS]]") unless valid

        registry = registry_for.call(name)
        if destination
          registry.confirm_to(version, sha256, destination, budget: budget || DEFAULT_BUDGET)
        else
          registry.confirm(version, sha256, budget: budget || DEFAULT_BUDGET)
        end
        out.puts "confirmed: #{name} #{version} is live with sha256 #{sha256.downcase}"
        0
      rescue Error => error
        err.puts "registry confirmation failed: #{error.message}"
        1
      end

      def self.run_download(argv, out: $stdout, err: $stderr, registry_for: method(:live))
        name, version, destination, budget = argv
        valid = (argv.size == 3) || (argv.size == 4 && String === budget && budget.match?(/\A\d+\z/))
        return usage(err, "registry_download.rb NAME VERSION DESTINATION [BUDGET_SECONDS]") unless valid

        digest = registry_for.call(name).verified_download_to(version, destination, budget: budget || DEFAULT_BUDGET)
        out.puts digest
        0
      rescue Error => error
        err.puts "registry download failed: #{error.message}"
        1
      end

      def self.usage(err, message)
        err.puts "usage: #{message}"
        2
      end
      private_class_method :usage

      def self.atomic_publish(destination, bytes)
        with_atomic_target(destination) { |sink| sink.write(bytes) }
      end

      def self.with_atomic_target(destination, deadline: nil)
        raise Error, "destination is empty" if destination.nil? || destination.empty?

        target = File.expand_path(destination)
        parent = File.dirname(target)
        validate_parent_chain!(parent, deadline: deadline)
        parent_stat = deadline_operation(deadline) { File.lstat(parent) }
        begin
          deadline_operation(deadline) { File.lstat(target) }
          raise Error, "destination already exists"
        rescue Errno::ENOENT
          nil
        end

        temporary = File.join(parent, ".#{File.basename(target)}.#{SecureRandom.hex(12)}.tmp")
        temporary_identity = nil
        publication_may_exist = false
        committed = false
        begin
          yielded, expected_digest, expected_size = deadline_operation(deadline) do
            File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
              file.binmode
              temporary_identity = file.stat
              sink = DigestingSink.new(file, GEM_LIMIT, deadline: deadline)
              result = yield sink
              sink.finish!
              [ result, sink.hexdigest, sink.bytesize ]
            end
          end
          verify_parent_identity!(parent, parent_stat, deadline)
          verify_regular_identity!(temporary, temporary_identity, deadline,
            message: "temporary download is not the expected mode-0600 regular file")

          publication_may_exist = true
          deadline_operation(deadline) { File.link(temporary, target) }
          verify_parent_identity!(parent, parent_stat, deadline)
          verify_linked_target!(target, temporary_identity, expected_size, expected_digest, deadline)
          fsync_directory!(parent, deadline)
          deadline_operation(deadline) { File.unlink(temporary) }
          fsync_directory!(parent, deadline)
          verify_parent_identity!(parent, parent_stat, deadline)
          verify_linked_target!(target, temporary_identity, expected_size, expected_digest, deadline)
          committed = true
          [ yielded, expected_digest ]
        rescue Errno::EEXIST
          message = publication_may_exist ? "destination already exists" : "temporary path collision"
          raise Error, message
        ensure
          if publication_may_exist && !committed && safe_unlink_expected(target, temporary_identity)
            fsync_directory!(parent, nil)
          end
          safe_unlink_expected(temporary, temporary_identity)
        end
      rescue SystemCallError => error
        raise Error, "atomic publication failed: #{error.message}"
      end

      def self.validate_parent_chain!(parent, deadline: nil)
        Pathname.new(File.expand_path(parent)).ascend.to_a.reverse_each do |component|
          stat = deadline_operation(deadline) { File.lstat(component.to_s) }
          raise Error, "symlink parent is forbidden" if stat.symlink?
          raise Error, "download parent is not a directory" unless stat.directory?
        end
      end
      private_class_method :validate_parent_chain!

      def self.verify_parent_identity!(parent, expected, deadline)
        validate_parent_chain!(parent, deadline: deadline)
        current = deadline_operation(deadline) { File.lstat(parent) }
        unless [ current.dev, current.ino ] == [ expected.dev, expected.ino ]
          raise Error, "download parent changed during publication"
        end
      end
      private_class_method :verify_parent_identity!

      def self.verify_regular_identity!(path, expected, deadline, message:)
        stat = deadline_operation(deadline) { File.lstat(path) }
        unless stat.file? && !stat.symlink? && [ stat.dev, stat.ino ] == [ expected.dev, expected.ino ] &&
            (stat.mode & 0o777) == 0o600
          raise Error, message
        end
        stat
      end
      private_class_method :verify_regular_identity!

      def self.verify_linked_target!(path, identity, expected_size, expected_digest, deadline)
        message = "published download is not the verified mode-0600 regular file"
        stat = verify_regular_identity!(path, identity, deadline, message: message)
        raise Error, "published download size changed" unless stat.size == expected_size

        digest = digest_regular_file(path, identity, deadline)
        raise Error, "published download digest changed" unless digest == expected_digest

        verify_regular_identity!(path, identity, deadline, message: message)
      end
      private_class_method :verify_linked_target!

      def self.digest_regular_file(path, identity, deadline)
        deadline_operation(deadline) do
          File.open(path, File::RDONLY) do |file|
            stat = file.stat
            unless stat.file? && [ stat.dev, stat.ino ] == [ identity.dev, identity.ino ]
              raise Error, "published download changed while opening"
            end

            digest = Digest::SHA256.new
            bytes = 0
            loop do
              chunk = deadline_operation(deadline) { file.read(16_384) }
              break unless chunk

              bytes += chunk.bytesize
              raise Error, "published download exceeds #{GEM_LIMIT} bytes" if bytes > GEM_LIMIT
              digest.update(chunk)
            end
            digest.hexdigest
          end
        end
      end
      private_class_method :digest_regular_file

      def self.fsync_directory!(parent, deadline)
        deadline_operation(deadline) { File.open(parent, File::RDONLY, &:fsync) }
      end
      private_class_method :fsync_directory!

      def self.deadline_operation(deadline)
        deadline&.check!
        result = yield
        deadline&.check!
        result
      end
      private_class_method :deadline_operation

      def self.safe_unlink_expected(path, identity)
        return unless identity

        stat = File.lstat(path)
        return unless stat.file? && !stat.symlink? && [ stat.dev, stat.ino ] == [ identity.dev, identity.ino ]

        File.unlink(path)
        true
      rescue Errno::ENOENT
        false
      end
      private_class_method :safe_unlink_expected

      def initialize(name, http:, sleeper:, clock:)
        raise Error, "invalid gem name" unless name.to_s.match?(/\A[a-z0-9_-]+\z/)

        @name = name.to_s.dup.freeze
        @http = http
        @sleeper = sleeper
        @clock = clock
        @deadline = nil
      end

      def check(version, sha256, budget: DEFAULT_BUDGET)
        within_budget(budget) do
          sha256 = normalize_sha(sha256)
          response = get_with_retries(version_uri(version), limit: METADATA_LIMIT)
          case response.status
          when 404 then :push
          when 200
            published = published_sha(response.body, version)
            return :skip if published == sha256

            raise Error, "#{@name} #{version} is already published with sha256 #{published}; our artifact is #{sha256}"
          else
            raise Error, "unexpected HTTP #{response.status} from registry metadata"
          end
        end
      end

      def confirm(version, sha256, budget: DEFAULT_BUDGET, deadline: nil)
        budget = deadline if deadline
        within_budget(budget) do
          sha256 = normalize_sha(sha256)
          poll(version, sha256)
          bytes, = verified_download_in_memory(version, required_sha: sha256)
          bytes
        end
      end

      def confirm_to(version, sha256, destination, budget: DEFAULT_BUDGET)
        within_budget(budget) do
          sha256 = normalize_sha(sha256)
          poll(version, sha256)
          stream_verified_download(version, destination, required_sha: sha256)
        end
      end

      def verified_download(version, budget: DEFAULT_BUDGET)
        within_budget(budget) { verified_download_in_memory(version) }
      end

      def verified_download_to(version, destination, budget: DEFAULT_BUDGET)
        within_budget(budget) { stream_verified_download(version, destination) }
      end

      private
        def within_budget(value)
          return yield if @deadline

          text = value.to_s
          raise Error, "budget must be 1..600 seconds" unless text.match?(/\A\d+\z/)

          budget = Integer(text, 10)
          raise Error, "budget must be 1..600 seconds" unless (MIN_BUDGET..MAX_BUDGET).cover?(budget)

          @deadline = Deadline.new(@clock, budget)
          yield
        ensure
          @deadline = nil if defined?(budget) && budget
        end

        def remaining
          @deadline.remaining
        end

        def sleep_bounded(seconds)
          raise Error, "registry operation exceeded its monotonic budget" if seconds >= remaining

          @sleeper.call(seconds)
          @deadline.check!
        end

        def version_uri(version)
          # Exact semver plus optional RubyGems prerelease segments (0.2.0.rc1),
          # the version domain the release workflows accept. Alphanumeric
          # dot-separated segments only, so interpolation stays URI/path-safe.
          raise Error, "invalid gem version" \
            unless version.to_s.match?(/\A(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}(?:\.[A-Za-z0-9]+)*\z/)

          URI("#{HOST}/api/v2/rubygems/#{@name}/versions/#{version}.json")
        end

        def normalize_sha(value)
          sha = value.to_s.downcase
          raise Error, "not a sha256 hex digest" unless sha.match?(/\A\h{64}\z/)

          sha
        end

        def published_sha(body, version)
          data = JSON.parse(body)
          raise Error, "unexpected response shape" unless data.is_a?(Hash)
          raise Error, "response is for a different version" unless data["number"] == version
          sha = data["sha"]
          raise Error, "response has no usable sha256" unless sha.is_a?(String) && sha.match?(/\A\h{64}\z/)

          sha.downcase
        rescue JSON::ParserError
          raise Error, "malformed JSON from registry"
        end

        def get_once(uri, limit:, sink: nil)
          validate_uri!(uri)
          @deadline.check!
          sink_before = sink&.bytesize
          response = case @http.arity
          when 1 then @http.call(uri)
          when 2 then @http.call(uri, remaining)
          else @http.call(uri, @deadline, limit, sink)
          end
          @deadline.check!
          raise Error, "invalid registry response" unless response.respond_to?(:status) && response.respond_to?(:body)

          status = Integer(response.status)
          declared = BodyLength.parse(response.declared_length, limit)
          body = response.body
          raise Error, "response body is not a byte string" unless body.nil? || body.is_a?(String)

          sink.write(body) if sink && status == 200 && body
          observed = if sink && status == 200
            sink.bytesize - sink_before
          else
            body.to_s.bytesize
          end
          actual = response.actual_length ? Integer(response.actual_length) : observed
          if response.actual_length && actual != observed
            raise Error, "reported actual response length does not match received bytes"
          end
          raise Error, "response exceeds #{limit} bytes" if actual > limit
          if declared && declared != actual
            raise Error, "declared response length does not match received bytes"
          end

          Response.new(status, body, response.location, declared, actual)
        rescue Timeout::Error, Net::OpenTimeout, Net::ReadTimeout, OpenSSL::SSL::SSLError,
               SocketError, SystemCallError, EOFError, IOError => error
          raise RetryableFault, error.class.to_s
        rescue ArgumentError, TypeError
          raise Error, "invalid registry response length or status"
        end

        def get_with_retries(uri, limit:, sink: nil)
          attempts = 0
          begin
            attempts += 1
            response = get_once(uri, limit: limit, sink: sink)
            raise RetryableFault, "HTTP #{response.status}" if retryable_status?(response.status)
            response
          rescue RetryableFault => error
            raise Error, "registry unavailable after #{attempts} attempts (#{error.message})" if attempts >= MAX_ATTEMPTS
            sink&.reset!
            @deadline.check!
            sleep_bounded(BACKOFF_BASE * attempts)
            retry
          end
        end

        def retryable_status?(status)
          status == 429 || (500..599).cover?(status)
        end

        def poll(version, sha256)
          faults = 0
          malformed = 0
          loop do
            @deadline.check!
            begin
              response = get_once(version_uri(version), limit: METADATA_LIMIT)
            rescue RetryableFault
              malformed = 0
              faults += 1
              sleep_bounded(BACKOFF_BASE * faults)
              next
            end
            case response.status
            when 200
              begin
                published = published_sha(response.body, version)
              rescue Error
                malformed += 1
                raise if malformed >= MALFORMED_LIMIT
                sleep_bounded(POLL_INTERVAL)
                next
              end
              return if published == sha256
              raise Error, "registry reports a different digest; stopping for a human"
            when 404
              malformed = 0
              sleep_bounded(POLL_INTERVAL)
            when 429, 500..599
              malformed = 0
              faults += 1
              sleep_bounded(BACKOFF_BASE * faults)
            else
              raise Error, "unexpected HTTP #{response.status} from registry metadata"
            end
          end
        end

        def download(version, sink:)
          uri = URI("#{HOST}/gems/#{@name}-#{version}.gem")
          redirects = 0
          loop do
            response = get_with_retries(uri, limit: GEM_LIMIT, sink: sink)
            case response.status
            when 200 then return
            when 301, 302, 303, 307, 308
              redirects += 1
              raise Error, "too many redirects downloading gem" if redirects > MAX_REDIRECTS
              raise Error, "redirect without a Location header" if response.location.nil? || response.location.empty?
              begin
                target = URI.join(uri.to_s, response.location)
              rescue URI::Error
                raise Error, "unusable redirect location"
              end
              validate_uri!(target)
              uri = target
            else
              raise Error, "unexpected HTTP #{response.status} downloading gem"
            end
          end
        end

        def stream_verified_download(version, destination, required_sha: nil)
          response = get_with_retries(version_uri(version), limit: METADATA_LIMIT)
          unless response.status == 200
            raise Error, "expected #{@name} #{version} to be published; got HTTP #{response.status}"
          end
          published = published_sha(response.body, version)

          result, = self.class.with_atomic_target(destination, deadline: @deadline) do |sink|
            download(version, sink: sink)
            digest = sink.hexdigest
            unless digest == published
              raise Error, "downloaded .gem digest #{digest} does not match registry-reported sha256 #{published}"
            end
            if required_sha && digest != required_sha
              raise Error, "canonical .gem digest #{digest} does not match our artifact digest #{required_sha}"
            end
            digest
          end
          result
        end

        def verified_download_in_memory(version, required_sha: nil)
          Dir.mktmpdir("surfguard-registry") do |directory|
            destination = File.join(directory, "#{@name}-#{version}.gem")
            digest = stream_verified_download(version, destination, required_sha: required_sha)
            bytes = @deadline.run { File.binread(destination, GEM_LIMIT + 1) }
            raise Error, "downloaded gem exceeds #{GEM_LIMIT} bytes" if bytes.bytesize > GEM_LIMIT
            raise Error, "downloaded gem changed after verification" unless Digest::SHA256.hexdigest(bytes) == digest

            [ bytes, digest ]
          end
        end

        def validate_uri!(uri)
          valid = uri.is_a?(URI::HTTPS) && uri.host == ORIGIN_HOST && uri.port == 443 &&
            uri.userinfo.nil? && uri.fragment.nil?
          raise Error, "refusing registry URL outside exact https://rubygems.org:443 origin" unless valid
        end
    end
  end
end
