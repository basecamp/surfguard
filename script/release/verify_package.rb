# frozen_string_literal: true

# Build-job package verification, run on every build — rehearsals included:
# archive integrity, spec identity, exact contents, zero runtime dependencies,
# and a real install + require into an isolated GEM_HOME.
#   ruby script/release/verify_package.rb GEM_FILE NAME VERSION
require "rubygems/package"
require "tmpdir"

REQUIRED_FILES = %w[ lib/surfguard.rb lib/surfguard/version.rb README.md LICENSE SECURITY.md ].freeze
ALLOWED_PATTERNS = [ %r{\Alib/.+\.rb\z}, /\AREADME\.md\z/, /\ALICENSE\z/, /\ASECURITY\.md\z/ ].freeze

# Keep child processes honest: no bundler or ruby options leaking in from CI.
CLEAN_ENV = { "RUBYOPT" => nil, "BUNDLE_GEMFILE" => nil, "BUNDLE_PATH" => nil }.freeze

def check(description)
  print "verify: #{description}... "
  result = yield
  puts "ok"
  result
rescue StandardError => e
  puts "FAIL"
  abort "verify_package: #{description}: #{e.message}"
end

gem_file, expected_name, expected_version = ARGV
abort "usage: verify_package.rb GEM_FILE NAME VERSION" unless ARGV.size == 3
abort "no such file: #{gem_file}" unless File.file?(gem_file)

package = check("archive integrity (Gem::Package#verify)") do
  Gem::Package.new(gem_file).tap(&:verify)
end

spec = package.spec

check("spec name is #{expected_name}") do
  raise "got #{spec.name.inspect}" unless spec.name == expected_name
end

check("spec version is #{expected_version}") do
  raise "got #{spec.version}" unless spec.version.to_s == expected_version
end

check("zero runtime dependencies") do
  deps = spec.runtime_dependencies
  raise "got: #{deps.map(&:name).sort.join(", ")}" unless deps.empty?
end

contents = package.contents
puts "verify: archive contents:"
contents.sort.each { |path| puts "  #{path}" }

check("required files all present") do
  missing = REQUIRED_FILES - contents
  raise "missing: #{missing.join(", ")}" unless missing.empty?
end

check("no unexpected files") do
  unexpected = contents.reject { |path| ALLOWED_PATTERNS.any? { |pattern| pattern.match?(path) } }
  raise "unexpected: #{unexpected.sort.join(", ")}" unless unexpected.empty?
end

check("installs and requires cleanly in an isolated GEM_HOME") do
  Dir.mktmpdir("#{expected_name}-verify") do |gem_home|
    env = CLEAN_ENV.merge("GEM_HOME" => gem_home, "GEM_PATH" => gem_home)

    unless system(env, "gem", "install", "--local", "--no-document", gem_file)
      raise "gem install failed"
    end

    probe = %(require "surfguard"; abort "version mismatch: \#{Surfguard::VERSION}" unless Surfguard::VERSION == ARGV[0])
    unless system(env, "ruby", "-e", probe, expected_version)
      raise "require probe failed"
    end
  end
end

puts "verify: #{File.basename(gem_file)} passed all checks"
