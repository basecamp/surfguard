# frozen_string_literal: true

require "open3"
require "fileutils"
require "rake/testtask"
require "tmpdir"

Rake::TestTask.new(:test) do |task|
  task.libs << "lib" << "test"
  task.test_files = FileList["test/**/*_test.rb"]
  task.warning = false
end

task default: :test

desc "Run RuboCop"
task :rubocop do
  sh "bundle", "exec", "rubocop"
end

VERSION_FILE = "lib/surfguard/version.rb"
LOCK_FILE = "Gemfile.lock"
SEMVER_PATTERN = /\A(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\z/
CANONICAL_PUSH_URL = "https://github.com/basecamp/surfguard"

def exact_semver?(version)
  SEMVER_PATTERN.match?(version)
end

def surfguard_version
  load File.expand_path(VERSION_FILE)
  Surfguard::VERSION
end

def git_capture(*args)
  stdout, stderr, status = Open3.capture3("git", *args)
  abort "git #{args.first} failed: #{stderr.strip}" unless status.success?
  stdout
end

def clean_tree?
  git_capture("status", "--porcelain").empty?
end

def canonical_push_url
  url = git_capture("remote", "get-url", "--push", "origin").strip
  fetch_url = git_capture("remote", "get-url", "origin").strip
  abort "tag: origin is not the canonical basecamp/surfguard push URL" unless url == CANONICAL_PUSH_URL
  abort "tag: origin fetch/push URLs differ; validate the canonical remote" unless url == fetch_url
  url.freeze
end

def clean_bundler_environment
  ENV.each_key.grep(/\ABUNDLE_/).to_h { |key| [ key, nil ] }.merge(
    "BUNDLE_IGNORE_CONFIG" => "1",
    "BUNDLER_VERSION" => nil,
    "RUBYOPT" => nil,
    "RUBYLIB" => nil,
    "RUBYGEMS_GEMDEPS" => nil
  )
end

desc "Rewrite version.rb to VERSION (exact semver, strictly greater) and refresh Gemfile.lock; commits nothing"
task :bump, [ :version ] do |_task, args|
  version = args[:version].to_s
  abort "bump: version must be exact semver X.Y.Z (got #{version.inspect})" unless exact_semver?(version)
  abort "bump: working tree must be clean" unless clean_tree?

  current = surfguard_version
  abort "bump: repository version is not exact semver" unless exact_semver?(current)
  abort "bump: #{version} must be strictly greater than the current #{current}" unless Gem::Version.new(version) > Gem::Version.new(current)

  originals = [ VERSION_FILE, LOCK_FILE ].to_h { |path| [ path, File.binread(path) ] }
  original_locked_versions = originals.fetch(LOCK_FILE).scan(/^    surfguard \(([^)]+)\)$/).flatten
  abort "bump: lockfile did not record exactly the current surfguard #{current}" unless original_locked_versions == [ current ]

  completed = false
  begin
    rewritten = originals.fetch(VERSION_FILE).sub(%(VERSION = "#{current}"), %(VERSION = "#{version}"))
    abort "bump: version declaration was not exact" if rewritten == originals.fetch(VERSION_FILE)

    staged_lock = nil
    Dir.mktmpdir("surfguard-bump") do |temporary|
      git_capture("ls-files", "-z").split("\0").each do |path|
        destination = File.join(temporary, path)
        FileUtils.mkdir_p(File.dirname(destination))
        FileUtils.copy_file(path, destination)
      end
      File.binwrite(File.join(temporary, VERSION_FILE), rewritten)
      Dir.chdir(temporary) do
        sh(clean_bundler_environment, "bundle", "install", "--quiet")
      end
      staged_lock = File.binread(File.join(temporary, LOCK_FILE))
    end
    locked_versions = staged_lock.scan(/^    surfguard \(([^)]+)\)$/).flatten
    abort "bump: lockfile did not record exactly surfguard #{version}" unless locked_versions == [ version ]

    File.binwrite(VERSION_FILE, rewritten)
    File.binwrite(LOCK_FILE, staged_lock)
    expected = [ VERSION_FILE, LOCK_FILE ].sort
    status = git_capture("status", "--porcelain=v1", "-z", "--untracked-files=all").split("\0").reject(&:empty?).sort
    expected_status = expected.map { |path| " M #{path}" }
    abort "bump: unexpected working tree state: #{status.inspect}" unless status == expected_status
    abort "bump: resulting version is invalid" unless surfguard_version == version
    completed = true
  ensure
    originals.each { |path, bytes| File.binwrite(path, bytes) } unless completed
  end

  puts "Bumped #{current} -> #{version}. Review and commit; rake tag after merge cuts the release."
end

desc "Tag and push v<current version> to trigger the release workflow"
task :tag do
  version = surfguard_version
  abort "tag: repository version is not exact semver" unless exact_semver?(version)
  tag = "v#{version}"
  expected_message = "surfguard #{tag}"

  abort "tag: working tree must be clean" unless clean_tree?
  branch = git_capture("rev-parse", "--abbrev-ref", "HEAD").strip
  abort "tag: must be on main (currently on #{branch})" unless branch == "main"

  push_url = canonical_push_url
  sh "git", "fetch", push_url, "main", "--quiet"
  head = git_capture("rev-parse", "HEAD").strip
  fetched_main = git_capture("rev-parse", "FETCH_HEAD").strip
  abort "tag: HEAD (#{head[0, 12]}) != fetched main (#{fetched_main[0, 12]}); reconcile first" unless head == fetched_main

  remote_tag = git_capture("ls-remote", "--tags", push_url, "refs/tags/#{tag}").strip
  abort "tag: #{tag} already exists on origin" unless remote_tag.empty?

  local_tag = git_capture("tag", "--list", tag).strip
  if local_tag.empty?
    sh "git", "tag", "--annotate", "--no-sign", tag, "--message", expected_message
  end

  type = git_capture("cat-file", "-t", tag).strip
  message = if type == "tag"
    git_capture("cat-file", "tag", tag).split("\n\n", 2)[1]
  end
  peeled = git_capture("rev-parse", "#{tag}^{commit}").strip
  unless type == "tag" && message == "#{expected_message}\n" && peeled == head
    abort "tag: existing local #{tag} is not the exact retryable annotated tag"
  end

  sh "git", "push", push_url, "HEAD:refs/heads/main"
  sh "git", "push", push_url, "refs/tags/#{tag}:refs/tags/#{tag}"
  puts "Pushed #{tag}. The release workflow takes it from here; approve the release environment when prompted."
end
