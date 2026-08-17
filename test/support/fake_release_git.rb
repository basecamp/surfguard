#!/usr/bin/env ruby
# frozen_string_literal: true

real_git = ENV.fetch("SURFGUARD_REAL_GIT")
origin = ENV.fetch("SURFGUARD_TEST_ORIGIN")
canonical = "https://github.com/basecamp/surfguard"

if ARGV == %w[remote get-url --push origin] && !ENV["SURFGUARD_EXPOSE_REMOTE"]
  puts canonical
  exit 0
end

if ARGV == %w[remote get-url origin] && !ENV["SURFGUARD_EXPOSE_REMOTE"]
  puts(ENV["SURFGUARD_MISMATCH_REMOTE"] ? "https://github.com/basecamp/not-surfguard" : canonical)
  exit 0
end

if ARGV.first(2) == %w[status --porcelain] && ENV["SURFGUARD_FAIL_GIT_STATUS"]
  warn "simulated git status failure"
  exit 1
end

if ARGV.include?("--porcelain=v1") && ENV["SURFGUARD_INJECT_UNTRACKED_ON_STATUS"]
  File.binwrite("unexpected-untracked", "injected during final validation")
end

mapped = ARGV.map { |argument| argument == canonical ? origin : argument }
exec real_git, *mapped
