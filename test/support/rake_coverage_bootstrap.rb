# frozen_string_literal: true

if ENV["SURFGUARD_COVERAGE_ROOT"]
  require "simplecov"

  SimpleCov.root ENV.fetch("SURFGUARD_COVERAGE_ROOT")
  SimpleCov.command_name "rake-task-#{Process.pid}"
  SimpleCov.start do
    # Subprocesses only persist their resultset fragments. The parent test
    # process is the sole report writer, avoiding concurrent report clobbering.
    formatter false
    enable_coverage :branch
    no_default_skips
    cover "Rakefile"
  end
end
