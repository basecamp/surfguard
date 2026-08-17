# frozen_string_literal: true

# Publish-job reconciliation: prints "push" or "skip", or fails closed.
#   ruby script/release/registry_check.rb NAME VERSION SHA256
require_relative "registry"
Surfguard::Release::Registry.run_if_main(
  $PROGRAM_NAME, __FILE__, ARGV, runner: Surfguard::Release::Registry.method(:run_check)
)
