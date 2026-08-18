# frozen_string_literal: true

# Confirm-job verification: bounded poll until the registry reports exactly
# our version with exactly our digest, then downloads the canonical bytes and
# verifies those too.
#   ruby script/release/registry_confirm.rb NAME VERSION SHA256 [DESTINATION [BUDGET_SECONDS]]
require_relative "registry"
Surfguard::Release::Registry.run_if_main(
  $PROGRAM_NAME, __FILE__, ARGV, runner: Surfguard::Release::Registry.method(:run_confirm)
)
