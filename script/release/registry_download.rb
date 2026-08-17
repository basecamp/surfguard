# frozen_string_literal: true

# Recovery-path download: fetches the canonical .gem bytes for a published
# version, verifies them against the digest the registry itself reports,
# writes them to DESTINATION, and prints the digest.
#   ruby script/release/registry_download.rb NAME VERSION DESTINATION [BUDGET_SECONDS]
require_relative "registry"
Surfguard::Release::Registry.run_if_main(
  $PROGRAM_NAME, __FILE__, ARGV, runner: Surfguard::Release::Registry.method(:run_download)
)
