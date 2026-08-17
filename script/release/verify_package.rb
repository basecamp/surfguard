# frozen_string_literal: true

# Fresh-runner package verification, run on every CI and release candidate.
#   ruby script/release/verify_package.rb GEM_FILE NAME VERSION IMMUTABLE_COMMIT_SHA
require_relative "package_verification"
Surfguard::Release::PackageVerification.run_if_main($PROGRAM_NAME, __FILE__, ARGV)
