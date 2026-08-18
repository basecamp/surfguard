# frozen_string_literal: true

require_relative "lib/surfguard/version"

Gem::Specification.new do |spec|
  spec.name        = "surfguard"
  spec.version     = Surfguard::VERSION
  spec.authors     = [ "37signals" ]
  spec.summary     = "One SSRF address policy: resolve a host and classify special-use IPv4/IPv6 ranges"
  spec.description = "Surfguard resolves a hostname to the public IP addresses it " \
                     "points at and refuses anything that would reach an internal " \
                     "network: private, loopback, link-local and carrier-grade NAT " \
                     "space, plus the IPv6 transition ranges a naive guard misses " \
                     "(IPv4-mapped, SIIT, NAT64, 6to4, Teredo). It resolves and " \
                     "classifies only; the caller owns the fetch and pins the " \
                     "connection to a returned address so DNS rebinding cannot swap " \
                     "in a blocked one. Standard library only, no runtime dependencies."
  spec.homepage    = "https://github.com/basecamp/surfguard"
  spec.license     = "MIT"
  spec.required_ruby_version = ">= 3.4.5"

  # homepage already points at the repo, so a source_code_uri/homepage_uri that
  # repeats it only earns a "same uri for multiple keys" warning. The issue
  # tracker is the one distinct link worth adding.
  spec.metadata = {
    "bug_tracker_uri"       => "#{spec.homepage}/issues",
    "changelog_uri"         => "#{spec.homepage}/releases",
    "rubygems_mfa_required" => "true"
  }

  spec.files = %w[lib/surfguard.rb lib/surfguard/version.rb README.md LICENSE SECURITY.md]
  spec.require_paths = [ "lib" ]

  # Standard library only: ipaddr, resolv, socket, uri. No runtime dependencies on
  # purpose — this must drop into apps on wildly different gem sets.
end
