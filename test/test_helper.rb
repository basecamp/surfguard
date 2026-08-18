# frozen_string_literal: true

# Coverage is opt-in so the bare-Ruby CI matrix (no bundle, no gems beyond the
# standard library) can run this suite untouched: without COVERAGE set, this
# file requires nothing but minitest.
if ENV["COVERAGE"]
  require "simplecov"

  SimpleCov.start do
    # Every owned runtime and release-critical Ruby implementation is included,
    # including CLI entry points and live adapters. A new uncovered path must be
    # tested or redesigned; it cannot disappear behind aggregate or per-file slack.
    coverage(:line) do
      minimum 100
      minimum_per_file 100
    end
    coverage(:branch) do
      minimum 100
      minimum_per_file 100
    end
    # The default hidden-file filter would silently discard the owned
    # Dependabot validator under `.github/scripts`. The explicit allowlist
    # below is the complete coverage universe, so default skips add no safety
    # and can only hide a newly tracked path.
    no_default_skips
    # `cover` is SimpleCov's non-deprecated track-files API: unloaded matching
    # files remain in the report at zero rather than silently disappearing.
    cover "lib/**/*.rb", "script/**/*.rb", ".github/scripts/**/*.rb", "Rakefile", "*.gemspec"
  end
end

require "minitest/autorun"
