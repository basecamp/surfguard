# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# Development-only. The gem itself is standard library only — CI proves that
# by running the test suite on bare Ruby with no bundle at all.
group :development do
  gem "minitest"
  gem "rake"
  gem "rubocop-37signals", require: false
  gem "simplecov", require: false
end
