# frozen_string_literal: true

# Coverage is opt-in so the bare-Ruby CI matrix (no bundle, no gems beyond the
# standard library) can run this suite untouched: without COVERAGE set, this
# file requires nothing but minitest.
if ENV["COVERAGE"]
  require "simplecov"

  SimpleCov.start do
    enable_coverage :branch
    add_filter "/test/"

    # Measured actuals are 100/100 (66/66 lines, 24/24 branches), so the
    # thresholds pin them there: any change that leaves a line or branch
    # untested fails loudly.
    minimum_coverage line: 100, branch: 100
  end
end

require "minitest/autorun"
