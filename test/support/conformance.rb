# frozen_string_literal: true

require "json"

# Loads the language-neutral classification corpus from conformance/*.json.
# Standard library only: the bare-Ruby CI matrix runs this without a bundle.
module Conformance
  ROOT = File.expand_path("../../conformance", __dir__)

  def self.cases(name)
    JSON.parse(File.read(File.join(ROOT, "#{name}.json"))).fetch("cases")
  end
end
