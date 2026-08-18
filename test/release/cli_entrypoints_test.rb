# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../script/release/verify_package"

class CliEntrypointsTest < Minitest::Test
  def test_package_entrypoint_guard_propagates_the_selected_runner_status
    runner = ->(argv) { argv.empty? ? 6 : 8 }

    error = assert_raises(SystemExit) do
      Surfguard::Release::PackageVerification.run_if_main("script", "script", [], runner: runner)
    end
    assert_equal 6, error.status
  end
end
