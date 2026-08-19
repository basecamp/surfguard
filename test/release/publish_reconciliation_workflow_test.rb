# frozen_string_literal: true

require_relative "../test_helper"
require "yaml"

class WorkflowPolicyTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  RELEASE = File.join(ROOT, ".github/workflows/release.yml")
  RECOVERY = File.join(ROOT, ".github/workflows/release-recovery.yml")
  CI = File.join(ROOT, ".github/workflows/ci.yml")
  DEPENDABOT = File.join(ROOT, ".github/workflows/dependabot-auto-merge.yml")
  ALLOWED_ACTION_REPOSITORIES = %w[
    actions/attest actions/checkout actions/dependency-review-action
    actions/download-artifact actions/setup-go actions/upload-artifact
    dependabot/fetch-metadata github/codeql-action
    rubygems/configure-rubygems-credentials ruby/setup-ruby
    softprops/action-gh-release zizmorcore/zizmor-action
  ].freeze

  def workflow(path = RELEASE)
    YAML.safe_load(File.read(path), aliases: false)
  end

  def scripts(job)
    job.fetch("steps").filter_map { |step| step["run"] }.join("\n")
  end

  def action_steps(job, repository)
    job.fetch("steps").select { |step| step["uses"]&.start_with?("#{repository}@") }
  end

  def test_oidc_publish_job_executes_no_checkout_setup_downloaded_script_or_installer
    publish = workflow.fetch("jobs").fetch("publish")
    assert_equal %w[name if needs runs-on timeout-minutes environment permissions env steps], publish.keys
    assert_equal "ubuntu-latest", publish.fetch("runs-on")
    assert_equal "release-rubygems", publish.fetch("environment")
    assert_equal({ "id-token" => "write" }, publish.fetch("permissions"))
    assert_operator publish.fetch("timeout-minutes"), :<=, 10

    uses = publish.fetch("steps").filter_map { |step| step["uses"] }
    assert_equal %w[actions/download-artifact rubygems/configure-rubygems-credentials],
      uses.map { |entry| entry.split("@").first }
    refute uses.any? { |entry| entry.start_with?("actions/checkout@", "ruby/setup-ruby@") }
    assert uses.all? { |entry| entry.match?(/@[0-9a-f]{40}\z/) }
    publish_scripts = scripts(publish)
    refute_match(/gem update|gem install|curl|wget|script\/release|bundle|ruby\/setup|source |chmod|\beval\b/, publish_scripts)
    assert_match(/gem push/, publish_scripts)
    downloads = action_steps(publish, "actions/download-artifact")
    assert_equal 1, downloads.length
    download = downloads.first
    assert_equal "rubygem", download.fetch("with").fetch("name")
    refute download.fetch("with").key?("path")

    scripts_by_name = publish.fetch("steps").filter_map do |step|
      [ step.fetch("name"), step.fetch("run") ] if step.key?("run")
    end.to_h
    assert_equal [
      "Verify artifact identity",
      "Push using only the hosted runner gem command",
      "Remove credentials created by the trusted-publishing action"
    ], scripts_by_name.keys
    assert_equal '[ "$(sha256sum "surfguard-${VERSION}.gem" | awk \'{print $1}\')" = "$GEM_SHA" ]',
      scripts_by_name.fetch("Verify artifact identity")
    assert_equal <<~'SHELL', scripts_by_name.fetch("Push using only the hosted runner gem command")
      [ "$(sha256sum "surfguard-${VERSION}.gem" | awk '{print $1}')" = "$GEM_SHA" ]
      gem push "surfguard-${VERSION}.gem"
    SHELL
    assert_equal <<~'SHELL'.chomp, scripts_by_name.fetch("Remove credentials created by the trusted-publishing action")
      ruby -e 'path = File.expand_path("~/.gem/credentials"); File.delete(path) if File.file?(path) && !File.symlink?(path)'
    SHELL
  end


  def test_dispatch_is_provably_no_publish_and_tag_authority_is_push_only
    release = workflow
    triggers = release.fetch(true)
    assert_equal [ "v*" ], triggers.fetch("push").fetch("tags")
    assert triggers.key?("workflow_dispatch")

    jobs = release.fetch("jobs")
    dispatch_jobs = %w[test source build package rebuild]
    assert_equal dispatch_jobs, jobs.keys.reject { |name| jobs.fetch(name)["if"] }
    %w[reconcile publish confirm attest github-release].each do |name|
      assert_equal "github.event_name == 'push'", jobs.fetch(name).fetch("if"), name
    end
    expected_graph = {
      "source" => %w[test],
      "build" => %w[source],
      "package" => %w[source build],
      "rebuild" => %w[source package],
      "reconcile" => %w[source package rebuild],
      "publish" => %w[source package reconcile],
      "confirm" => %w[source package publish],
      "attest" => %w[source package confirm],
      "github-release" => %w[source package confirm attest]
    }
    expected_graph.each do |name, needs|
      assert_equal needs, Array(jobs.fetch(name).fetch("needs")), name
    end

    dispatch_jobs.each do |name|
      assert_equal({ "contents" => "read" }, jobs.fetch(name).fetch("permissions"), name)
      refute jobs.fetch(name).key?("environment"), name
    end
  end

  def test_canonical_registry_artifact_is_the_only_attestation_and_release_input
    jobs = workflow.fetch("jobs")
    assert_equal [ "source", "package", "publish" ], Array(jobs.fetch("confirm").fetch("needs"))
    producers = jobs.flat_map do |name, job|
      action_steps(job, "actions/upload-artifact").filter_map do |step|
        name if step.fetch("with").fetch("name") == "canonical-gem"
      end
    end
    assert_equal [ "confirm" ], producers
    assert_equal [ "canonical-gem" ], action_steps(jobs.fetch("attest"), "actions/download-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    assert_equal [ "canonical-gem", "release-notes" ],
      action_steps(jobs.fetch("github-release"), "actions/download-artifact").map { |step| step.fetch("with").fetch("name") }
    release_inputs = jobs.fetch("github-release").fetch("steps").last.fetch("with")
    assert_equal false, release_inputs.fetch("overwrite_files")
    assert release_inputs.key?("target_commitish")
    assert_equal "RELEASE_NOTES_${{ needs.source.outputs.version }}.md", release_inputs.fetch("body_path")
    refute release_inputs.key?("make_latest")
    refute release_inputs.key?("generate_release_notes")
  end

  def test_canonical_artifact_producer_and_consumers_are_digest_gated_in_order
    jobs = workflow.fetch("jobs")
    confirm = jobs.fetch("confirm")
    assert_equal [ "source", "package", "publish" ], Array(confirm.fetch("needs"))
    confirm_steps = confirm.fetch("steps")
    script_download = confirm_steps.index { |step| step["uses"]&.start_with?("actions/download-artifact@") }
    script_check = confirm_steps.index { |step| step["name"] == "Verify release scripts before execution" }
    execution = confirm_steps.index { |step| step["name"] == "Save and verify canonical registry artifact" }
    upload = confirm_steps.index { |step| step["uses"]&.start_with?("actions/upload-artifact@") }
    assert_operator script_download, :<, script_check
    assert_operator script_check, :<, execution
    assert_operator execution, :<, upload
    assert_equal "canonical-gem", confirm_steps.fetch(upload).fetch("with").fetch("name")
    assert_match(/registry_confirm\.rb.*surfguard-\$\{VERSION\}\.gem/m, confirm_steps.fetch(execution).fetch("run"))

    %w[attest github-release].each do |name|
      job = jobs.fetch(name)
      download_index = job.fetch("steps").index { |step| step["uses"]&.start_with?("actions/download-artifact@") }
      digest_index = job.fetch("steps").index { |step| step["run"]&.include?("sha256sum") }
      authority_index = job.fetch("steps").index do |step|
        step["uses"]&.start_with?(name == "attest" ? "actions/attest@" : "softprops/action-gh-release@")
      end
      assert_operator download_index, :<, digest_index, name
      assert_operator digest_index, :<, authority_index, name
    end
  end

  def test_reconciliation_decision_fails_closed_and_is_allowlisted
    check = workflow.fetch("jobs").fetch("reconcile").fetch("steps")
      .find { |step| step["id"] == "check" }.fetch("run")

    # A standalone assignment (never inside `echo "$(…)"`) so a nonzero helper
    # exit fails the step, then an explicit push/skip allowlist before the
    # decision is recorded.
    assert_match(/^decision="\$\(ruby script\/release\/registry_check\.rb /, check)
    assert_includes check, "push|skip"
    refute_match(/echo "decision=\$\(/, check)
  end

  def test_release_creation_verifies_any_existing_asset_before_upload
    [ [ RELEASE, "EXPECTED_DIGEST" ], [ RECOVERY, "GEM_SHA256" ] ].each do |path, digest_variable|
      steps = workflow(path).fetch("jobs").fetch("github-release").fetch("steps")
      preflight = steps.index { |step| step["run"]&.include?("existing-asset.gem") }
      authority = steps.index { |step| step["uses"]&.start_with?("softprops/action-gh-release@") }

      refute_nil preflight, path
      assert_operator preflight, :<, authority, path
      assert_includes steps.fetch(preflight).fetch("run"), digest_variable
      assert_equal false, steps.fetch(authority).fetch("with").fetch("overwrite_files"), path
    end
  end

  def test_release_has_independent_rebuild_and_script_digest_verification
    jobs = workflow.fetch("jobs")
    assert jobs.key?("rebuild")
    assert_includes Array(jobs.fetch("reconcile").fetch("needs")), "rebuild"
    confirm_script = jobs.fetch("confirm").fetch("steps").filter_map { |step| step["run"] }.join("\n")
    assert_includes confirm_script, "registry_confirm.rb"
    assert_includes confirm_script, "sha256sum script/release/registry.rb"
  end

  def test_every_rubygems_installer_is_unprivileged_byte_pinned_and_version_checked
    release = workflow.fetch("jobs")
    recovery = workflow(RECOVERY).fetch("jobs")
    installer_jobs = [ release.fetch("build"), release.fetch("rebuild"), recovery.fetch("rebuild") ]

    installer_jobs.each do |job|
      assert_equal({ "contents" => "read" }, job.fetch("permissions"))
      script = scripts(job)
      fetch = script.index("gem fetch rubygems-update")
      digest = script.index("sha256sum --check")
      install = script.index("gem install --local")
      update = script.index("update_rubygems --no-document")
      version = script.index('"$(gem --version)" = "$RUBYGEMS_VERSION"')
      assert_operator fetch, :<, digest
      assert_operator digest, :<, install
      assert_operator install, :<, update
      assert_operator update, :<, version
      assert_includes script, "--clear-sources --source https://rubygems.org"
      refute_includes script, "gem update --system"
    end
  end

  def test_package_identity_is_proved_on_fresh_runners_before_authority
    jobs = workflow.fetch("jobs")
    assert_equal [ "source", "build" ], Array(jobs.fetch("package").fetch("needs"))
    assert_equal [ "source", "package" ], Array(jobs.fetch("rebuild").fetch("needs"))

    assert_equal [ "rubygem" ], action_steps(jobs.fetch("build"), "actions/upload-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    rubygem_producers = jobs.flat_map do |name, job|
      action_steps(job, "actions/upload-artifact").filter_map do |step|
        name if step.fetch("with").fetch("name") == "rubygem"
      end
    end
    assert_equal [ "build" ], rubygem_producers
    package = jobs.fetch("package")
    assert_equal [ "rubygem" ], action_steps(package, "actions/download-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    capture = package.fetch("steps").index { |step| step["name"] == "Capture immutable artifact digest" }
    verify = package.fetch("steps").index { |step| step["name"] == "Verify immutable candidate against source and installed bytes" }
    assert_operator capture, :<, verify
    verification_step = package.fetch("steps").fetch(verify)
    assert_equal "${{ needs.source.outputs.commit_sha }}", verification_step.fetch("env").fetch("SOURCE_COMMIT")
    assert_includes verification_step.fetch("run"), 'verify_package.rb "surfguard-${VERSION}.gem" surfguard "$VERSION" "$SOURCE_COMMIT"'
    assert_includes package.fetch("steps").fetch(verify).fetch("run"), "sha256sum"

    source = jobs.fetch("source")
    manifest = source.fetch("steps").find { |step| step["name"] == "Validate tag and capture source manifest" }
    assert_equal "${{ steps.manifest.outputs.commit_sha }}", source.fetch("outputs").fetch("commit_sha")
    assert_includes manifest.fetch("run"), 'git rev-parse "refs/tags/${REF_NAME}^{commit}"'
    assert_includes manifest.fetch("run"), 'git cat-file -t "$commit_sha"'
    assert_includes manifest.fetch("run"), 'echo "commit_sha=${commit_sha}"'

    publish = jobs.fetch("publish")
    assert_equal [ "rubygem" ], action_steps(publish, "actions/download-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    assert_equal "${{ needs.package.outputs.gem_sha256 }}", publish.fetch("env").fetch("GEM_SHA")
  end

  def test_every_release_job_has_the_planned_timeout
    workflow.fetch("jobs").each do |name, job|
      limit = %w[test source build package rebuild].include?(name) ? 15 : 10
      assert_operator job.fetch("timeout-minutes"), :<=, limit, name
    end
  end

  def test_ci_checks_bare_and_bundle_effective_resolv_versions
    release_test = workflow.fetch("jobs").fetch("test")
    assert_includes scripts(release_test), "ruby script/check_resolv_version.rb"
    assert_includes scripts(release_test), "bundle exec ruby script/check_resolv_version.rb"

    ci = workflow(CI).fetch("jobs")
    assert_includes scripts(ci.fetch("test")), "ruby script/check_resolv_version.rb"
    assert_includes scripts(ci.fetch("lint")), "bundle exec ruby script/check_resolv_version.rb"
    %w[platforms musl].each do |name|
      assert_includes scripts(ci.fetch(name)), "ruby script/check_resolv_version.rb", name
    end
  end

  def test_every_workflow_action_is_sha_pinned_and_in_the_repository_allowlist
    Dir[File.join(ROOT, ".github/workflows/*.yml")].each do |path|
      File.read(path).scan(/^\s*-?\s*uses:\s*([^\s#]+)/).flatten.each do |use|
        action, revision = use.split("@", 2)
        repository = action.split("/").first(2).join("/")
        assert_includes ALLOWED_ACTION_REPOSITORIES, repository, "#{path}: #{action}"
        assert_match(/\A[0-9a-f]{40}\z/, revision, "#{path}: #{use}")
      end
    end
  end

  def test_recovery_splits_attestation_and_release_permissions
    release_attest = workflow.fetch("jobs").fetch("attest")
    assert_equal({
      "id-token" => "write",
      "attestations" => "write",
      "artifact-metadata" => "write"
    }, release_attest.fetch("permissions"))
    assert_attestation_shape(release_attest, digest_name: "Independently recheck the canonical digest")

    recovery = workflow(RECOVERY).fetch("jobs")
    assert_equal({
      "id-token" => "write",
      "attestations" => "write",
      "artifact-metadata" => "write"
    }, recovery.fetch("attest").fetch("permissions"))
    assert_attestation_shape(recovery.fetch("attest"),
      digest_name: "Verify artifact identity (digest must match the verify job's)")
    assert_equal({ "contents" => "write" }, recovery.fetch("github-release").fetch("permissions"))
    assert_equal "release-recovery", recovery.fetch("attest").fetch("environment")
    assert_equal "github-release", recovery.fetch("github-release").fetch("environment")
  end

  def test_recovery_consumers_independently_verify_the_same_canonical_artifact
    recovery = workflow(RECOVERY).fetch("jobs")
    verify = recovery.fetch("verify")
    canonical_download = verify.fetch("steps").index { |step| step["name"] == "Download canonical bytes before executing package code" }
    canonical_upload = verify.fetch("steps").index do |step|
      step["uses"]&.start_with?("actions/upload-artifact@") && step.dig("with", "name") == "canonical-gem"
    end
    package_verification = verify.fetch("steps").index {
      |step| step["name"] == "Verify rebuilt package and prove rebuilt equals canonical"
    }
    assert_operator canonical_download, :<, canonical_upload
    assert_operator canonical_upload, :<, package_verification

    attest = recovery.fetch("attest")
    assert_equal [ "canonical-gem" ], action_steps(attest, "actions/download-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    assert_includes scripts(attest), "GEM_SHA256"

    release = recovery.fetch("github-release")
    assert_equal [ "canonical-gem", "release-notes" ], action_steps(release, "actions/download-artifact").map {
      |step| step.fetch("with").fetch("name")
    }
    assert_includes scripts(release), "GEM_SHA256"
    assert_includes scripts(release), "git/ref/tags/v${VERSION}"
    assert_includes scripts(release), '"$sha" = "$TAG_SHA"'
    inputs = release.fetch("steps").last.fetch("with")
    assert_equal false, inputs.fetch("overwrite_files")
    assert inputs.key?("target_commitish")
    assert_equal "RELEASE_NOTES_${{ inputs.version }}.md", inputs.fetch("body_path")
    refute inputs.key?("make_latest")
  end

  def test_ci_fan_in_has_an_explicit_closed_skip_policy
    ci = workflow(CI).fetch("jobs")
    fan_in = ci.fetch("ci")
    expected = %w[test lint lint-actions dependency-review package-build package platforms musl iana-drift codeql go-test go-lint go-fuzz]
    assert_equal expected, fan_in.fetch("needs")
    assert_equal "always()", fan_in.fetch("if")
    fan_in_scripts = fan_in.fetch("steps").map { |step| [ step["if"], step["run"] ] }
    assert fan_in_scripts.any? { |condition, run| condition&.include?("failure") && condition.include?("cancelled") && run == "exit 1" }
    assert fan_in_scripts.any? { |condition, run| condition&.include?("needs.iana-drift.result == 'skipped'") && run == "exit 1" }
    assert fan_in_scripts.any? { |condition, run| condition&.include?("needs.dependency-review.result == 'skipped'") && run == "exit 1" }
    required = %w[test lint lint-actions package-build package platforms musl codeql go-test go-lint go-fuzz]
    skip_condition = fan_in_scripts.filter_map { |condition, run| condition if run == "exit 1" }.find do |condition|
      required.all? { |name| condition.include?("needs.#{name}.result == 'skipped'") }
    end
    refute_nil skip_condition
  end

  def test_dependabot_never_checks_out_head_and_revalidates_protected_base_and_identity_at_both_boundaries
    jobs = workflow(DEPENDABOT).fetch("jobs")
    all_uses = jobs.values.flat_map { |job| job.fetch("steps").filter_map { |step| step["uses"] } }
    refute all_uses.any? { |entry| entry.start_with?("actions/checkout@") }
    assert_equal [ "dependabot/fetch-metadata" ], all_uses.map { |entry| entry.split("@").first }.uniq

    metadata_condition = jobs.fetch("metadata").fetch("if")
    assert_includes metadata_condition, "github.event.pull_request.state == 'open'"
    assert_includes metadata_condition, "github.event.pull_request.draft == false"
    assert_includes metadata_condition, "github.event.pull_request.base.repo.full_name == github.repository"
    assert_includes metadata_condition, "github.event.pull_request.base.ref == 'main'"
    assert_includes metadata_condition, "github.event.pull_request.head.repo.full_name == github.repository"

    steps = jobs.fetch("automerge").fetch("steps")
    initial = steps.fetch(0).fetch("run")
    assert_includes initial, '[ "$state" = "open" ]'
    assert_includes initial, '[ "$draft" = "false" ]'
    assert_includes initial, '[ "$base_repo" = "$REPO" ]'
    assert_includes initial, '[ "$base_ref" = "main" ]'
    assert_includes initial, 'fetch_file .github/scripts/validate_dependabot_lockfile.rb "$base_sha" validator.rb'
    assert_includes initial, 'fetch_file Gemfile.lock "$base_sha" base.lock'
    assert_includes initial, 'fetch_file Gemfile.lock "$head_sha" head.lock'
    assert_includes initial, '[[ "$base_sha" =~ ^[0-9a-f]{40}$ ]]'
    assert_includes initial, 'echo "base_sha=${base_sha}" >> "$GITHUB_OUTPUT"'

    assert_equal "${{ steps.validation.outputs.base_sha }}",
      steps.fetch(1).fetch("env").fetch("VALIDATED_BASE_SHA")

    boundary = steps.fetch(1).fetch("run")
    assert_includes boundary, "revalidate_current_pr()"
    assert_equal [ "before approval", "before merge" ],
      boundary.scan(/^\s*revalidate_current_pr "([^"]+)"$/).flatten
    assert_includes boundary, '.state == "open" and .draft == false'
    assert_includes boundary, '.user.login == "dependabot[bot]"'
    assert_includes boundary, ".head.sha == $head and .head.repo.full_name == $repo"
    assert_includes boundary, '.base.sha == $base and .base.ref == "main"'
    assert_includes boundary, ".base.repo.full_name == $repo"
    assert_includes boundary, '.author.login == "dependabot[bot]"'
    # Dependabot commits are committed and signed server-side by GitHub.
    assert_includes boundary, '.committer.login == "web-flow"'
    assert_includes boundary, ".commit.verification.verified == true"
    assert_operator boundary.index('revalidate_current_pr "before approval"'), :<, boundary.index("-f event=APPROVE")
    assert_operator boundary.index("-f event=APPROVE"), :<, boundary.index('revalidate_current_pr "before merge"')
    assert_operator boundary.index('revalidate_current_pr "before merge"'), :<,
      boundary.index('gh pr merge "$PR_URL"')
    assert_includes boundary, '--match-head-commit "$EVENT_HEAD_SHA"'
  end

  private
    def assert_attestation_shape(job, digest_name:)
      steps = job.fetch("steps")
      assert_equal 3, steps.length
      assert_equal [ "actions/download-artifact", "actions/attest" ],
        steps.filter_map { |step| step["uses"]&.split("@")&.first }
      assert_equal [ digest_name ], steps.filter_map { |step| step["name"] if step.key?("run") }
      assert_equal [ "canonical-gem" ], action_steps(job, "actions/download-artifact").map {
        |step| step.fetch("with").fetch("name")
      }
      digest_script = steps.find { |step| step["name"] == digest_name }.fetch("run")
      assert_includes digest_script, "sha256sum"
      refute_match(/curl|wget|gem install|bundle|source |chmod|\beval\b/, digest_script)
    end
end
