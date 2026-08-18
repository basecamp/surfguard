# Releasing surfguard

Releases are cut by tagging `main`. The tag triggers `.github/workflows/release.yml`:

```
test -> build -> publish -> confirm -> attest -> github-release
```

- **test** — RuboCop + the full suite (coverage thresholds enforced).
- **build** — unprivileged job that builds the gem with an exactly pinned
  toolchain (Ruby + RubyGems versions in `release.yml`; `SOURCE_DATE_EPOCH`
  from the commit, so identical source produces identical bytes), verifies the
  package (`script/release/verify_package.rb`), and emits the artifact plus its
  SHA-256. Artifact identity flows forward **by digest**: every later job
  re-downloads the artifact and asserts that digest before acting.
- **publish** — the only job that can mint RubyGems credentials, gated by the
  `release-rubygems` environment (required reviewer: Jeremy) and OIDC trusted
  publishing. No checkout and no artifact-delivered executable code: only the
  `.gem` enters this job. Before pushing it reconciles with the registry using
  workflow-owned `curl`/`jq` — a total state machine: version absent → push;
  already published with exactly our bytes → skip (idempotent re-run);
  anything else → fail closed. It verifies the gem digest again immediately
  before `gem push`. Credentials are scrubbed unconditionally (`if: always()`),
  even when the push fails.
- **confirm** — deliberately credential-free (`permissions: {}`): polls the
  registry until it reports exactly our version with exactly our digest, then
  downloads the canonical bytes from RubyGems and asserts their digest equals
  the artifact digest.
- **attest** — attests SLSA build provenance for the canonical,
  registry-confirmed bytes only.
- **github-release** — creates the GitHub Release with the exact `.gem`
  attached (`fail_on_unmatched_files: true`).

`workflow_dispatch` on `release.yml` is always a **no-publish rehearsal**:
test → build only. No environment prompt, no credentials, no attestation.
Rehearse before every first-of-its-kind release.

## Cutting a release

1. For a version bump: `rake "bump[X.Y.Z]"` on a clean branch, review, PR,
   merge. `bump`
   rewrites `lib/surfguard/version.rb` and refreshes `Gemfile.lock`; it
   commits nothing itself.
2. **First release only:** verify/create the RubyGems pending trusted
   publisher **immediately before tagging** (pending publishers expire after
   ~12 hours) — see one-time setup below.
3. On an up-to-date `main` checkout: `rake tag`. Guards: clean tree, on
   `main`, HEAD == `origin/main` after fetch, tag absent locally and remotely.
   It pushes `main` first, then the tag.
4. Approve the `release-rubygems` environment when the run pauses.
5. Watch the run to completion. Verify afterwards:
   - digest equality across the RubyGems download, the GitHub Release asset,
     and the attestation subject;
   - `gh attestation verify surfguard-X.Y.Z.gem --signer-workflow basecamp/surfguard/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z` —
     constrain by signer workflow **and** source ref, not just `--repo`.
     (A release finished by the recovery workflow is signed by it instead:
     use `--signer-workflow basecamp/surfguard/.github/workflows/release-recovery.yml`,
     with `--source-ref refs/tags/vX.Y.Z` when recovery was dispatched on the
     tag — the preferred mode — or `--source-ref refs/heads/main` when it had
     to be dispatched on `main`.)
6. **First release only:** verify durable ownership on RubyGems — the gem
   sits under the RubyGems `basecamp` organization / the correct owner
   accounts with MFA enforced — before announcing.

### One release at a time

The release workflow uses a constant concurrency group
(`release-publishing`, `cancel-in-progress: false`). GitHub retains only
**one pending run per group**: if two tags are pushed in quick succession, the
middle run is silently dropped. Rapid successive release tags are therefore
prohibited — cut one release, let its run finish, then cut the next.

## Recovery

The registry reconciliation makes re-running a tag's workflow **idempotent**:
it never re-pushes bytes that are already published, and it fails closed on
any conflict. Recovery rules, by failure state:

| State | Recovery |
|---|---|
| Failure before `gem push` ran (test/build/reconciliation) | Fix on `main`; delete the unpublished tag; re-tag. Allowed **only** because nothing was published. Tag deletion has **no standing bypass** — an admin must temporarily lift the `release-tags-immutable` ruleset, delete, and re-enable it. That friction is deliberate. |
| Push succeeded; confirm/attest/release failed | Re-run the same run/tag. Reconciliation sees same-SHA → skips the push; downstream completes idempotently. |
| **Ambiguous push result** (push errored/timed out; registry state unknown) | Never use a later 404 to justify deleting or moving the tag. Poll, then **download the canonical RubyGems bytes and compare digests**. Match → re-run the same tag to finish. Absent after bounded polling → re-run the same tag (reconciliation decides). Indeterminate/conflicting → **stop; contact RubyGems support**. |
| Workflow defect embedded in a published tag | Re-runs use the tagged workflow; fixing `main` doesn't fix the tag. Never move/delete the tag. Run `release-recovery.yml` (dispatch with the version) to finish attestation + the GitHub Release from verified canonical registry bytes; ship the workflow fix in the next version. |
| Bad published release | Never re-point or delete the tag. Ship a new patch version (per SECURITY.md, fixes ship as new releases). Yank only for security-critical cases. |

`release-recovery.yml` never publishes and never mints RubyGems credentials.
It mirrors the release pipeline's privilege separation: an **unprivileged
`verify` job** proves the `vX.Y.Z` tag exists on `main` (so a typo can never
attest an arbitrary registry version or mint a fresh tag at the
default-branch tip), extracts the tagged source to the side with
`git archive` (the recovery helpers keep running from the dispatch revision,
not the possibly-defective tag), **rebuilds the gem with the tag's own
toolchain pins**, and requires the rebuilt digest to equal the canonical
RubyGems digest. Only then does the **reviewer-gated `finish` job**
(`release-recovery` environment, same reviewer as publishing, no checkout)
attest and create the GitHub Release from the canonical bytes. That digest
equality is what makes the recovery attestation honest: the attested bytes
are demonstrably the product of the tagged source, not merely whatever the
registry served. A mismatch stops the workflow for a human.

Dispatch recovery **on the release tag** when possible:

```sh
gh workflow run release-recovery.yml --ref vX.Y.Z --field version=X.Y.Z
```

so the attestation's source ref binds to `refs/tags/vX.Y.Z` and the
documented `--source-ref` verification holds. Dispatch on `main`
(`--ref main`) only when the tag's own copy of the recovery workflow is
defective; provenance then binds to `refs/heads/main`, and the binding to
the tag rests on the run's logged rebuild-equality proof.

## Threat model — an honest limitation

Repository-level controls **cannot defend against malicious repository
administrators**: admins can edit the controls themselves. With 19 effective
admins on this repo, that residual exposure is real. The setup below narrows
*routine* release authority to Jeremy; it does not and cannot make admins
powerless. Before announcing Surfguard as a public security control, re-audit
effective admin membership, reduce it, and/or impose independently managed
org-level governance (org rulesets). That risk cannot be eliminated by another
repository-owned workflow or ruleset.

## One-time setup

Idempotent payloads, each **read back** to assert the declared invariant.
Replace IDs where noted.

1. **Workflow token defaults** — read-only token, bot approvals enabled
   (required for zero-touch Dependabot automation), and the repository's
   auto-merge setting (independent of token permissions; `gh pr merge --auto`
   fails without it):

   ```sh
   gh api -X PUT repos/basecamp/surfguard/actions/permissions/workflow \
     -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
   gh api repos/basecamp/surfguard/actions/permissions/workflow

   gh api -X PATCH repos/basecamp/surfguard -F allow_auto_merge=true
   gh api repos/basecamp/surfguard --jq .allow_auto_merge
   ```

2. **Release actor** — a dedicated one-member team
   (`@basecamp/surfguard-releasers`, member: Jeremy), or a dedicated GitHub
   App if org-team creation is unavailable. **Never `RepositoryRole: admin`
   as a bypass actor** — that would grant all 19 admins release authority.

3. **Environment `release-rubygems`** — required reviewer is Jeremy's
   **numeric user id**; `prevent_self_review: false` (deliberate: the gate
   stops the other collaborators, not Jeremy); **`can_admins_bypass: false`**
   (admins bypass protection rules by default otherwise); deployment branch
   policy restricted to `v*` **tags**:

   ```sh
   reviewer_id=$(gh api users/jeremy --jq .id)
   gh api -X PUT repos/basecamp/surfguard/environments/release-rubygems \
     --input - <<JSON
   { "reviewers": [{ "type": "User", "id": ${reviewer_id} }],
     "prevent_self_review": false,
     "can_admins_bypass": false,
     "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
   JSON
   gh api -X POST repos/basecamp/surfguard/environments/release-rubygems/deployment-branch-policies \
     -f name='v*' -f type=tag
   gh api repos/basecamp/surfguard/environments/release-rubygems
   gh api repos/basecamp/surfguard/environments/release-rubygems/deployment-branch-policies
   ```

3a. **Environment `release-recovery`** — same reviewer and
   `can_admins_bypass: false` as above, with deployment branch policies for
   both `main` (branch type) and `v*` (tag type): recovery is preferably
   dispatched on the release tag (binding provenance to it) and falls back
   to `main`. Gates `release-recovery.yml`'s attestation + Release
   permissions behind the same human as publishing.

4. **Tag rulesets** — two separate rulesets on `refs/tags/v*`, enforcement
   `active`: (a) creation restricted, bypass_actors = the release team only
   (`bypass_mode: always`); (b) update + deletion blocked with **no** bypass
   actors. Read back both, asserting enforcement and bypass lists.

5. **Main branch ruleset** — require PRs (≥ 1 approving review, code-owner
   review, **dismiss stale approvals on push** — the Dependabot automation's
   revoke path assumes it), required status check **`CI`** bound to the
   GitHub Actions app (integration_id **15368**) with strict up-to-date
   policy, block deletion + force pushes. Bypass: the release team with
   `bypass_mode: pull_request` (so Jeremy's own PRs don't deadlock on
   self-approval). Read back.

6. **Server-side SHA pinning** — after the pinned workflows merge, enable
   "require actions to be pinned to a full-length commit SHA"; read back.

7. **Dependabot security updates**:

   ```sh
   gh api -X PUT repos/basecamp/surfguard/automated-security-fixes
   gh api repos/basecamp/surfguard/automated-security-fixes
   ```

8. **Labels** — `gh label create --force` for `breaking`, `enhancement`,
   `bug`, `ci`, `dependencies`, `github-actions`, `documentation`.

9. **Dependency graph** — confirm enabled (Settings → Security).

10. **RubyGems trusted publisher** — **immediately before v0.1.0** (pending
    publishers expire ~12h): create/verify the pending trusted publisher for
    gem `surfguard`: owner `basecamp`, repository `surfguard`, workflow
    `release.yml`, environment `release-rubygems`. A v1 API 404 for the gem
    name is **never** treated as proof the name is unclaimed. **After first
    publication**: move/verify ownership under the RubyGems `basecamp`
    organization with MFA enforced, before announcing.

## Dependabot automation

`dependabot-auto-merge.yml` auto-approves and auto-merges **Bundler
patch/minor** updates only, via a constrained `pull_request_target` workflow
that never checks out or executes PR-controlled code. Everything else —
bundler major, all github-actions updates — is human-gated. The approval is
created through the API pinned to the validated head commit, the merge is
pinned with `--match-head-commit`, and a human push to a Dependabot PR
triggers a revoke job that disables any pending auto-merge (the
dismiss-stale-reviews branch rule retracts the bot approval at the same
time). CODEOWNERS pairs a blanket `* @jeremy` rule with an ownerless
`/Gemfile.lock` override: every path requires code-owner review except the
lockfile, so lockfile-only Dependabot PRs don't deadlock on code-owner
review while any PR touching anything else stays human-gated; the required
`CI` check still gates every merge.
