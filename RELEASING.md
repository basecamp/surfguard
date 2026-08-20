# Releasing surfguard

Releases are cut by tagging `main`. The tag triggers `.github/workflows/release.yml`:

```
test -> source -> build -> package -> independent rebuild -> reconcile -> publish -> confirm -> attest -> github-release
```

- **test** — RuboCop + the full suite (coverage thresholds enforced).
- **source** — validates the version and annotated release tag without running
  repository code, then emits immutable, SHA-256-addressed release helpers and
  the reviewed release notes.
- **build** — unprivileged job that builds the gem with an exactly pinned
  toolchain (Ruby + RubyGems versions in `release.yml`; `SOURCE_DATE_EPOCH`
  from the commit, so identical source produces identical bytes) and uploads
  the candidate. It does not supply its own verification result.
- **package** — a fresh runner downloads the immutable build artifact, records
  its digest before executing package code, verifies the raw archive, source
  bytes/modes, isolated installation, and installed-byte suite, then rechecks
  the original path. This job's digest is the identity every authority-bearing
  job must consume.
- **rebuild** — a second fresh runner must reproduce the verified package
  digest and pass the same package verifier.
- **reconcile** — an unprivileged, credential-free registry state machine; its
  downloaded scripts are checked against the source-manifest digests before
  execution.
- **publish** — the only job that can mint RubyGems credentials, gated by the
  `release-rubygems` environment (required reviewer: Jeremy) and OIDC trusted
  publishing. No checkout and no artifact-delivered executable code: only the
  `.gem` enters this job. It has no checkout, Ruby setup, installer, downloaded
  script, or arbitrary executable download and uses the hosted `gem` command
  only for `gem push`. If trusted-publishing credentials were configured, the
  action-created credentials file is removed on success or failure; this is not
  a claim that arbitrary process state can be scrubbed.
- **confirm** — deliberately credential-free (`permissions: {}`): polls the
  registry until it reports exactly our version with exactly our digest, then
  downloads and atomically saves the canonical bytes from RubyGems, asserts
  their digest, and uploads them as `canonical-gem`.
- **attest** — attests SLSA build provenance for the canonical,
  registry-confirmed bytes only.
- **github-release** — independently rechecks the canonical digest and tag SHA,
  disables asset overwrite, uses the verified commit as `target_commitish`,
  and publishes only the reviewed, digest-checked release notes.

`workflow_dispatch` on `release.yml` is always a **no-publish rehearsal**:
test → source → build → package → independent rebuild only. No environment
prompt, credentials, registry reconciliation, attestation, or release creation.
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
   `main`, HEAD == the fetched canonical push URL, and the remote tag absent.
   Retry is allowed only for an exact annotated local tag that peels to HEAD.
4. Approve the `release-rubygems` environment when the run pauses.
5. Watch the run to completion. Verify afterwards:
   - digest equality across the RubyGems download, the GitHub Release asset,
     and the attestation subject;
   - constrain attestation verification by repository, signer workflow,
     **and** source ref:

     ```sh
     gh attestation verify surfguard-X.Y.Z.gem \
       --repo basecamp/surfguard \
       --signer-workflow basecamp/surfguard/.github/workflows/release.yml \
       --source-ref refs/tags/vX.Y.Z
     ```

     A release finished by recovery is signed by that workflow instead:

     ```sh
     gh attestation verify surfguard-X.Y.Z.gem \
       --repo basecamp/surfguard \
       --signer-workflow basecamp/surfguard/.github/workflows/release-recovery.yml \
       --source-ref refs/tags/vX.Y.Z
     ```

     Use `--source-ref refs/heads/main` only when recovery had to be dispatched
     on `main`. The GitHub CLI requires `--repo` or `--owner`; the signer
     constraints do not replace it.
6. **First release only:** verify durable ownership on RubyGems — the gem
   sits under the RubyGems `basecamp` organization / the correct owner
   accounts with MFA enforced — before announcing.

### One release at a time

The release workflow uses a constant concurrency group
(`release-publishing`, `cancel-in-progress: false`). GitHub retains only
**one pending run per group**: if two tags are pushed in quick succession, the
middle run is silently dropped. Rapid successive release tags are therefore
prohibited — cut one release, let its run finish, then cut the next.

### Releasing the Go module

Everything above concerns the gem. The Go module at `go/` versions
independently and has **no publish pipeline**: tagging is the release.

1. On an up-to-date `main` whose CI is green, annotate a tag named
   `go/vX.Y.Z` — the subdirectory prefix is required by Go's module rules, and
   the version applies to `go/` only, never to the gem.
2. Push it. No workflow runs (see the tag ruleset note below); the module
   becomes fetchable the first time anyone requests it.
3. Verify from outside the repository, not from the checkout — a working tree
   proves nothing about what was published:

   ```sh
   cd "$(mktemp -d)" && go mod init verify
   go get github.com/basecamp/surfguard/go@vX.Y.Z
   ```

**Major version 2 and beyond.** Go requires the major suffix in the module
path itself, so v2 is not just a different tag: `go/go.mod` must declare
`module github.com/basecamp/surfguard/go/v2`, the package's own imports and
the README must use that path, and consumers `go get
github.com/basecamp/surfguard/go/v2@v2.X.Y`. The repository tag stays
`go/v2.X.Y` — the `/v2` belongs to the module path, not the tag. Tagging v2
without moving the module path first produces a tag Go refuses to resolve.

There is no yank and no re-point. `proxy.golang.org` and `sum.golang.org`
record the tag's contents permanently on first fetch, so a mutated tag does
not reach anyone who has already fetched it — and, worse, silently disagrees
with the checksum database for everyone who has.

That protection is not universal, and the exposed set is narrower than "anyone
not using the proxy": it is consumers configured to fetch straight from
version control, meaning `GOPROXY=direct` or a `GOPRIVATE`/`GONOPROXY` pattern
matching this module. Those builds read the tag from the repository and are
covered by neither the proxy nor the checksum database. (Vendoring is *not* in
that set — a vendored build uses the checked-in `vendor/` tree without
fetching, and `go mod vendor` itself downloads through `GOPROXY` like any
other module command.) Protecting those consumers is what the
`refs/tags/go/v*` immutability ruleset is for. A bad release ships as a new
patch version, exactly as it does for the gem.

## Recovery

The registry reconciliation makes re-running a tag's workflow **idempotent**:
it never re-pushes bytes that are already published, and it fails closed on
any conflict. Recovery rules, by failure state:

| State | Recovery |
|---|---|
| Failure before `gem push` ran (test/source/build/package/rebuild/reconciliation) | Fix on `main`; delete the unpublished tag; re-tag. Allowed **only** because nothing was published. Tag deletion has **no standing bypass** — an admin must temporarily lift the `release-tags-immutable` ruleset, delete, and re-enable it. That friction is deliberate. |
| Push succeeded; confirm/attest/release failed | Re-run the same run/tag. Reconciliation sees same-SHA → skips the push; downstream completes idempotently. |
| **Ambiguous push result** (push errored/timed out; registry state unknown) | Never use a later 404 to justify deleting or moving the tag. Poll, then **download the canonical RubyGems bytes and compare digests**. Match → re-run the same tag to finish. Absent after bounded polling → re-run the same tag (reconciliation decides). Indeterminate/conflicting → **stop; contact RubyGems support**. |
| Workflow defect embedded in a published tag | Re-runs use the tagged workflow; fixing `main` doesn't fix the tag. Never move/delete the tag. Run `release-recovery.yml` (dispatch with the version) to finish attestation + the GitHub Release from verified canonical registry bytes; ship the workflow fix in the next version. |
| Bad published release | Never re-point or delete the tag. Ship a new patch version (per SECURITY.md, fixes ship as new releases). Yank only for security-critical cases. |

`release-recovery.yml` never publishes and never mints RubyGems credentials.
It mirrors the release pipeline's privilege separation: an **unprivileged
`rebuild` job** proves the `vX.Y.Z` tag exists on `main` (so a typo can never
attest an arbitrary registry version or mint a fresh tag at the default-branch
tip), extracts the tagged source to the side with `git archive`, and rebuilds
the gem with the tag's own toolchain pins. A separate fresh **`verify` job**
revalidates the immutable tag, downloads and uploads the canonical RubyGems
bytes before executing tagged package code, then verifies the immutable
rebuild artifact against the tagged source and requires rebuilt == canonical.
Only then do separate reviewer-gated jobs independently recheck the canonical
digest: `attest` has only OIDC/attestation authority, and `github-release` has
only `contents: write` and immediately re-reads the tag before creating the
Release. That digest
equality is what makes the recovery attestation honest: the attested bytes
are demonstrably the product of the tagged source, not merely whatever the
registry served. A mismatch stops the workflow for a human.

Recovery applies to **0.2.0+ tags only** — releases cut by the pipeline it
mirrors, whose tags carry the toolchain digest pins, `RELEASE_NOTES_X.Y.Z.md`,
and the package contract the verifier asserts. The 0.1.x releases are already
complete (published, attested, released), so there is nothing for recovery to
finish; a defective earlier release ships a new patch version per SECURITY.md.
The workflow refuses pre-0.2.0 tags with an explicit error rather than
carrying untestable legacy fallbacks.

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

Setup payloads, each **read back** to assert the declared invariant. Creation
calls are one-time operations and can report an already-existing resource when
repeated. Replace IDs where noted.

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
   to `main`. This environment gates only the recovery `attest` job's
   OIDC/attestation authority.

3b. **Environment `github-release`** — same reviewer,
   `prevent_self_review: false`, and `can_admins_bypass: false`, also with
   `main` (branch) and `v*` (tag) deployment policies. This distinct
   environment gates the `contents: write` GitHub Release job in both normal
   and recovery workflows. Configure and read back both environments before
   either workflow references them:

   ```sh
   reviewer_id=$(gh api users/jeremy --jq .id)
   for environment in release-recovery github-release; do
     gh api -X PUT "repos/basecamp/surfguard/environments/${environment}" \
       --input - <<JSON
   { "reviewers": [{ "type": "User", "id": ${reviewer_id} }],
     "prevent_self_review": false,
     "can_admins_bypass": false,
     "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
   JSON
     gh api -X POST "repos/basecamp/surfguard/environments/${environment}/deployment-branch-policies" \
       -f name=main -f type=branch
     gh api -X POST "repos/basecamp/surfguard/environments/${environment}/deployment-branch-policies" \
       -f name='v*' -f type=tag
     gh api "repos/basecamp/surfguard/environments/${environment}"
     gh api "repos/basecamp/surfguard/environments/${environment}/deployment-branch-policies"
   done
   ```

4. **Tag rulesets** — two separate rulesets, each matching **both**
   `refs/tags/v*` (the gem) and `refs/tags/go/v*` (the Go module), enforcement
   `active`: (a) creation restricted, bypass_actors = the release team only
   (`bypass_mode: always`); (b) update + deletion blocked with **no** bypass
   actors. Read back both, asserting enforcement, the full include list, and
   bypass lists.

   A ref-name pattern's `*` does not cross `/`, so `refs/tags/v*` alone matches
   no `go/` tag at all: listing the Go pattern is what protects those tags, not
   an extra precaution. The same rule is why a `go/vX.Y.Z` tag does not trigger
   `release.yml` (`tags: [ "v*" ]`), which is deliberate — the Go module has no
   publish pipeline to run.

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

10. **RubyGems trusted publisher** — **immediately before a release** (pending
    publishers expire ~12h): create/verify the pending trusted publisher for
    gem `surfguard`: owner `basecamp`, repository `surfguard`, workflow
    `release.yml`, environment `release-rubygems`. A v1 API 404 for the gem
    name is **never** treated as proof the name is unclaimed. **After first
    publication**: move/verify ownership under the RubyGems `basecamp`
    organization with MFA enforced, before announcing. Save the owner/MFA and
    trusted-publisher readback with the release evidence. For 0.2.0 that
    evidence remains pending because this implementation does not publish.

## 0.2.0 control readback (2026-08-17)

Before either workflow referenced it, `github-release` was created and read
back with sole reviewer `jeremy` (numeric id 199), self-review allowed,
`can_admins_bypass: false`, and deployment policies `v*` (tag) plus `main`
(branch). The unused `copilot` environment was verified to have no protection
rules and deleted; readback lists only `github-release`, `release-recovery`,
and `release-rubygems`.

Repository Actions were changed from unrestricted to selected repositories
and read back with full-SHA pinning required, GitHub-owned/verified blanket
allowances disabled, and only repositories referenced by checked-in workflows
allowed. RubyGems owner/MFA and trusted-publisher evidence is still a mandatory
manual pre-tag gate. No tag or publication was performed.

## Dependabot automation

`dependabot-auto-merge.yml` auto-approves and auto-merges **lockfile-only,
single-direct-dependency Bundler patch/minor** updates, via a constrained `pull_request_target` workflow
that never checks out or executes PR-controlled code. Everything else —
bundler major, all github-actions updates — is human-gated. The approval is
created through the API pinned to the validated head commit, and the merge is
pinned with `--match-head-commit`. Automation requires an open, non-draft PR
authored by Dependabot, a same-repository Dependabot head, and a base in this
repository's protected `main`. The current base/head identity and every
commit's Dependabot author, committer, and verified signature are checked
again immediately before approval and immediately before merge enablement. A
human push to a Dependabot PR triggers a revoke job that disables any pending
auto-merge (the dismiss-stale-reviews branch rule retracts the bot approval at
the same time). The trusted-base validator and base/head lockfiles are fetched
through the API at exact SHAs; PR code is never checked out. Source, structure,
prerelease, major, transitive, grouped, ambiguous, added, or removed changes
require human review. CODEOWNERS uses an ownerless trailing `/Gemfile.lock` pattern to remove
lockfile ownership while its catch-all protects every other path; the required
`CI` check still gates every merge.
