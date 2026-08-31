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
3. **Tag the commit you rehearsed — not "latest `main`".** Immediately before
   `rake tag`, assert that the checkout is still exactly the rehearsed commit
   and that remote `main` has not moved past it:

   ```sh
   REHEARSED=<head_sha of the successful workflow_dispatch run>
   test "$(git rev-parse HEAD)" = "$REHEARSED" || { echo "checkout is not the rehearsed commit"; exit 1; }
   test "$(gh api repos/basecamp/surfguard/commits/main --jq .sha)" = "$REHEARSED" \
     || { echo "remote main advanced; re-rehearse on the new head"; exit 1; }
   ```

   Do **not** `git pull` at this point. A fast-forward here silently moves the
   checkout off the rehearsed commit onto one whose bytes nobody has built, and
   `rake tag` would accept it — its guard is HEAD == fetched `main`, which a
   pull satisfies by construction. If `main` has advanced, the answer is to
   re-rehearse on the new head, not to tag past the rehearsal.

   Then `rake tag`. Guards: clean tree, on `main`, HEAD == the fetched
   canonical push URL, and the remote tag absent. Retry is allowed only for an
   exact annotated local tag that peels to HEAD. The residual race is safe in
   one direction only: if `main` advances between the assertion and the push,
   `rake tag` re-fetches and aborts — it cannot tag the wrong commit, it can
   only refuse.
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

1. Add the version's entry to `go/CHANGELOG.md` and merge it **before**
   tagging. A new deny is a minor bump and the entry must name the range and
   the `conformance/` case, per the promise in `go/README.md` and
   `conformance/README.md`. Tagging first would ship a version whose only
   description is the tag message, which nobody reads without a checkout.
2. On an up-to-date `main` whose CI is green, annotate a tag named
   `go/vX.Y.Z` — the subdirectory prefix is required by Go's module rules, and
   the version applies to `go/` only, never to the gem.
3. Push it. No workflow runs (see the tag ruleset note below); the module
   becomes fetchable the first time anyone requests it.
4. Verify from outside the repository, not from the checkout — a working tree
   proves nothing about what was published. Two things in your environment
   will otherwise answer the check for you:

   - **The module cache is global.** A throwaway *directory* is not enough —
     once you have fetched the version even once, which right after tagging
     you have, `go get` is served from `GOMODCACHE` without contacting
     anything. Give the check its own cache.
   - **`GOPRIVATE` outranks a pinned `GOPROXY`.** It is the default for
     `GONOPROXY` and `GONOSUMDB`, so a pattern matching this module sends the
     fetch straight to VCS and skips the checksum database — even with the
     public proxy named on the command line. Override all three patterns, not
     just `GOPROXY`/`GOSUMDB`.

   ```sh
   cache="$(mktemp -d)"
   cd "$(mktemp -d)" && go mod init verify
   GOMODCACHE="$cache" GOPRIVATE= GONOPROXY=none GONOSUMDB=none \
     GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
     go get github.com/basecamp/surfguard/go@vX.Y.Z
   GOMODCACHE="$cache" go clean -modcache
   ```

   It must print `go: downloading …`. Then confirm the check can actually
   fail, because a verification you have never seen fail is not evidence:
   re-run it with a fresh `cache` and `GOPROXY=off`, keeping the same three
   pattern overrides. That must report `module lookup disabled by
   GOPROXY=off`. If it succeeds, something answered locally — a warm cache, or
   a `GONOPROXY` pattern reaching VCS — and the positive run proved nothing.
5. Only once step 4 passes, publish a GitHub Release on the tag whose body is
   the entry from step 1. No pipeline does this — the gem's `github-release`
   job is bound to `refs/tags/v*` and never sees a `go/` tag — so it is manual,
   and skipping it leaves a Go consumer with nowhere to read what shipped:

   ```sh
   version=X.Y.Z
   # The changelog file is the source; the Release body is a copy of one
   # section. Read the extract before posting.
   awk -v v="## v${version} " \
     'index($0, v) == 1 { f = 1; next } f && /^## / { exit } f' \
     go/CHANGELOG.md > /tmp/go-notes.md
   gh release create "go/v${version}" --repo basecamp/surfguard \
     --title "Surfguard for Go ${version}" --notes-file /tmp/go-notes.md
   ```

   It comes last because it is the announcement: publishing before step 4 would
   advertise a version that may not resolve. Unlike the gem's Release, this one
   carries no digest-verified asset — the module's bytes are whatever the tag
   contains, and `sum.golang.org`, not this Release, is what attests them.
   Attach nothing; the Release is the notes only.

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

That protection is not universal, but the uncovered set is much narrower than
"anyone not using the proxy", and the two mechanisms have to be kept apart to
see why. The go command validates downloaded modules against `sum.golang.org`
**regardless of where they were fetched from**, so bypassing the proxy alone —
`GOPROXY=direct`, or a `GONOPROXY` pattern — does not bypass verification: a
moved tag fails the checksum check loudly rather than being accepted.

A mutated tag can only actually reach a consumer whose checksum verification
is off for this module too: a matching `GOPRIVATE` (which disables both the
proxy and the database), a matching `GONOSUMDB`, or `GOSUMDB=off` — and even
then only on a first fetch, since an existing `go.sum` entry pins the hash.
Vendoring is not in that set either: a vendored build uses the checked-in
`vendor/` tree without fetching, and `go mod vendor` downloads through
`GOPROXY` like any other module command.

That residue is small, and it is still the reason the `refs/tags/go/v*`
immutability ruleset exists — a tag nobody can move is a stronger guarantee
than one whose consequences depend on each consumer's configuration. A bad
release ships as a new patch version, exactly as it does for the gem.

## Recovery

The registry reconciliation makes re-running a tag's workflow **idempotent**:
it never re-pushes bytes that are already published, and it fails closed on
any conflict.

The discriminator is the **remote** tag — not whether anything was published —
and then whether a corrective commit is needed. `rake tag` creates the local tag
before it pushes, and pushes `main` and the tag as two separate operations, so a
failed `rake tag` can leave a local tag with no remote counterpart. Establish
which state you are in before acting:

**Do not use `git ls-remote` to establish this.** A URL spelled out in full on
the command line is still rewritten by `url.<base>.insteadOf`, so the query can
silently inspect a different repository and report the canonical tag absent —
and a rewriting `insteadOf` rule has already been configured on this maintainer's
machine once. Ask GitHub directly, over a path that touches no Git
configuration:

```sh
gh api repos/basecamp/surfguard/git/matching-refs/tags/vX.Y.Z \
  --jq '[.[]|select(.ref=="refs/tags/vX.Y.Z")]|length'
```

**The exact-ref filter is required, not tidiness.** `matching-refs` matches by
**prefix**: querying `tags/v0.1` returns `v0.1.0`, `v0.1.1`, `v0.1.2` and
`v0.1.3`. So if `vX.Y.Z` is absent while some `vX.Y.Z…` tag exists — a
`-rc1`, or `v1.2.30` against a query for `v1.2.3` — the raw array is populated
even though your tag is not there, and an unfiltered length test misroutes an
absent tag into the present-tag rows. Filter to the exact ref, then test.

Read the filtered result as: `0` means the tag is **definitively absent**; `1`
means present. Any non-200 — auth failure, a secondary rate limit, a network
error — means **unknown, not absent**. Never route on a failed query.

When it is present, it is not automatically *your* tag; a concurrent attempt
could have won the name. Compare it against the tag you still hold:

```sh
gh api repos/basecamp/surfguard/git/matching-refs/tags/vX.Y.Z \
  --jq '.[]|select(.ref=="refs/tags/vX.Y.Z")|.object.sha'   # remote tag object
git rev-parse vX.Y.Z                                        # local tag object
git rev-parse 'vX.Y.Z^{commit}'                             # local peeled commit
```

| State | Recovery |
|---|---|
| Remote tag **absent**, remote `main` still equals your tagged `HEAD`, no corrective commit needed (transient push failure) | Re-run `rake tag`. The local tag still peels to `HEAD` and `HEAD` still equals fetched `main`, so `rake tag` accepts it as the exact retryable annotated tag and re-pushes. No deletion, no ruleset change. |
| Remote tag **absent**, but remote `main` has **advanced** (an unrelated PR landed) | Re-running `rake tag` will *not* work: it fetches `main` and aborts because your tagged `HEAD` no longer equals it, and you cannot fast-forward while keeping the tag because the peel check then rejects the pair. Prove the remote tag absent (the filtered query above returns `0`), delete the **local** ref only (`git tag -d vX.Y.Z`), fast-forward, **re-rehearse on the new head**, and tag that. The rehearsed commit must be the commit you tag. |
| Remote tag **absent**, a corrective commit **is** needed | Same shape: the fix moves `HEAD`, so the stale local tag no longer peels to it and `rake tag` aborts by design. Prove the remote tag absent, then delete the **local** ref only: `git tag -d vX.Y.Z`. This touches no remote ref and no ruleset — it is **not** the immutability case. Commit the fix, **re-rehearse**, and re-run `rake tag`. |
| Remote tag **present and identical** to your local tag object, run failed at any stage | `gh run rerun <RUN_ID>`. Reconciliation is idempotent: same-SHA skips the push, downstream completes. **Never re-push, move, or delete the tag.** A defect that survives the re-run ships as the next patch version. |
| Remote tag **present but different** from your local tag object (or you no longer hold one) | **Stop.** Another attempt won this tag name. Mere presence is not proof the remote tag is the one whose bytes you rehearsed, and the workflow only checks that its tag is well formed and points into `main` — not that it matches your checkout. Do not approve that run's environments; reconcile who tagged what first. |
| **Ambiguous** (push errored or timed out) | Resolve the state before acting: run the `matching-refs` query above and the object comparison, then route to a row above. Never treat a 404 or a failed query as licence to delete. If registry state is also unknown, **download the canonical RubyGems bytes and compare digests**; indeterminate or conflicting → **stop; contact RubyGems support**. |
| Workflow defect embedded in a published tag | Re-runs use the tagged workflow; fixing `main` doesn't fix the tag. Never move/delete the tag. Run `release-recovery.yml` (dispatch with the version) to finish attestation + the GitHub Release from verified canonical registry bytes; ship the workflow fix in the next version. |
| Bad published release | Never re-point or delete the tag. Ship a new patch version (per SECURITY.md, fixes ship as new releases). Yank only for security-critical cases. |
| Anything that appears to require lifting `release-tags-immutable` | **Stop.** Obtain a separately reviewed break-glass runbook. Do not improvise a ruleset change on a public security gem under pressure. No row above needs one: the only deletion any of them permits is of a **local** ref. |

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
    trusted-publisher readback with the release evidence. For 0.2.0 both
    readbacks were captured on 2026-08-31 before tagging; see the release
    record below.

## 0.2.0 control readback (2026-08-17)

Before either workflow referenced it, `github-release` was created and read
back with sole reviewer `jeremy` (numeric id 199), self-review allowed,
`can_admins_bypass: false`, and deployment policies `v*` (tag) plus `main`
(branch). The unused `copilot` environment was verified to have no protection
rules and deleted; readback lists only `github-release`, `release-recovery`,
and `release-rubygems`.

> **Correction (2026-08-22).** The `copilot` environment is **not deletable in
> any lasting sense**, so the sentence above records an end state that does not
> hold. It was present again on 2026-08-22 at `created_at`
> `2026-08-17T21:56:44Z` — one second after pull request #11 was opened
> (`21:56:43Z`), in the burst that opened #9–#13. Deleting it on 2026-08-22
> reproduced the mechanism exactly: it reappeared with a **new** id and a new
> `created_at` ten seconds after the next pull request was opened. The cause is
> the active `Copilot Reviews` ruleset (`copilot_code_review`, scoped `~ALL`),
> which makes GitHub create the environment on demand for each pull request.
>
> So the readback was almost certainly accurate the moment it was taken, and an
> unrelated pull request recreated the environment seconds later. The defect is
> not a false record — it is that a **transient** deletion was written down as a
> settled control, and that "the readback lists only three environments" is an
> assertion which cannot stay true in a repository that receives pull requests.
>
> This costs nothing in release authority. Across both incarnations the
> environment had no protection rules, no deployment branch policy, no secrets,
> no variables, no deployments, and no reference from any workflow; `release.yml`
> and `release-recovery.yml` name only `release-rubygems`, `github-release` and
> `release-recovery`. It can neither gate nor bypass any release job.
>
> The pre-tag gate therefore asserts **protection values, not an environment
> count**: the three release environments must each carry the required-reviewer
> and `can_admins_bypass` settings recorded above, and any environment outside
> that set must be inert — no protection rules, no branch policy, no secrets, no
> variables, no deployments. That assertion survives Copilot recreating
> `copilot`; an equality check on the environment list would fail the release
> spuriously after any pull request.
>
> Recorded as a correction rather than by amending the original paragraph, so
> that the reason this readback could not be reproduced stays visible.

Repository Actions were changed from unrestricted to selected repositories
and read back with full-SHA pinning required, GitHub-owned/verified blanket
allowances disabled, and only repositories referenced by checked-in workflows
allowed. RubyGems owner/MFA and trusted-publisher evidence is still a mandatory
manual pre-tag gate. No tag or publication was performed.

## 0.2.0 release record (2026-08-31)

Tagged and published from commit `59e278c01a537755f22791429051891949231ead`
(`main` after #23 and Dependabot #26). One digest end to end:

```
b7460e177be9ee452dc610fe244113cd38a2f5e6d6717bc26dcf9fefb320da30
```

- **Rehearsal** — `workflow_dispatch` run `32751899739` (2026-08-24) on the
  same commit produced the `rubygem` artifact with this digest. The tag run's
  `rubygem` artifact, read back before the first approval, and its
  `canonical-gem` artifact, read back before the second, both matched it.
- **Pre-tag gate** — the value-based control snapshot returned GO on all
  controls at `2026-08-31T08:38:53Z`; the tag was pushed at `08:39:15Z` with
  `main` unmoved.
- **RubyGems readback** (signed-in session, human-only): gem owned by the
  `basecamp` organization with "New versions require MFA"; exactly one trusted
  publisher — GitHub Actions, `basecamp/surfguard`, `release.yml`,
  environment `release-rubygems` — durable, not pending.
- **Tag run** `33373923125` (`push`, attempt 1): both environment gates were
  approved by hand. For each, the pending deployment was read back as the
  expected environment id (`19725840442`, then `20023779259`) with every
  upstream job green and the run's artifact digest equal to the rehearsed one.
- **Post-publish verification** — five authorities agree on the digest:
  RubyGems archive bytes, RubyGems v2 `.sha`, the GitHub Release asset
  (release `379622054`, published `08:58:22Z`), the sole attestation subject
  (`gh attestation verify` with `--signer-workflow` `release.yml` and
  `--source-ref refs/tags/v0.2.0`; certificate records
  `sourceRepositoryDigest` `59e278c0…` and `buildTrigger` `push`), and the
  compact-index `checksum:`. The negative control was observed to fail for the
  intended reason: a wrong `--source-ref` exits 1 with `expected
  SourceRepositoryRef to be <bogus>, got refs/tags/v0.2.0`.

Evidence, including the snapshot and verification scripts, is retained
outside the repository with the release evidence.

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
