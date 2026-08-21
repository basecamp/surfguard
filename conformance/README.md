# Conformance corpus

Language-neutral classification matrices shared by every surfguard
implementation (Ruby at the repo root, Go under `go/`). One policy, N
implementations, byte-identical expectations: the tests in each language load
these files and assert the same verdicts, so the implementations cannot drift
apart silently.

The IANA registry snapshots these policies are generated from live in
`script/iana/*.json`; this directory holds only expectations, never policy
source data.

## Files

| File | Contents |
|------|----------|
| `blocked.json` | Addresses refused under both policies |
| `allowed.json` | Addresses admitted under the default policy (per-policy verdicts) |
| `boundaries.json` | Range-edge and policy-divergence cases (per-policy verdicts) |
| `legacy_numeric.json` | Legacy `inet_aton` host spellings: classified authoritatively, never sent to DNS |
| `malformed_numeric_hosts.json` | Malformed IPv4-shaped tokens: refused before any parser or DNS |
| `non_host_prefixes.json` | Network prefixes: refused, never normalized to a host address |
| `dns_hostnames.json` | Hostnames that legitimately reach DNS despite numeric-looking labels |

## Schema

Every file is an object with `schema_version`, `description`, and `cases`.

Classification cases (`blocked.json`, `allowed.json`, `boundaries.json`):

```json
{ "label": "…", "input": "<address literal>",
  "policies": { "default": "blocked|allowed", "iana_special_use": "blocked|allowed" },
  "note": "optional rationale / RFC reference" }
```

Host-input cases (the other files) carry `input` plus file-specific fields:
`legacy_numeric.json` adds `canonical` (the address the spelling denotes) and
`blocked` (default-policy verdict for that address); the rest are bare inputs
whose expectation is the file's contract stated in its `description`.

## Change protocol

Policy changes land here and in every implementation in the same commit. A new
deny is a minor version bump with a prominent changelog entry in each release.
The implementations version independently, so "each release" means each one's
own record: `../go/CHANGELOG.md` for the Go module, `../RELEASE_NOTES_X.Y.Z.md`
for the gem. An entry names the range and the corpus case added here, because
that is what tells a consumer which host stopped resolving on upgrade.
