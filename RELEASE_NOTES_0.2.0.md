# Surfguard 0.2.0

Surfguard 0.2.0 closes the reserved/unallocated IPv6 default-allow gap. The default policy now admits only reviewed IANA `Status=ALLOCATED` IPv6 unicast prefixes plus the documented transition and globally reachable service exceptions. The previously reported three-prefix v0.1.3 regression was stale; its boundaries are nevertheless locked down across every public API.

The five public APIs now accept `policy:`. The default remains reachability-oriented; the new trusted-caller `:iana_special_use` policy blocks every checked-in RFC 6890/IANA special-purpose prefix, including AMT, AS112, and the complete NAT64 well-known prefix. Unknown policies raise `ArgumentError`.

Input and resolver handling is now owned, bounded, and fail-closed: malformed encodings, zones, networks, unstable coercion, malformed mixed answers, and more than 256 answers are rejected. Results and policy data are deeply frozen, resolver order is preserved by the single-address API, and public error messages are fixed strings without attacker-controlled content.

Caller guidance now includes a tested, proxy-disabled Net::HTTP recipe that preserves Host/SNI/certificate identity, pins the validated address, bounds response bytes, retries without resolving again, and revalidates every redirect. Surfguard remains an address policy rather than an HTTP client; callers still own schemes, userinfo, redirects, request deadlines, response handling, and egress controls.

This release requires Ruby 3.4.5 or newer and keeps zero runtime dependencies. CI covers Ruby 3.4.5, current 3.4, 4.0, head, macOS, Windows, and pinned musl, and rejects vulnerable effective `resolv` versions. Explicitly downgrading `resolv` beneath the supported patched ranges is unsupported.

Release assurance now includes exact raw gem-archive validation, immutable-source byte and mode comparison, isolated installed-byte tests, independent reproducible builds, bounded and pinned RubyGems access, canonical registry-byte confirmation, split attestation/release authority, stricter Dependabot lockfile validation, and hardened release helpers. The accepted High SG-02 residual remains: one authorized principal can initiate and self-approve a release until a second principal is available.
