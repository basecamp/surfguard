//! Surfguard resolves and classifies addresses for programs that fetch a URL
//! supplied by someone else. It is deliberately not an HTTP client: the
//! caller owns scheme restrictions, redirects, connection pinning, response
//! limits, retries and request deadlines.
//!
//! This is the Rust implementation of the gem at the root of the
//! [surfguard repository](https://github.com/basecamp/surfguard), with the
//! same guarantees: its policy tables are generated from the same checked-in
//! IANA snapshots, and its tests assert the same verdicts against the shared
//! conformance corpus.
//!
//! ```
//! use std::net::IpAddr;
//! use surfguard::{Policy, SystemResolver};
//!
//! assert!(Policy::Default.blocks("169.254.169.254".parse().unwrap()));
//! assert!(surfguard::blocked_address("10.0.0.1", Policy::Default));
//!
//! // Address literals, legacy spellings included, are never sent to DNS.
//! let admitted = surfguard::resolve_public_ips("2130706433", &Policy::Default, &SystemResolver);
//! assert_eq!(Ok(Vec::<IpAddr>::new()), admitted);
//! ```
//!
//! | Condition | [`resolve_public_ips`] | [`resolvable_public_ip`] | [`enforce_public_ip`] | [`resolve_public_ip`] | [`blocked_address`] |
//! |---|---|---|---|---|---|
//! | malformed direct input | `Ok([])` | `false` | [`Violation::Malformed`] | `Ok(None)` | `true` |
//! | empty, failed or oversized resolver result | [`Unresolvable`] | `false` | [`Unresolvable`] | [`Unresolvable`] | n/a |
//! | mixed public and blocked answers | the public subset | `false` | [`Violation::Blocked`] | `Ok(None)` | n/a |
//!
//! The plural result is IPv4-first while keeping the resolver's order within
//! each family; the single result keeps the resolver's order exactly.
//! Answers are deduplicated in order, and more than [`MAX_ADDRESSES`]
//! answers invalidate the lookup.
//!
//! Only a returned address can be pinned. The predicate and enforcement
//! helpers are conservative preflights that bind no later connection:
//! resolving the name again afterwards reopens DNS rebinding.

#![forbid(unsafe_code)]

mod error;
mod host;
mod iana;
mod ipaddr;
mod policy;
mod prefix;
mod resolver;
mod uri;

use std::net::IpAddr;

pub use error::{
    BLOCKED_MESSAGE, Error, MALFORMED_MESSAGE, UNRESOLVABLE_MESSAGE, Unresolvable, Violation,
};
pub use host::MAX_HOST_BYTES;
pub use policy::{Classifier, Policy};
pub use resolver::{Resolver, SystemResolver};

/// `MAX_ADDRESSES`: the most answers a lookup may hold.
pub const MAX_ADDRESSES: usize = 256;

/// `resolve_public_ips`: every address `host` resolves to that `policy`
/// admits, IPv4 before IPv6 and in the resolver's order within each family.
///
/// `host` is a name or an address literal (in brackets or not, or a
/// one-address prefix such as `93.184.216.34/32`); a literal, including a
/// legacy `inet_aton` spelling, is judged without DNS. A malformed host
/// admits nothing. Every answer blocked yields an empty list.
///
/// # Errors
///
/// [`Unresolvable`] when the resolver fails, answers nothing, or answers
/// more than [`MAX_ADDRESSES`].
pub fn resolve_public_ips(
    host: &str,
    policy: &impl Classifier,
    resolver: &impl Resolver,
) -> Result<Vec<IpAddr>, Unresolvable> {
    let Ok(host) = host::host(host) else {
        return Ok(Vec::new());
    };
    let (ipv4, ipv6): (Vec<IpAddr>, Vec<IpAddr>) = answers(host, resolver)?
        .into_iter()
        .filter(|address| !policy.blocks(*address))
        .partition(IpAddr::is_ipv4);
    Ok(ipv4.into_iter().chain(ipv6).collect())
}

/// `resolvable_public_ip?`: whether `url`'s host resolves and `policy`
/// admits every address it resolves to.
pub fn resolvable_public_ip(url: &str, policy: &impl Classifier, resolver: &impl Resolver) -> bool {
    url_answers(url, resolver)
        .is_ok_and(|answers| !answers.iter().any(|address| policy.blocks(*address)))
}

/// `enforce_public_ip`: refuses `url` unless its host resolves and `policy`
/// admits every address it resolves to.
///
/// # Errors
///
/// [`Violation::Malformed`] for a malformed URL or host,
/// [`Violation::Blocked`] when any address is blocked, and [`Unresolvable`]
/// as [`resolve_public_ips`] has it.
pub fn enforce_public_ip(
    url: &str,
    policy: &impl Classifier,
    resolver: &impl Resolver,
) -> Result<(), Error> {
    if url_answers(url, resolver)?
        .iter()
        .any(|address| policy.blocks(*address))
    {
        Err(Violation::Blocked.into())
    } else {
        Ok(())
    }
}

/// `resolve_public_ip`: the first address `url`'s host resolves to, in the
/// resolver's order, when `policy` admits every address it resolves to.
/// `None` for a malformed URL or host, or when any address is blocked.
///
/// # Errors
///
/// [`Unresolvable`] as [`resolve_public_ips`] has it.
pub fn resolve_public_ip(
    url: &str,
    policy: &impl Classifier,
    resolver: &impl Resolver,
) -> Result<Option<IpAddr>, Unresolvable> {
    match url_answers(url, resolver) {
        Ok(answers) if answers.iter().any(|address| policy.blocks(*address)) => Ok(None),
        Ok(answers) => Ok(answers.first().copied()),
        Err(Error::Violation(_)) => Ok(None),
        Err(Error::Unresolvable(unresolvable)) => Err(unresolvable),
    }
}

/// `blocked_address?` for a string, as Ruby's `IPAddr` reads it: an address,
/// an IPv6 address in brackets, or a one-address prefix. Anything else,
/// networks, zones and legacy numeric spellings included, is blocked. For an
/// address already parsed, use [`Policy::blocks`].
#[must_use]
pub fn blocked_address(address: &str, policy: Policy) -> bool {
    !address.is_ascii()
        || address.contains('\0')
        || ipaddr::host_address(address).is_none_or(|address| policy.blocks(address))
}

fn url_answers(url: &str, resolver: &impl Resolver) -> Result<Vec<IpAddr>, Error> {
    let host = uri::host(url).map_err(|uri::Malformed| Violation::Malformed)?;
    let host = host::host(host).map_err(|host::Malformed| Violation::Malformed)?;
    Ok(answers(host, resolver)?)
}

/// `resolve` and `normalize_answers`: the literal, or the resolver's answer
/// bounded and deduplicated in order.
fn answers(host: host::Host<'_>, resolver: &impl Resolver) -> Result<Vec<IpAddr>, Unresolvable> {
    let raw = match host {
        host::Host::Literal(address) => vec![address],
        host::Host::Name(name) => resolver.lookup(name).map_err(|_| Unresolvable)?,
    };
    if raw.len() > MAX_ADDRESSES {
        return Err(Unresolvable);
    }
    let mut answers: Vec<IpAddr> = Vec::with_capacity(raw.len());
    for address in raw {
        if !answers.contains(&address) {
            answers.push(address);
        }
    }
    if answers.is_empty() {
        Err(Unresolvable)
    } else {
        Ok(answers)
    }
}

#[cfg(test)]
mod tests;
