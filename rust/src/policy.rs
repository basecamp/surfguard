use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::iana::{IANA_ALLOCATED_IPV6_UNICAST, IANA_SPECIAL_USE_IPV4, IANA_SPECIAL_USE_IPV6};
use crate::prefix::{
    Ipv4Prefix, Ipv6Prefix, any_contains4, any_contains6, ipv4_table, ipv6, ipv6_table,
};

/// Which addresses are refused. Trusted consumer code chooses it; a target
/// must never choose its own policy.
///
/// The gem's `policy:` symbols, as an enum: an unknown policy, which the gem
/// refuses with `ArgumentError` at run time, does not compile here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Policy {
    /// `:default`, reachability-oriented. IPv4 keeps the documented SSRF deny
    /// ranges. IPv6 is admitted only inside a checked-in IANA
    /// `Status=ALLOCATED` unicast prefix, less the explicit special and
    /// transition denies. Public NAT64/SIIT translations and globally
    /// reachable AMT/AS112 services stay admitted.
    #[default]
    Default,
    /// `:iana_special_use`: [`Policy::Default`], and every prefix in the
    /// checked-in IANA IPv4 and IPv6 special-purpose registries besides,
    /// including AMT, AS112 and the whole NAT64 well-known prefix. For
    /// advertised or discovered infrastructure values.
    IanaSpecialUse,
}

/// Judges one address. [`Policy`] is the classifier every consumer starts
/// from; a closure can wrap one with an exception of the consumer's own, such
/// as a loopback fixture that trusted configuration turns on.
pub trait Classifier {
    /// Whether `address` must be refused.
    fn blocks(&self, address: IpAddr) -> bool;
}

impl Classifier for Policy {
    fn blocks(&self, address: IpAddr) -> bool {
        Policy::blocks(*self, address)
    }
}

impl<F: Fn(IpAddr) -> bool> Classifier for F {
    fn blocks(&self, address: IpAddr) -> bool {
        self(address)
    }
}

impl Policy {
    /// `blocked_address?` for an address: whether the policy refuses it.
    #[must_use]
    pub fn blocks(self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.blocks_ipv4(address),
            IpAddr::V6(address) => self.blocks_ipv6(address),
        }
    }

    fn blocks_ipv4(self, address: Ipv4Addr) -> bool {
        (self == Policy::IanaSpecialUse && any_contains4(&IANA_SPECIAL_USE_IPV4, address))
            || any_contains4(&DISALLOWED_IPV4, address)
    }

    /// The gem's pipeline, in its order: the strict tables first, so the
    /// whole NAT64 well-known registration wins before its decode; then the
    /// structural transition forms; then the embedded IPv4 re-check; then the
    /// deny tables and the allocated-unicast allowlist.
    fn blocks_ipv6(self, address: Ipv6Addr) -> bool {
        if (self == Policy::IanaSpecialUse && any_contains6(&IANA_SPECIAL_USE_IPV6, address))
            || IPV4_MAPPED.contains(address)
            || IPV4_COMPATIBLE.contains(address)
            || NAT64_LOCAL_USE.contains(address)
        {
            true
        } else if NAT64_WELL_KNOWN.contains(address) || IPV4_TRANSLATABLE.contains(address) {
            self.blocks_ipv4(embedded_ipv4(address))
        } else {
            disallowed_ipv6(address)
        }
    }
}

fn disallowed_ipv6(address: Ipv6Addr) -> bool {
    if any_contains6(&GLOBALLY_REACHABLE_IETF_ASSIGNMENTS, address) {
        false
    } else if any_contains6(&PRIVATE_LOOPBACK_LINK_LOCAL_IPV6, address)
        || IETF_PROTOCOL_ASSIGNMENTS.contains(address)
        || any_contains6(&DISALLOWED_IPV6, address)
    {
        true
    } else {
        !any_contains6(&IANA_ALLOCATED_IPV6_UNICAST, address)
    }
}

fn embedded_ipv4(address: Ipv6Addr) -> Ipv4Addr {
    let [.., a, b, c, d] = address.octets();
    Ipv4Addr::new(a, b, c, d)
}

/// `DISALLOWED_IPV4`. It holds every range `IPAddr#private?`, `#loopback?`
/// and `#link_local?` add to it in the gem.
pub(crate) static DISALLOWED_IPV4: [Ipv4Prefix; 16] = ipv4_table([
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "168.63.129.16/32",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
]);

/// `DISALLOWED_IPV6`.
pub(crate) static DISALLOWED_IPV6: [Ipv6Prefix; 11] = ipv6_table([
    "::/128",
    "100::/64",
    "100:0:0:1::/64",
    "2001::/32",
    "2001:2::/48",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fec0::/10",
    "ff00::/8",
]);

/// What `IPAddr#private?`, `#loopback?` and `#link_local?` refuse of IPv6 in
/// the gem: unique local, loopback and link-local space.
static PRIVATE_LOOPBACK_LINK_LOCAL_IPV6: [Ipv6Prefix; 3] =
    ipv6_table(["fc00::/7", "::1/128", "fe80::/10"]);

/// IETF special-purpose parent space: refused, with narrow carve-outs below
/// for the two globally reachable services.
const IETF_PROTOCOL_ASSIGNMENTS: Ipv6Prefix = ipv6("2001::/23");

/// AMT and AS112-v6: globally reachable service infrastructure inside the
/// IETF parent.
static GLOBALLY_REACHABLE_IETF_ASSIGNMENTS: [Ipv6Prefix; 2] =
    ipv6_table(["2001:3::/32", "2001:4:112::/48"]);

/// The NAT64 well-known prefix: the low 32 bits are a real IPv4 target,
/// decoded and re-checked.
const NAT64_WELL_KNOWN: Ipv6Prefix = ipv6("64:ff9b::/96");

/// The NAT64 local-use prefix embeds at an offset only the deployment knows
/// (RFC 6052), so it is refused whole.
const NAT64_LOCAL_USE: Ipv6Prefix = ipv6("64:ff9b:1::/48");

/// SIIT's IPv4-translatable addresses: decoded and re-checked like the NAT64
/// well-known prefix.
const IPV4_TRANSLATABLE: Ipv6Prefix = ipv6("::ffff:0:0:0/96");

/// IPv4-mapped addresses, `IPAddr#ipv4_mapped?`: a hostile AAAA record or a
/// caller's mistake, never a public target.
const IPV4_MAPPED: Ipv6Prefix = ipv6("::ffff:0:0/96");

/// IPv4-compatible addresses, `::` and `::1` among them.
const IPV4_COMPATIBLE: Ipv6Prefix = ipv6("::/96");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_nat64_prefixes_do_not_overlap() {
        assert!(!NAT64_WELL_KNOWN.contains("64:ff9b:1::".parse().unwrap()));
        assert!(!NAT64_LOCAL_USE.contains("64:ff9b::ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn the_siit_and_mapped_prefixes_do_not_overlap() {
        assert!(!IPV4_TRANSLATABLE.contains("::ffff:7f00:1".parse().unwrap()));
        assert!(!IPV4_MAPPED.contains("::ffff:0:7f00:1".parse().unwrap()));
    }

    /// Transcription is only trustworthy under count and membership: the
    /// gem's `DISALLOWED_IPV4` and `DISALLOWED_IPV6`, range for range.
    #[test]
    fn the_hand_tables_are_the_gems() {
        let ipv4: Vec<String> = DISALLOWED_IPV4
            .iter()
            .map(|prefix| cidr(prefix.parts()))
            .collect();
        assert_eq!(
            [
                "0.0.0.0/8",
                "10.0.0.0/8",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "168.63.129.16/32",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.0.0.0/24",
                "192.0.2.0/24",
                "192.88.99.0/24",
                "192.168.0.0/16",
                "198.18.0.0/15",
                "198.51.100.0/24",
                "203.0.113.0/24",
                "224.0.0.0/4",
                "240.0.0.0/4",
            ]
            .as_slice(),
            ipv4
        );
        let ipv6: Vec<String> = DISALLOWED_IPV6
            .iter()
            .map(|prefix| cidr(prefix.parts()))
            .collect();
        assert_eq!(
            [
                "::/128",
                "100::/64",
                "100:0:0:1::/64",
                "2001::/32",
                "2001:2::/48",
                "2001:db8::/32",
                "2002::/16",
                "3fff::/20",
                "5f00::/16",
                "fec0::/10",
                "ff00::/8",
            ]
            .as_slice(),
            ipv6
        );
    }

    fn cidr<A: std::fmt::Display>((address, length): (A, u32)) -> String {
        format!("{address}/{length}")
    }
}
