//! Ruby's `IPAddr.new` for a string, the parser the gem classifies strings
//! with: an address, an address with a prefix length or a mask, or an IPv6
//! address in brackets. Only what it reads as one host address is an address
//! here; a zone, a network, and anything it refuses are not.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_BITS: u128 = u32::MAX as u128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    fn full(self) -> u128 {
        match self {
            Family::Ipv4 => IPV4_BITS,
            Family::Ipv6 => u128::MAX,
        }
    }

    fn bits(self) -> u32 {
        match self {
            Family::Ipv4 => 32,
            Family::Ipv6 => 128,
        }
    }
}

struct Parsed {
    family: Family,
    address: u128,
    mask: u128,
}

/// The address `IPAddr.new(text)` reads, when it reads one host address
/// with no zone.
pub(crate) fn host_address(text: &str) -> Option<IpAddr> {
    let parsed = parse(text)?;
    (parsed.mask == parsed.family.full()).then(|| match parsed.family {
        Family::Ipv4 => IpAddr::V4(Ipv4Addr::from_bits(
            u32::try_from(parsed.address).expect("an IPv4 address fits 32 bits"),
        )),
        Family::Ipv6 => IpAddr::V6(Ipv6Addr::from_bits(parsed.address)),
    })
}

/// A zone (`%eth0`) makes the gem refuse the address, and any other `%`
/// makes `IPAddr` refuse it, so a `%` anywhere is never an address.
fn parse(text: &str) -> Option<Parsed> {
    if text.contains('%') {
        return None;
    }
    let (prefix, length) = match text.split_once('/') {
        Some((prefix, length)) => (prefix, Some(length)),
        None => (text, None),
    };
    let bracketed = prefix
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .filter(|inner| !inner.contains('\n'));
    let (family, address) = match bracketed {
        Some(inner) => (Family::Ipv6, in6_addr(inner)?),
        None => in_addr(prefix)
            .map(|address| (Family::Ipv4, address))
            .or_else(|| Some((Family::Ipv6, in6_addr(prefix)?)))?,
    };
    match length {
        None => Some(Parsed {
            family,
            address,
            mask: family.full(),
        }),
        Some(length) => masked(family, address, length),
    }
}

/// `IPAddr#mask!` with a string: a prefix length without leading zeros, or a
/// contiguous mask written as an address of the same family.
fn masked(family: Family, address: u128, length: &str) -> Option<Parsed> {
    let mask = if !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit()) {
        if length.len() > 1 && length.starts_with('0') {
            return None;
        }
        let length: u32 = length
            .parse()
            .ok()
            .filter(|length| *length <= family.bits())?;
        prefix_mask(family, length)
    } else {
        let mask = parse(length).filter(|mask| mask.family == family)?;
        let inverse = mask.address ^ mask.mask;
        if inverse.wrapping_add(1) & inverse != 0 {
            return None;
        }
        mask.address
    };
    Some(Parsed {
        family,
        address: address & mask,
        mask,
    })
}

fn prefix_mask(family: Family, length: u32) -> u128 {
    let host_bits = family.bits() - length;
    if host_bits == 128 {
        0
    } else {
        (family.full() >> host_bits) << host_bits
    }
}

/// `IPAddr#in_addr`: four decimal octets. Where `IPAddr` raises for a text
/// so shaped and goes on to IPv6 for any other, both are refused here: text
/// with no colon is never an IPv6 address.
fn in_addr(text: &str) -> Option<u128> {
    octets_value(&dotted_quad(text)?)
}

/// `IPAddr#in_addr` over octets the caller has already shaped: each below
/// 256 and written without a leading zero.
fn octets_value(octets: &[&str]) -> Option<u128> {
    octets.iter().try_fold(0u128, |value, octet| {
        if octet.len() > 1 && octet.starts_with('0') {
            return None;
        }
        let octet: u128 = octet.parse().ok().filter(|octet| *octet < 256)?;
        Some(value << 8 | octet)
    })
}

/// `IPAddr#in6_addr`, its `RE_IPV6ADDRLIKE_FULL` and
/// `RE_IPV6ADDRLIKE_COMPRESSED` and the colon counts it holds each to. The
/// counts refuse some addresses RFC 4291 allows, such as
/// `::1:2:3:4:5:1.2.3.4`, and so does this.
fn in6_addr(text: &str) -> Option<u128> {
    match text.split_once("::") {
        None => full(text),
        Some((left, right)) => compressed(text, left, right),
    }
}

fn full(text: &str) -> Option<u128> {
    let groups: Vec<&str> = text.split(':').collect();
    match groups.as_slice() {
        groups if groups.len() == 8 && groups.iter().all(|group| hex_group(group)) => {
            Some(groups_value(groups))
        }
        [groups @ .., ipv4] if groups.len() == 6 && groups.iter().all(|group| hex_group(group)) => {
            let embedded = dotted_quad(ipv4)?;
            Some(groups_value(groups) << 32 | octets_value(&embedded)?)
        }
        _ => None,
    }
}

fn compressed(text: &str, left: &str, right: &str) -> Option<u128> {
    let left: Vec<&str> = if left.is_empty() {
        Vec::new()
    } else {
        left.split(':').collect()
    };
    let right: Vec<&str> = if right.is_empty() {
        Vec::new()
    } else {
        right.split(':').collect()
    };
    if !left.iter().all(|group| hex_group(group)) {
        return None;
    }
    let colons = text.bytes().filter(|byte| *byte == b':').count();
    let (right, embedded) = match right.split_last() {
        Some((last, groups)) if !hex_group(last) => {
            let embedded = dotted_quad(last)?;
            if colons > 6 {
                return None;
            }
            (groups, Some(octets_value(&embedded)?))
        }
        _ => {
            let most = if left.is_empty() || right.is_empty() {
                8
            } else {
                7
            };
            if colons > most {
                return None;
            }
            (right.as_slice(), None)
        }
    };
    if !right.iter().all(|group| hex_group(group)) {
        return None;
    }
    let right_groups = right.len() + if embedded.is_some() { 2 } else { 0 };
    let zeros = 8usize.checked_sub(left.len() + right_groups)?;
    let mut groups: Vec<&str> = left;
    groups.extend(std::iter::repeat_n("0", zeros));
    groups.extend(right);
    match embedded {
        Some(ipv4) => {
            groups.extend(["0", "0"]);
            Some(groups_value(&groups) | ipv4)
        }
        None => Some(groups_value(&groups)),
    }
}

fn dotted_quad(text: &str) -> Option<Vec<&str>> {
    let octets: Vec<&str> = text.split('.').collect();
    (octets.len() == 4 && octets.iter().all(|octet| decimal_digits(octet))).then_some(octets)
}

fn groups_value(groups: &[&str]) -> u128 {
    groups.iter().fold(0, |value, group| {
        value << 16 | u128::from_str_radix(group, 16).expect("a hex group")
    })
}

fn hex_group(group: &str) -> bool {
    (1..=4).contains(&group.len()) && group.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decimal_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(text: &str) -> Option<String> {
        host_address(text).map(|address| address.to_string())
    }

    #[test]
    fn addresses_read_as_ipaddr_reads_them() {
        for (text, read) in [
            ("93.184.216.34", Some("93.184.216.34")),
            ("0.0.0.0", Some("0.0.0.0")),
            ("01.2.3.4", None),
            ("256.1.1.1", None),
            ("1.2.3", None),
            ("2130706433", None),
            ("::", Some("::")),
            ("::1", Some("::1")),
            ("[::1]", Some("::1")),
            ("[1.2.3.4]", None),
            ("::ffff:1.2.3.4", Some("::ffff:1.2.3.4")),
            ("::FFFF:a9fe:A9FE", Some("::ffff:169.254.169.254")),
            ("1:2:3:4:5:6:1.2.3.4", Some("1:2:3:4:5:6:102:304")),
            ("1:2:3:4:5::1.2.3.4", Some("1:2:3:4:5:0:102:304")),
            ("::2:3:4:5:6:1.2.3.4", None),
            ("1:2:3:4:5:6:7::", Some("1:2:3:4:5:6:7:0")),
            ("::2:3:4:5:6:7:8", Some("0:2:3:4:5:6:7:8")),
            ("1:2:3:4::5:6:7:8", None),
            ("1:2:3:4:5:6:7:8:9", None),
            ("1::2::3", None),
            (":::1", None),
            ("12345::", None),
            ("fe80::1%eth0", None),
            ("93.184.216.34/32", Some("93.184.216.34")),
            ("93.184.216.34/032", None),
            ("93.184.216.34/31", None),
            ("93.184.216.34/33", None),
            ("93.184.216.34/255.255.255.255", Some("93.184.216.34")),
            ("93.184.216.34/255.255.255.254", None),
            ("93.184.216.34/255.255.255.255/32", Some("93.184.216.34")),
            ("93.184.216.34/::ffff:ffff", None),
            ("::1/128", Some("::1")),
            ("[::1]/128", Some("::1")),
            ("::1/127", None),
            ("", None),
            ("/32", None),
            ("1.2.3.4/", None),
        ] {
            assert_eq!(read.map(str::to_owned), address(text), "{text:?}");
        }
    }
}
