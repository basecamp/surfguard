//! Address prefixes, parsed from their CIDR spelling at compile time so a
//! mistyped table entry is a build error rather than a silently wrong range.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4Prefix {
    network: u32,
    length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ipv6Prefix {
    network: u128,
    length: u32,
}

impl Ipv4Prefix {
    pub(crate) const fn contains(self, address: Ipv4Addr) -> bool {
        address.to_bits() & mask32(self.length) == self.network
    }

    #[cfg(test)]
    pub(crate) const fn parts(self) -> (Ipv4Addr, u32) {
        (Ipv4Addr::from_bits(self.network), self.length)
    }
}

impl Ipv6Prefix {
    pub(crate) const fn contains(self, address: Ipv6Addr) -> bool {
        address.to_bits() & mask128(self.length) == self.network
    }

    #[cfg(test)]
    pub(crate) const fn parts(self) -> (Ipv6Addr, u32) {
        (Ipv6Addr::from_bits(self.network), self.length)
    }
}

pub(crate) fn any_contains4(prefixes: &[Ipv4Prefix], address: Ipv4Addr) -> bool {
    prefixes.iter().any(|prefix| prefix.contains(address))
}

pub(crate) fn any_contains6(prefixes: &[Ipv6Prefix], address: Ipv6Addr) -> bool {
    prefixes.iter().any(|prefix| prefix.contains(address))
}

const fn mask32(length: u32) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    }
}

const fn mask128(length: u32) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - length)
    }
}

/// Every CIDR in `cidrs`, which must be dotted-quad IPv4 networks with no
/// host bits set.
pub(crate) const fn ipv4_table<const N: usize>(cidrs: [&str; N]) -> [Ipv4Prefix; N] {
    let mut table = [Ipv4Prefix {
        network: 0,
        length: 0,
    }; N];
    let mut index = 0;
    while index < N {
        table[index] = ipv4(cidrs[index]);
        index += 1;
    }
    table
}

/// Every CIDR in `cidrs`, which must be hexadecimal IPv6 networks (no
/// embedded dotted quad) with no host bits set.
pub(crate) const fn ipv6_table<const N: usize>(cidrs: [&str; N]) -> [Ipv6Prefix; N] {
    let mut table = [Ipv6Prefix {
        network: 0,
        length: 0,
    }; N];
    let mut index = 0;
    while index < N {
        table[index] = ipv6(cidrs[index]);
        index += 1;
    }
    table
}

pub(crate) const fn ipv4(cidr: &str) -> Ipv4Prefix {
    let bytes = cidr.as_bytes();
    let slash = slash_in(bytes);
    let length = decimal(bytes, slash + 1, bytes.len());
    assert!(length <= 32, "IPv4 prefix length out of range");

    let mut network = 0u32;
    let mut octets = 0;
    let mut index = 0;
    while index < slash {
        let start = index;
        while index < slash && bytes[index] != b'.' {
            index += 1;
        }
        let octet = decimal(bytes, start, index);
        assert!(octet <= 255, "IPv4 octet out of range");
        network = (network << 8) | octet;
        octets += 1;
        if index < slash {
            index += 1;
            assert!(index < slash, "IPv4 address ends in a dot");
        }
    }
    assert!(octets == 4, "IPv4 address needs four octets");
    assert!(
        network & !mask32(length) == 0,
        "IPv4 prefix has host bits set"
    );
    Ipv4Prefix { network, length }
}

pub(crate) const fn ipv6(cidr: &str) -> Ipv6Prefix {
    let bytes = cidr.as_bytes();
    let slash = slash_in(bytes);
    let length = decimal(bytes, slash + 1, bytes.len());
    assert!(length <= 128, "IPv6 prefix length out of range");

    let mut head = 0u128;
    let mut head_groups = 0;
    let mut tail = 0u128;
    let mut tail_groups = 0;
    let mut compressed = false;
    let mut index = 0;
    if slash >= 2 && bytes[0] == b':' && bytes[1] == b':' {
        compressed = true;
        index = 2;
    }
    while index < slash {
        let start = index;
        let mut group = 0u128;
        while index < slash && bytes[index] != b':' {
            group = (group << 4) | hex_digit(bytes[index]);
            index += 1;
        }
        assert!(
            index > start && index - start <= 4,
            "IPv6 group needs one to four digits"
        );
        if compressed {
            tail = (tail << 16) | group;
            tail_groups += 1;
        } else {
            head = (head << 16) | group;
            head_groups += 1;
        }
        if index < slash {
            index += 1;
            if index < slash && bytes[index] == b':' {
                assert!(!compressed, "IPv6 address compresses twice");
                compressed = true;
                index += 1;
            } else {
                assert!(index < slash, "IPv6 address ends in a single colon");
            }
        }
    }
    let network = if compressed {
        assert!(
            head_groups + tail_groups <= 7,
            "IPv6 address has too many groups"
        );
        let head_shift = 16 * (8 - head_groups);
        let head_bits = if head_groups == 0 {
            0
        } else {
            head << head_shift
        };
        head_bits | tail
    } else {
        assert!(head_groups == 8, "IPv6 address needs eight groups");
        head
    };
    assert!(
        network & !mask128(length) == 0,
        "IPv6 prefix has host bits set"
    );
    Ipv6Prefix { network, length }
}

const fn slash_in(bytes: &[u8]) -> usize {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' {
            return index;
        }
        index += 1;
    }
    panic!("prefix needs a /length");
}

const fn decimal(bytes: &[u8], start: usize, end: usize) -> u32 {
    assert!(
        start < end && end - start <= 3,
        "decimal needs one to three digits"
    );
    let mut value = 0;
    let mut index = start;
    while index < end {
        assert!(bytes[index].is_ascii_digit(), "decimal digit expected");
        value = value * 10 + (bytes[index] - b'0') as u32;
        index += 1;
    }
    value
}

const fn hex_digit(byte: u8) -> u128 {
    match byte {
        b'0'..=b'9' => (byte - b'0') as u128,
        b'a'..=b'f' => (byte - b'a' + 10) as u128,
        b'A'..=b'F' => (byte - b'A' + 10) as u128,
        _ => panic!("hexadecimal digit expected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_parse_as_std_reads_them() {
        for cidr in [
            "0.0.0.0/8",
            "168.63.129.16/32",
            "255.255.255.255/32",
            "0.0.0.0/0",
        ] {
            let (address, length) = cidr.split_once('/').unwrap();
            assert_eq!(
                (
                    address.parse::<Ipv4Addr>().unwrap(),
                    length.parse().unwrap()
                ),
                ipv4(cidr).parts(),
                "{cidr}"
            );
        }
        for cidr in [
            "::/128",
            "::1/128",
            "::/0",
            "::ffff:0:0/96",
            "64:ff9b:1::/48",
            "2001::/23",
            "2001:4:112::/48",
            "fe80::/10",
            "ff00::/8",
            "1:2:3:4:5:6:7::/128",
            "1:2:3:4:5:6:7:8/128",
            "::2:3:4:5:6:7:8/128",
        ] {
            let (address, length) = cidr.split_once('/').unwrap();
            assert_eq!(
                (
                    address.parse::<Ipv6Addr>().unwrap(),
                    length.parse().unwrap()
                ),
                ipv6(cidr).parts(),
                "{cidr}"
            );
        }
    }

    #[test]
    fn containment_honours_the_length() {
        let documentation = ipv4("192.0.2.0/24");
        assert!(documentation.contains(Ipv4Addr::new(192, 0, 2, 255)));
        assert!(!documentation.contains(Ipv4Addr::new(192, 0, 3, 0)));
        assert!(ipv4("0.0.0.0/0").contains(Ipv4Addr::BROADCAST));

        let ietf = ipv6("2001::/23");
        assert!(ietf.contains("2001:1ff:ffff::".parse().unwrap()));
        assert!(!ietf.contains("2001:200::".parse().unwrap()));
        assert!(ipv6("::/0").contains(Ipv6Addr::from_bits(u128::MAX)));
    }
}
