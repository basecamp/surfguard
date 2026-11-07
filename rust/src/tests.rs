//! The generated tables against the snapshots they come from, read by
//! `std`'s own parser rather than the compile-time one in `prefix.rs`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::iana::{IANA_ALLOCATED_IPV6_UNICAST, IANA_SPECIAL_USE_IPV4, IANA_SPECIAL_USE_IPV6};
use crate::policy::{DISALLOWED_IPV4, DISALLOWED_IPV6};
use crate::{Policy, blocked_address};

#[path = "../tests/support/json.rs"]
#[allow(dead_code, reason = "these tests use only part of the reader")]
mod json;

fn snapshot(name: &str) -> Vec<(String, u32)> {
    let path = format!("{}/testdata/iana/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let snapshot = json::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        Some(1.0),
        snapshot.get("schema_version").and_then(json::Value::as_f64)
    );
    assert_eq!(
        Some(name),
        snapshot.get("registry").and_then(json::Value::as_str)
    );
    snapshot
        .get("prefixes")
        .and_then(json::Value::as_array)
        .unwrap()
        .iter()
        .map(|prefix| {
            let (address, length) = prefix.as_str().unwrap().split_once('/').unwrap();
            (address.to_owned(), length.parse().unwrap())
        })
        .collect()
}

#[test]
fn the_generated_tables_are_the_snapshots() {
    let ipv4: Vec<(Ipv4Addr, u32)> = IANA_SPECIAL_USE_IPV4
        .iter()
        .map(|prefix| prefix.parts())
        .collect();
    let expected: Vec<(Ipv4Addr, u32)> = snapshot("ipv4_special_use")
        .into_iter()
        .map(|(address, length)| (address.parse().unwrap(), length))
        .collect();
    assert_eq!(expected, ipv4);

    for (name, table) in [
        ("ipv6_allocated", IANA_ALLOCATED_IPV6_UNICAST.as_slice()),
        ("ipv6_special_use", IANA_SPECIAL_USE_IPV6.as_slice()),
    ] {
        let ipv6: Vec<(Ipv6Addr, u32)> = table.iter().map(|prefix| prefix.parts()).collect();
        let expected: Vec<(Ipv6Addr, u32)> = snapshot(name)
            .into_iter()
            .map(|(address, length)| (address.parse().unwrap(), length))
            .collect();
        assert_eq!(expected, ipv6, "{name}");
    }
}

#[test]
fn the_allocated_unicast_covers_the_corpus_public_addresses() {
    for address in ["2606:2800:220:1:248:1893:25c8:1946", "2620:4f:8000::1"] {
        let address: Ipv6Addr = address.parse().unwrap();
        assert!(
            IANA_ALLOCATED_IPV6_UNICAST
                .iter()
                .any(|prefix| prefix.contains(address))
        );
    }
}

#[test]
fn the_strict_policy_blocks_every_registered_endpoint() {
    for (first, last) in IANA_SPECIAL_USE_IPV4
        .iter()
        .map(|prefix| ipv4_ends(prefix.parts()))
    {
        for address in [first, last] {
            assert!(
                Policy::IanaSpecialUse.blocks(IpAddr::V4(address)),
                "{address}"
            );
        }
    }
    for (first, last) in IANA_SPECIAL_USE_IPV6
        .iter()
        .map(|prefix| ipv6_ends(prefix.parts()))
    {
        for address in [first, last] {
            assert!(
                Policy::IanaSpecialUse.blocks(IpAddr::V6(address)),
                "{address}"
            );
        }
    }
}

#[test]
fn every_explicit_deny_is_exactly_as_wide_as_written() {
    for (first, last) in DISALLOWED_IPV4
        .iter()
        .map(|prefix| ipv4_ends(prefix.parts()))
    {
        assert!(Policy::Default.blocks(IpAddr::V4(first)), "{first}");
        assert!(Policy::Default.blocks(IpAddr::V4(last)), "{last}");
    }
    for (first, last) in DISALLOWED_IPV6
        .iter()
        .map(|prefix| ipv6_ends(prefix.parts()))
    {
        assert!(Policy::Default.blocks(IpAddr::V6(first)), "{first}");
        assert!(Policy::Default.blocks(IpAddr::V6(last)), "{last}");
    }
    assert!(!blocked_address("168.63.129.15", Policy::Default));
    assert!(!blocked_address("168.63.129.17", Policy::Default));
}

fn ipv4_ends((network, length): (Ipv4Addr, u32)) -> (Ipv4Addr, Ipv4Addr) {
    let host = u32::MAX.checked_shr(length).unwrap_or(0);
    (network, Ipv4Addr::from_bits(network.to_bits() | host))
}

fn ipv6_ends((network, length): (Ipv6Addr, u32)) -> (Ipv6Addr, Ipv6Addr) {
    let host = u128::MAX.checked_shr(length).unwrap_or(0);
    (network, Ipv6Addr::from_bits(network.to_bits() | host))
}
