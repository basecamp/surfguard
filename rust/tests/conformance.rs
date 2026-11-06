//! The shared corpus under `../conformance`, read from its checked-in mirror
//! in `testdata/conformance` (kept identical by `tests/drift.rs`), so the
//! crate's tests pass from the crate directory alone. Every verdict here is
//! asserted by the gem's suite and the Go module's too.

mod support;

use std::cell::RefCell;
use std::io;
use std::net::IpAddr;

use support::json::{self, Value};
use surfguard::{Policy, Resolver};

fn cases(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/testdata/conformance/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let file = json::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        Some(1.0),
        file.get("schema_version").and_then(Value::as_f64),
        "{name}"
    );
    let cases = file
        .get("cases")
        .and_then(Value::as_array)
        .unwrap()
        .to_vec();
    assert!(!cases.is_empty(), "{name}: empty corpus");
    cases
}

fn input(case: &Value) -> &str {
    case.get("input").and_then(Value::as_str).unwrap()
}

fn policy(name: &str) -> Policy {
    match name {
        "default" => Policy::Default,
        "iana_special_use" => Policy::IanaSpecialUse,
        other => panic!("unknown policy {other:?}"),
    }
}

const PUBLIC: &str = "93.184.216.34";

/// A wildcard answer for every name, standing in for a search domain or a
/// wildcard record: were a spelling ever sent to DNS, it would come back
/// admitted.
#[derive(Default)]
struct Wildcard {
    asked: RefCell<Vec<String>>,
}

impl Resolver for Wildcard {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.asked.borrow_mut().push(host.to_owned());
        Ok(vec![PUBLIC.parse().unwrap()])
    }
}

#[test]
fn every_address_is_classified_as_the_corpus_says() {
    let mut wrong = Vec::new();
    for name in ["blocked", "allowed", "boundaries"] {
        for case in cases(name) {
            let address: IpAddr = input(&case).parse().unwrap();
            for (policy_name, verdict) in case.get("policies").and_then(Value::as_object).unwrap() {
                let policy = policy(policy_name);
                let blocked = verdict.as_str() == Some("blocked");
                if policy.blocks(address) != blocked {
                    wrong.push(format!("{name}: {address} under {policy_name}: blocks"));
                }
                if surfguard::blocked_address(input(&case), policy) != blocked {
                    wrong.push(format!(
                        "{name}: {address} under {policy_name}: blocked_address"
                    ));
                }
                let resolved =
                    surfguard::resolve_public_ips(input(&case), &policy, &Wildcard::default());
                let expected: Vec<IpAddr> = if blocked { Vec::new() } else { vec![address] };
                if resolved != Ok(expected) {
                    wrong.push(format!(
                        "{name}: {address} under {policy_name}: resolve_public_ips"
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn legacy_numeric_spellings_are_classified_without_dns() {
    for case in cases("legacy_numeric") {
        let canonical: IpAddr = case
            .get("canonical")
            .and_then(Value::as_str)
            .unwrap()
            .parse()
            .unwrap();
        let blocked = case.get("blocked").and_then(Value::as_bool).unwrap();
        let resolver = Wildcard::default();

        let admitted = surfguard::resolve_public_ips(input(&case), &Policy::Default, &resolver);

        let expected = if blocked { Vec::new() } else { vec![canonical] };
        assert_eq!(Ok(expected), admitted, "{}", input(&case));
        assert!(
            resolver.asked.borrow().is_empty(),
            "{} was sent to DNS",
            input(&case)
        );
        assert_eq!(
            blocked,
            Policy::Default.blocks(canonical),
            "{}",
            input(&case)
        );
        assert!(
            surfguard::blocked_address(input(&case), Policy::Default),
            "{}: the classifier reads no legacy spelling",
            input(&case)
        );
    }
}

#[test]
fn malformed_numeric_hosts_and_networks_are_refused_without_dns() {
    for name in ["malformed_numeric_hosts", "non_host_prefixes"] {
        for case in cases(name) {
            let resolver = Wildcard::default();
            let url = format!("https://{}/", input(&case));

            assert_eq!(
                Ok(Vec::new()),
                surfguard::resolve_public_ips(input(&case), &Policy::Default, &resolver)
            );
            assert!(
                surfguard::blocked_address(input(&case), Policy::Default),
                "{}",
                input(&case)
            );
            assert_eq!(
                Ok(None),
                surfguard::resolve_public_ip(&url, &Policy::Default, &resolver),
                "{url}"
            );
            assert!(
                resolver.asked.borrow().is_empty(),
                "{name}: {} was sent to DNS",
                input(&case)
            );
        }
    }
}

#[test]
fn one_address_prefixes_stay_literals() {
    for (host, address) in [
        ("93.184.216.34/32", "93.184.216.34"),
        (
            "2606:2800:220:1:248:1893:25c8:1946/128",
            "2606:2800:220:1:248:1893:25c8:1946",
        ),
    ] {
        let resolver = Wildcard::default();
        assert_eq!(
            Ok(vec![address.parse().unwrap()]),
            surfguard::resolve_public_ips(host, &Policy::Default, &resolver),
            "{host}"
        );
        assert!(!surfguard::blocked_address(host, Policy::Default), "{host}");
        assert!(resolver.asked.borrow().is_empty(), "{host} was sent to DNS");
    }
}

#[test]
fn numeric_looking_hostnames_still_reach_dns() {
    for case in cases("dns_hostnames") {
        let resolver = Wildcard::default();
        assert_eq!(
            Ok(vec![PUBLIC.parse().unwrap()]),
            surfguard::resolve_public_ips(input(&case), &Policy::Default, &resolver),
            "{}",
            input(&case)
        );
        assert_eq!(vec![input(&case).to_owned()], *resolver.asked.borrow());
    }
}
