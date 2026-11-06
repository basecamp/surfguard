//! The README's contract for the five APIs, after the gem's
//! `surfguard_test.rb` and `surfguard_hardening_test.rb`. No test reaches the
//! network: every name is answered by a resolver the test supplies.

use std::cell::RefCell;
use std::io;
use std::net::IpAddr;

use surfguard::{
    BLOCKED_MESSAGE, Error, MALFORMED_MESSAGE, MAX_ADDRESSES, Policy, Resolver,
    UNRESOLVABLE_MESSAGE, Unresolvable, Violation,
};

const PUBLIC_IPV4: &str = "93.184.216.34";
const PUBLIC_IPV6: &str = "2606:2800:220:1:248:1893:25c8:1946";

/// Answers every name with `answers`, and remembers what it was asked.
struct Answers {
    answers: io::Result<Vec<IpAddr>>,
    asked: RefCell<Vec<String>>,
}

impl Answers {
    fn of(answers: &[&str]) -> Self {
        Answers {
            answers: Ok(addresses(answers)),
            asked: RefCell::default(),
        }
    }

    fn failing() -> Self {
        Answers {
            answers: Err(io::Error::other("attacker-controlled resolver detail")),
            asked: RefCell::default(),
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.borrow().clone()
    }
}

impl Resolver for Answers {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.asked.borrow_mut().push(host.to_owned());
        match &self.answers {
            Ok(answers) => Ok(answers.clone()),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }
}

fn addresses(texts: &[&str]) -> Vec<IpAddr> {
    texts.iter().map(|text| text.parse().unwrap()).collect()
}

/// What each API makes of one URL, `https://target.example/` unless given.
#[derive(Debug, PartialEq)]
struct Results {
    plural: Result<Vec<IpAddr>, Unresolvable>,
    predicate: bool,
    enforce: Result<(), Error>,
    single: Result<Option<IpAddr>, Unresolvable>,
}

fn results(resolver: &Answers, policy: Policy) -> Results {
    let url = "https://target.example/path";
    Results {
        plural: surfguard::resolve_public_ips("target.example", &policy, resolver),
        predicate: surfguard::resolvable_public_ip(url, &policy, resolver),
        enforce: surfguard::enforce_public_ip(url, &policy, resolver),
        single: surfguard::resolve_public_ip(url, &policy, resolver),
    }
}

fn unresolvable() -> Results {
    Results {
        plural: Err(Unresolvable),
        predicate: false,
        enforce: Err(Error::Unresolvable(Unresolvable)),
        single: Err(Unresolvable),
    }
}

#[test]
fn messages_are_fixed() {
    assert_eq!("Host could not be resolved", UNRESOLVABLE_MESSAGE);
    assert_eq!("Refusing blocked address", BLOCKED_MESSAGE);
    assert_eq!("Refusing malformed address", MALFORMED_MESSAGE);
    assert_eq!(UNRESOLVABLE_MESSAGE, Unresolvable.to_string());
    assert_eq!(BLOCKED_MESSAGE, Violation::Blocked.to_string());
    assert_eq!(MALFORMED_MESSAGE, Violation::Malformed.to_string());
    assert_eq!(
        UNRESOLVABLE_MESSAGE,
        Error::Unresolvable(Unresolvable).to_string()
    );
    assert_eq!(
        BLOCKED_MESSAGE,
        Error::Violation(Violation::Blocked).to_string()
    );
}

#[test]
fn all_public_answers_pass_every_api() {
    let resolver = Answers::of(&[PUBLIC_IPV4]);
    assert_eq!(
        Results {
            plural: Ok(addresses(&[PUBLIC_IPV4])),
            predicate: true,
            enforce: Ok(()),
            single: Ok(Some(PUBLIC_IPV4.parse().unwrap())),
        },
        results(&resolver, Policy::Default)
    );
}

#[test]
fn mixed_answers_follow_the_contract() {
    let resolver = Answers::of(&[PUBLIC_IPV6, "10.0.0.1", PUBLIC_IPV4]);
    assert_eq!(
        Results {
            plural: Ok(addresses(&[PUBLIC_IPV4, PUBLIC_IPV6])),
            predicate: false,
            enforce: Err(Error::Violation(Violation::Blocked)),
            single: Ok(None),
        },
        results(&resolver, Policy::Default)
    );
}

#[test]
fn every_answer_blocked_is_an_empty_list_not_unresolvable() {
    let resolver = Answers::of(&["10.0.0.1", "169.254.169.254"]);
    assert_eq!(Ok(Vec::new()), results(&resolver, Policy::Default).plural);
    assert_eq!(Ok(None), results(&resolver, Policy::Default).single);
}

#[test]
fn the_single_keeps_resolver_order_and_the_plural_puts_ipv4_first() {
    let resolver = Answers::of(&[PUBLIC_IPV6, PUBLIC_IPV4]);
    let results = results(&resolver, Policy::Default);
    assert_eq!(Ok(Some(PUBLIC_IPV6.parse().unwrap())), results.single);
    assert_eq!(Ok(addresses(&[PUBLIC_IPV4, PUBLIC_IPV6])), results.plural);
}

#[test]
fn the_plural_keeps_resolver_order_within_each_family() {
    let resolver = Answers::of(&["2a00::1", "8.8.8.8", "2400::1", "1.1.1.1", "fd00::1"]);
    assert_eq!(
        Ok(addresses(&["8.8.8.8", "1.1.1.1", "2a00::1", "2400::1"])),
        surfguard::resolve_public_ips("target.example", &Policy::Default, &resolver)
    );
}

#[test]
fn answers_are_deduplicated_in_order() {
    let resolver = Answers::of(&[PUBLIC_IPV4, "93.184.216.35", PUBLIC_IPV4]);
    assert_eq!(
        Ok(addresses(&[PUBLIC_IPV4, "93.184.216.35"])),
        surfguard::resolve_public_ips("target.example", &Policy::Default, &resolver)
    );

    let resolver = Answers::of(&[PUBLIC_IPV4; MAX_ADDRESSES]);
    assert_eq!(
        Results {
            plural: Ok(addresses(&[PUBLIC_IPV4])),
            predicate: true,
            enforce: Ok(()),
            single: Ok(Some(PUBLIC_IPV4.parse().unwrap())),
        },
        results(&resolver, Policy::Default)
    );
}

#[test]
fn more_than_256_answers_invalidate_the_lookup() {
    let resolver = Answers::of(&[PUBLIC_IPV4; MAX_ADDRESSES + 1]);
    assert_eq!(unresolvable(), results(&resolver, Policy::Default));

    let unique: Vec<String> = (0..=MAX_ADDRESSES)
        .map(|index| {
            std::net::Ipv4Addr::from_bits(0x0b00_0000 + u32::try_from(index).unwrap()).to_string()
        })
        .collect();
    let unique: Vec<&str> = unique.iter().map(String::as_str).collect();
    let resolver = Answers::of(&unique[..MAX_ADDRESSES]);
    assert_eq!(
        Ok(addresses(&unique[..MAX_ADDRESSES])),
        surfguard::resolve_public_ips("target.example", &Policy::Default, &resolver)
    );
    assert_eq!(
        unresolvable(),
        results(&Answers::of(&unique), Policy::Default)
    );
}

#[test]
fn an_empty_or_failed_lookup_is_unresolvable() {
    assert_eq!(unresolvable(), results(&Answers::of(&[]), Policy::Default));
    assert_eq!(
        unresolvable(),
        results(&Answers::failing(), Policy::Default)
    );
    assert!(!format!("{:?}", results(&Answers::failing(), Policy::Default)).contains("attacker"));
}

#[test]
fn malformed_input_follows_the_contract() {
    let resolver = Answers::of(&[PUBLIC_IPV4]);
    for host in [
        "",
        "example\0.com",
        "café.example",
        &"a".repeat(256),
        "a_b.1.1.1.1.sslip.io",
        "host%25eth0",
    ] {
        assert_eq!(
            Ok(Vec::new()),
            surfguard::resolve_public_ips(host, &Policy::Default, &resolver),
            "{host:?}"
        );
    }
    for url in [
        "https://",
        "http://",
        "https:///path",
        "::::not a url",
        "example.com",
        "https://[fe80::1%25lo]/",
        "https://[v1.fe]/",
        "https://example.invalid/ attacker-controlled-uri-detail",
        "https://caf\u{e9}.example/",
        "https://a_b.example/",
        "mailto:someone@example.com",
    ] {
        assert!(
            !surfguard::resolvable_public_ip(url, &Policy::Default, &resolver),
            "{url}"
        );
        assert_eq!(
            Err(Error::Violation(Violation::Malformed)),
            surfguard::enforce_public_ip(url, &Policy::Default, &resolver),
            "{url}"
        );
        assert_eq!(
            Ok(None),
            surfguard::resolve_public_ip(url, &Policy::Default, &resolver),
            "{url}"
        );
    }
    assert!(resolver.asked().is_empty(), "{:?}", resolver.asked());
    assert!(surfguard::blocked_address("not-an-ip", Policy::Default));
    assert!(surfguard::blocked_address(
        "2606:4700:4700::1111%lo",
        Policy::Default
    ));
    assert!(surfguard::blocked_address(
        "2606:4700:4700::1111%lo",
        Policy::IanaSpecialUse
    ));
}

#[test]
fn literal_hosts_skip_dns() {
    let resolver = Answers::of(&[PUBLIC_IPV4]);
    assert!(!surfguard::resolvable_public_ip(
        "http://169.254.169.254/latest/meta-data/",
        &Policy::Default,
        &resolver
    ));
    assert!(surfguard::resolvable_public_ip(
        "http://93.184.216.34/",
        &Policy::Default,
        &resolver
    ));
    assert!(!surfguard::resolvable_public_ip(
        "http://[::1]/",
        &Policy::Default,
        &resolver
    ));
    assert!(!surfguard::resolvable_public_ip(
        "http://[fd00:ec2::254]/",
        &Policy::Default,
        &resolver
    ));
    assert_eq!(
        Ok(addresses(&[PUBLIC_IPV6])),
        surfguard::resolve_public_ips(&format!("[{PUBLIC_IPV6}]"), &Policy::Default, &resolver)
    );
    assert_eq!(
        Ok(addresses(&["127.0.0.1"])),
        surfguard::resolve_public_ips("0x7f.1", &|_: IpAddr| false, &resolver)
    );
    assert!(resolver.asked().is_empty(), "{:?}", resolver.asked());
}

#[test]
fn the_azure_wire_server_is_refused_as_a_literal_and_in_an_answer() {
    let url = "http://168.63.129.16/machine/?comp=goalstate";
    let resolver = Answers::of(&[]);
    assert_eq!(
        Ok(Vec::new()),
        surfguard::resolve_public_ips("168.63.129.16", &Policy::Default, &resolver)
    );
    assert_eq!(
        Ok(None),
        surfguard::resolve_public_ip(url, &Policy::Default, &resolver)
    );
    assert!(!surfguard::resolvable_public_ip(
        url,
        &Policy::Default,
        &resolver
    ));
    assert_eq!(
        Err(Error::Violation(Violation::Blocked)),
        surfguard::enforce_public_ip(url, &Policy::Default, &resolver)
    );

    let resolver = Answers::of(&[PUBLIC_IPV4, "168.63.129.16"]);
    assert_eq!(
        Results {
            plural: Ok(addresses(&[PUBLIC_IPV4])),
            predicate: false,
            enforce: Err(Error::Violation(Violation::Blocked)),
            single: Ok(None),
        },
        results(&resolver, Policy::Default)
    );
}

#[test]
fn the_reported_prefixes_are_blocked_at_both_ends_through_every_api() {
    for (first, last) in [
        ("100:0:0:1::", "100::1:ffff:ffff:ffff:ffff"),
        ("3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ("5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ] {
        for address in [first, last] {
            let url = format!("https://[{address}]/");
            let resolver = Answers::of(&[address]);
            assert!(
                surfguard::blocked_address(address, Policy::Default),
                "{address}"
            );
            assert_eq!(
                Ok(Vec::new()),
                surfguard::resolve_public_ips(address, &Policy::Default, &resolver)
            );
            assert_eq!(
                Ok(None),
                surfguard::resolve_public_ip(&url, &Policy::Default, &resolver)
            );
            assert_eq!(
                Err(Error::Violation(Violation::Blocked)),
                surfguard::enforce_public_ip(&url, &Policy::Default, &resolver)
            );
            assert_eq!(
                Ok(Vec::new()),
                results(&resolver, Policy::Default).plural,
                "{address} by DNS"
            );
        }
    }
}

#[test]
fn unallocated_ipv6_is_refused() {
    for address in [
        "1::1",
        "400::1",
        "100:0:0:2::1",
        "2000::1",
        "3ffe::1",
        "3fff:1000::",
        "4000::1",
        "f000::1",
    ] {
        assert!(
            surfguard::blocked_address(address, Policy::Default),
            "{address}"
        );
    }
}

#[test]
fn the_strict_policy_refuses_service_and_transition_space_the_default_admits() {
    for address in [
        "2001:3::1",
        "2001:4:112::1",
        "2620:4f:8000::1",
        "64:ff9b::5db8:d822",
        "192.31.196.1",
    ] {
        assert!(
            !surfguard::blocked_address(address, Policy::Default),
            "{address}"
        );
        assert!(
            surfguard::blocked_address(address, Policy::IanaSpecialUse),
            "{address}"
        );
    }
    for address in ["64:ff9b::c01f:c401", "::ffff:0:c01f:c401"] {
        assert!(
            !surfguard::blocked_address(address, Policy::Default),
            "{address}"
        );
        assert!(
            surfguard::blocked_address(address, Policy::IanaSpecialUse),
            "{address}"
        );
    }
    assert!(!surfguard::blocked_address(
        PUBLIC_IPV4,
        Policy::IanaSpecialUse
    ));
    assert!(!surfguard::blocked_address(
        PUBLIC_IPV6,
        Policy::IanaSpecialUse
    ));
}

#[test]
fn a_classifier_of_the_callers_own_can_wrap_a_policy() {
    let fixture = |address: IpAddr| !address.is_loopback() && Policy::Default.blocks(address);
    let resolver = Answers::of(&["127.0.0.1", "10.0.0.1", PUBLIC_IPV4]);
    assert_eq!(
        Ok(addresses(&["127.0.0.1", PUBLIC_IPV4])),
        surfguard::resolve_public_ips("fixture.test", &fixture, &resolver)
    );
}

#[test]
fn unresolvable_and_violation_are_different_errors() {
    let resolver = Answers::of(&[]);
    assert!(matches!(
        surfguard::enforce_public_ip("https://nope.example", &Policy::Default, &resolver),
        Err(Error::Unresolvable(_))
    ));
    assert!(std::error::Error::source(&Error::Unresolvable(Unresolvable)).is_none());
}
