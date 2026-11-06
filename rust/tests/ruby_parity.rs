//! The gem's own verdicts, written by `tests/ruby/verdicts.rb` into the file
//! `SURFGUARD_RUBY_VERDICTS` names, replayed against the crate: tens of
//! thousands of addresses, host spellings and URLs, table edges and random
//! noise among them. CI writes the file with the gem in this repository;
//! without it, there is nothing to replay.
//!
//! One difference is expected. The gem lets `URI::InvalidComponentError`
//! escape for a `mailto://` URL with no query; the crate calls it malformed.

mod support;

use std::cell::RefCell;
use std::io;
use std::net::IpAddr;

use support::json::{self, Value};
use surfguard::{Error, Policy, Resolver, Unresolvable, Violation};

const PUBLIC: &str = "93.184.216.34";

#[derive(Default)]
struct Recording {
    asked: RefCell<Vec<String>>,
}

impl Resolver for Recording {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.asked.borrow_mut().push(host.to_owned());
        Ok(vec![PUBLIC.parse().unwrap()])
    }
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap().to_owned()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

fn verdicts() -> Option<Value> {
    let path = std::env::var("SURFGUARD_RUBY_VERDICTS").ok()?;
    Some(json::parse(&std::fs::read_to_string(path).unwrap()).unwrap())
}

fn report(wrong: &[String]) {
    assert!(
        wrong.is_empty(),
        "{} differ from the gem:\n{}",
        wrong.len(),
        wrong
            .iter()
            .take(50)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_classifier_agrees_with_the_gem() {
    let Some(verdicts) = verdicts() else {
        eprintln!("SURFGUARD_RUBY_VERDICTS unset: nothing to replay");
        return;
    };
    let mut wrong = Vec::new();
    for case in verdicts.get("addresses").and_then(Value::as_array).unwrap() {
        let input = text(case, "input");
        for (name, policy) in [
            ("default", Policy::Default),
            ("iana_special_use", Policy::IanaSpecialUse),
        ] {
            let expected = case.get(name).and_then(Value::as_bool).unwrap();
            if surfguard::blocked_address(&input, policy) != expected {
                wrong.push(format!(
                    "blocked_address({input:?}, {name}): gem says {expected}"
                ));
            }
        }
    }
    report(&wrong);
}

#[test]
fn hosts_resolve_as_the_gem_resolves_them() {
    let Some(verdicts) = verdicts() else {
        eprintln!("SURFGUARD_RUBY_VERDICTS unset: nothing to replay");
        return;
    };
    let mut wrong = Vec::new();
    for case in verdicts.get("hosts").and_then(Value::as_array).unwrap() {
        let input = text(case, "input");
        let resolver = Recording::default();
        let result = surfguard::resolve_public_ips(&input, &Policy::Default, &resolver);
        let expected = match case.get("result").unwrap() {
            Value::Array(addresses) => Ok(addresses
                .iter()
                .map(|address| address.as_str().unwrap().parse().unwrap())
                .collect()),
            Value::String(outcome) if outcome == "unresolvable" => Err(Unresolvable),
            other => panic!("{input:?}: the gem answered {other:?}"),
        };
        let asked = resolver.asked.borrow().clone();
        if result != expected || asked != strings(case, "asked") {
            wrong.push(format!("resolve_public_ips({input:?}): crate {result:?} asking {asked:?}, gem {expected:?} asking {:?}", strings(case, "asked")));
        }
    }
    report(&wrong);
}

#[test]
fn urls_are_judged_as_the_gem_judges_them() {
    let Some(verdicts) = verdicts() else {
        eprintln!("SURFGUARD_RUBY_VERDICTS unset: nothing to replay");
        return;
    };
    let mut wrong = Vec::new();
    for case in verdicts.get("urls").and_then(Value::as_array).unwrap() {
        let input = text(case, "input");
        let resolver = Recording::default();
        let single = match surfguard::resolve_public_ip(&input, &Policy::Default, &resolver) {
            Ok(Some(address)) => Value::String(address.to_string()),
            Ok(None) => Value::Null,
            Err(Unresolvable) => Value::String(String::from("unresolvable")),
        };
        let canonical = |value: Value| match value {
            Value::String(text) => Value::String(
                text.parse::<IpAddr>()
                    .map_or(text, |address| address.to_string()),
            ),
            other => other,
        };
        let enforce = match surfguard::enforce_public_ip(&input, &Policy::Default, &resolver) {
            Ok(()) => String::from("ok"),
            Err(Error::Violation(violation)) => violation.to_string(),
            Err(Error::Unresolvable(_)) => String::from("unresolvable"),
        };
        let mut asked = resolver.asked.borrow().clone();
        asked.dedup();

        let mut expected_single = case.get("single").unwrap().clone();
        let mut expected_enforce = text(case, "enforce");
        if expected_enforce.starts_with("raises URI::InvalidComponentError")
            && input.to_ascii_lowercase().starts_with("mailto://")
        {
            expected_single = Value::Null;
            expected_enforce = Violation::Malformed.to_string();
        }
        let expected_single = canonical(expected_single);
        if single != expected_single
            || enforce != expected_enforce
            || asked != strings(case, "asked")
        {
            wrong.push(format!(
                "{input:?}: crate {single:?}/{enforce} asking {asked:?}, gem {expected_single:?}/{expected_enforce} asking {:?}",
                strings(case, "asked")
            ));
        }
    }
    report(&wrong);
}
