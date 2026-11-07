//! Renders `rust/src/iana.rs` from the IANA registry snapshots mirrored under
//! `rust/testdata/iana`: a checked-in copy of the repo-root `script/iana`
//! snapshots the Ruby constants and the Go tables are generated from (a drift
//! test keeps the mirror identical), so the crate generates self-contained
//! while the policy source of truth stays shared.
//!
//! Run from `rust/`:
//!
//! ```text
//! cargo run -p surfguard-generate              # rewrite src/iana.rs
//! cargo run -p surfguard-generate -- --check   # fail if src/iana.rs is stale (CI)
//! ```

use std::fmt::Write;
use std::path::Path;
use std::process::ExitCode;

#[path = "../../tests/support/json.rs"]
#[allow(
    dead_code,
    reason = "the tests use more of the reader than the generator does"
)]
mod json;

struct Region {
    constant: &'static str,
    snapshot: &'static str,
    family: Family,
    comments: &'static [&'static str],
}

#[derive(Clone, Copy)]
enum Family {
    Ipv4,
    Ipv6,
}

const REGIONS: [Region; 3] = [
    Region {
        constant: "IANA_ALLOCATED_IPV6_UNICAST",
        snapshot: "ipv6_allocated",
        family: Family::Ipv6,
        comments: &[
            "Generated from IANA IPv6 Global Unicast Status=ALLOCATED rows.",
            "Source provenance is checked in under script/iana.",
        ],
    },
    Region {
        constant: "IANA_SPECIAL_USE_IPV4",
        snapshot: "ipv4_special_use",
        family: Family::Ipv4,
        comments: &["Every prefix in the checked-in IANA IPv4 special-purpose snapshot."],
    },
    Region {
        constant: "IANA_SPECIAL_USE_IPV6",
        snapshot: "ipv6_special_use",
        family: Family::Ipv6,
        comments: &["Every prefix in the checked-in IANA IPv6 special-purpose snapshot."],
    },
];

fn main() -> ExitCode {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the generator lives inside the crate");
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let check = match arguments.as_slice() {
        [] => false,
        [flag] if flag == "--check" => true,
        _ => {
            eprintln!("usage: cargo run -p surfguard-generate [-- --check]");
            return ExitCode::from(2);
        }
    };
    match run(crate_root, check) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("generate: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(crate_root: &Path, check: bool) -> Result<String, String> {
    let target = crate_root.join("src").join("iana.rs");
    let generated = render(&crate_root.join("testdata").join("iana"))?;
    if check {
        let current = std::fs::read_to_string(&target)
            .map_err(|error| format!("read {}: {error}", target.display()))?;
        if current == generated {
            Ok(String::from("generated IANA tables: ok"))
        } else {
            Err(format!(
                "{} differs from the script/iana snapshots; review the snapshots, then run cargo run -p surfguard-generate",
                target.display()
            ))
        }
    } else {
        std::fs::write(&target, generated)
            .map_err(|error| format!("write {}: {error}", target.display()))?;
        Ok(format!("wrote {}", target.display()))
    }
}

fn render(snapshots: &Path) -> Result<String, String> {
    let mut out = String::from(
        "// Code generated from the IANA registry snapshots in script/iana by\n\
         // rust/generate. DO NOT EDIT. Refresh with: cargo run -p surfguard-generate\n\
         // (verified in CI by cargo run -p surfguard-generate -- --check).\n\n\
         use crate::prefix::{Ipv4Prefix, Ipv6Prefix, ipv4_table, ipv6_table};\n",
    );
    for region in &REGIONS {
        let prefixes = load(&snapshots.join(format!("{}.json", region.snapshot)), region)?;
        let (kind, table) = match region.family {
            Family::Ipv4 => ("Ipv4Prefix", "ipv4_table"),
            Family::Ipv6 => ("Ipv6Prefix", "ipv6_table"),
        };
        let _ = writeln!(out, "\n// iana-generator:begin {}", region.constant);
        for comment in region.comments {
            let _ = writeln!(out, "// {comment}");
        }
        let _ = writeln!(
            out,
            "pub(crate) static {}: [{kind}; {}] = {table}([",
            region.constant,
            prefixes.len()
        );
        for prefix in &prefixes {
            let _ = writeln!(out, "    \"{prefix}\",");
        }
        out.push_str("]);\n");
        let _ = writeln!(out, "// iana-generator:end {}", region.constant);
    }
    Ok(out)
}

fn load(path: &Path, region: &Region) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let snapshot = json::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    if snapshot.get("schema_version").and_then(json::Value::as_f64) != Some(1.0) {
        return Err(format!("{}: unsupported schema_version", path.display()));
    }
    if snapshot.get("registry").and_then(json::Value::as_str) != Some(region.snapshot) {
        return Err(format!(
            "{}: registry is not {}",
            path.display(),
            region.snapshot
        ));
    }
    let prefixes = snapshot
        .get("prefixes")
        .and_then(json::Value::as_array)
        .filter(|prefixes| !prefixes.is_empty())
        .ok_or_else(|| format!("{}: empty prefix list", path.display()))?;
    prefixes
        .iter()
        .map(|prefix| {
            let cidr = prefix
                .as_str()
                .ok_or_else(|| format!("{}: a prefix is not a string", path.display()))?;
            canonical(cidr, region.family)
                .then(|| cidr.to_owned())
                .ok_or_else(|| format!("{}: {cidr} is not a canonical network", path.display()))
        })
        .collect()
}

/// Whether `cidr` is a network of `family` in the spelling `std` writes, with
/// no host bits set: the form `prefix.rs` parses at compile time.
fn canonical(cidr: &str, family: Family) -> bool {
    let Some((address, length)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(length) = length.parse::<u32>() else {
        return false;
    };
    match family {
        Family::Ipv4 => address.parse::<std::net::Ipv4Addr>().is_ok_and(|address| {
            length <= 32
                && address.to_string() == address_text(cidr)
                && address.to_bits().checked_shl(length).unwrap_or(0) == 0
        }),
        Family::Ipv6 => address.parse::<std::net::Ipv6Addr>().is_ok_and(|address| {
            length <= 128
                && !address_text(cidr).contains('.')
                && address.to_bits().checked_shl(length).unwrap_or(0) == 0
        }),
    }
}

fn address_text(cidr: &str) -> &str {
    cidr.split_once('/').map_or(cidr, |(address, _)| address)
}
