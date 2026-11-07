//! What a host is before any DNS: an address literal, a name to resolve, or
//! malformed. The gem's `normalize_host` and `numeric_literals`.
//!
//! An address literal includes the legacy `inet_aton` spellings (`2130706433`,
//! `0x7f.1`, `0177.0.0.1`): connection parsers read them as addresses, so they
//! are classified as the address they denote and never sent to DNS, where a
//! wildcard or search domain could answer for them with a public-looking
//! record. The gem reads them with the platform's
//! `getaddrinfo(AI_NUMERICHOST)`; this reads them with glibc's grammar
//! (`inet_aton_exact`, then `inet_pton` for IPv6), the platform production
//! runs on, on every platform.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ipaddr;

/// `MAX_HOST_BYTES`.
pub const MAX_HOST_BYTES: usize = 255;

#[derive(Clone, Copy)]
pub(crate) enum Host<'a> {
    Literal(IpAddr),
    Name(&'a str),
}

pub(crate) struct Malformed;

pub(crate) fn host(text: &str) -> Result<Host<'_>, Malformed> {
    normalized(text)?;
    if !valid_host_syntax(text) || malformed_numeric_candidate(text) {
        Err(Malformed)
    } else if let Some(address) = numeric_host(text).or_else(|| ipaddr::host_address(text)) {
        Ok(Host::Literal(address))
    } else if numeric_candidate(text) {
        Err(Malformed)
    } else {
        Ok(Host::Name(text))
    }
}

/// `normalize_host` and `owned_string`: ASCII, no NUL, no `%` (a zone in any
/// spelling), and between one and `MAX_HOST_BYTES` bytes.
fn normalized(text: &str) -> Result<(), Malformed> {
    if text.is_empty()
        || text.len() > MAX_HOST_BYTES
        || !text.is_ascii()
        || text.contains(['\0', '%'])
    {
        Err(Malformed)
    } else {
        Ok(())
    }
}

/// `valid_host_syntax?`: anything with a colon (judged later as IPv6),
/// legacy IPv4 shapes and one-address literals, and otherwise RFC 1123
/// letters, digits and hyphens with one trailing dot allowed.
fn valid_host_syntax(host: &str) -> bool {
    host.contains(':')
        || legacy_ipv4_shape(host)
        || ipaddr::host_address(host).is_some()
        || ldh_hostname(host)
}

fn ldh_hostname(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    name.split('.').all(ldh_label)
}

fn ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// `numeric_host_candidate?`: what must never reach DNS even when no parser
/// reads it as an address.
fn numeric_candidate(host: &str) -> bool {
    host.contains(':') || legacy_ipv4_shape(host)
}

/// `malformed_numeric_host_candidate?`: a legacy IPv4 shape decorated with a
/// leading `/`, a trailing `/…`, or an empty label (`127.0.0.1.`, `.1`,
/// `//127.0.0.1`, `127.0.0.1/33`). A loose parser downstream might still read
/// one as an address, so none is resolved. A one-address prefix spelling
/// (`127.0.0.1/32`) is a literal instead.
fn malformed_numeric_candidate(host: &str) -> bool {
    if host.contains(':') {
        return false;
    }
    let trimmed = host.trim_start_matches(['%', '/']);
    let core = trimmed.split(['%', '/']).next().unwrap_or_default();
    let decorated = core != host || core.split('.').any(str::is_empty);
    decorated && legacy_ipv4_shape(core) && ipaddr::host_address(host).is_none()
}

/// `legacy_ipv4_shape?`: one to four non-empty dot-separated parts, each
/// decimal digits or `0x` and hex digits, ignoring empty parts so decorated
/// spellings still register as numeric.
fn legacy_ipv4_shape(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').filter(|part| !part.is_empty()).collect();
    (1..=4).contains(&parts.len()) && parts.iter().all(|part| legacy_part_shape(part))
}

fn legacy_part_shape(part: &str) -> bool {
    match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => part.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

/// What glibc's `getaddrinfo` reads as a numeric host: `inet_aton_exact`,
/// then `inet_pton` for IPv6.
fn numeric_host(host: &str) -> Option<IpAddr> {
    inet_aton(host)
        .map(IpAddr::V4)
        .or_else(|| host.parse::<Ipv6Addr>().ok().map(IpAddr::V6))
}

/// glibc's `inet_aton_exact`: one to four parts, each `strtoul` base 0 (`0x`
/// hex, a leading `0` octal, decimal otherwise) and starting with a digit,
/// the leading parts a byte each and the last part covering the bytes left,
/// with nothing after.
pub(crate) fn inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let values: Vec<u32> = parts
        .iter()
        .map(|part| inet_aton_part(part))
        .collect::<Option<_>>()?;
    let (last, leading) = values.split_last()?;
    if leading.iter().any(|value| *value > 0xff) {
        return None;
    }
    let last_bits = 8 * (4 - u32::try_from(leading.len()).expect("at most three"));
    if last_bits < 32 && *last >= 1 << last_bits {
        return None;
    }
    let value = leading
        .iter()
        .enumerate()
        .fold(*last, |value, (index, part)| {
            value | part << (24 - 8 * index)
        });
    Some(Ipv4Addr::from_bits(value))
}

fn inet_aton_part(part: &str) -> Option<u32> {
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    let well_formed =
        !digits.is_empty() && digits.bytes().all(|byte| (byte as char).is_digit(radix));
    if well_formed {
        u32::from_str_radix(digits, radix).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_aton_reads_as_glibc_reads() {
        for (host, address) in [
            ("2130706433", Some("127.0.0.1")),
            ("4294967295", Some("255.255.255.255")),
            ("4294967296", None),
            ("0x100000000", None),
            ("1.16777215", Some("1.255.255.255")),
            ("1.16777216", None),
            ("99999999999999999999", None),
            ("0x", None),
            ("0", Some("0.0.0.0")),
            ("00", Some("0.0.0.0")),
            ("08", None),
            ("0x7f.1", Some("127.0.0.1")),
            ("0177.0.0.1", Some("127.0.0.1")),
            ("00000000000000000000001", Some("0.0.0.1")),
            ("0x0000000000000000001", Some("0.0.0.1")),
            ("1.2.0x10.4", Some("1.2.16.4")),
            ("1.2.3.4.", None),
            (".1", None),
            ("1..2", None),
            ("1.2.3.4.5", None),
            ("256.1", None),
            ("1e5", None),
            ("+1", None),
            ("", None),
        ] {
            assert_eq!(
                address.map(|address| address.parse().unwrap()),
                inet_aton(host),
                "{host:?}"
            );
        }
    }
}
