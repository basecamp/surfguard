//! The host of a URL as the gem reads it: Ruby's `URI.parse`, its RFC 3986
//! grammar and the checks its scheme classes add, then `host_of`, which
//! refuses a missing or empty host and strips the brackets from an IPv6
//! literal. A URL with no authority, such as `mailto:` or a bare path, has no
//! host and is malformed, and so is an `IPvFuture` literal, which Ruby's
//! grammar admits and `host_of` refuses.

pub(crate) struct Malformed;

pub(crate) fn host(url: &str) -> Result<&str, Malformed> {
    if !url.is_ascii() || url.contains('\0') {
        return Err(Malformed);
    }
    let (scheme, rest) = match scheme(url) {
        Some(scheme) => (Some(scheme), &url[scheme.len() + 1..]),
        None => (None, url),
    };
    let authority = rest.strip_prefix("//").ok_or(Malformed)?;
    let Parts {
        host,
        query,
        fragment,
    } = parts(authority)?;
    let host = match scheme.map(str::to_ascii_lowercase).as_deref() {
        Some("file") if host == "localhost" => "",
        Some("ldap" | "ldaps") if fragment => return Err(Malformed),
        Some("mailto") if !query => return Err(Malformed),
        _ => host,
    };
    if host.is_empty() {
        return Err(Malformed);
    }
    let host = host.strip_prefix('[').unwrap_or(host);
    Ok(host.strip_suffix(']').unwrap_or(host))
}

/// `scheme ":"`, when `url` starts with one.
fn scheme(url: &str) -> Option<&str> {
    let end = url.find(':')?;
    let scheme = &url[..end];
    let mut bytes = scheme.bytes();
    let well_formed = bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    well_formed.then_some(scheme)
}

struct Parts<'a> {
    host: &'a str,
    query: bool,
    fragment: bool,
}

/// Everything after `//`: `authority path-abempty [ "?" query ] [ "#"
/// fragment ]`, all of it.
fn parts(text: &str) -> Result<Parts<'_>, Malformed> {
    let authority_end = text.find(['/', '?', '#']).unwrap_or(text.len());
    let host = authority_host(&text[..authority_end])?;
    let rest = &text[authority_end..];
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (rest, None),
    };
    let (path, query) = match before_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (before_fragment, None),
    };
    let well_formed = encoded(path, |byte| segment_byte(byte) || byte == b'/')
        && query.is_none_or(query_escapes)
        && fragment.is_none_or(|fragment| {
            encoded(fragment, |byte| {
                segment_byte(byte) || matches!(byte, b'/' | b'?')
            })
        });
    if well_formed {
        Ok(Parts {
            host,
            query: query.is_some(),
            fragment: fragment.is_some(),
        })
    } else {
        Err(Malformed)
    }
}

/// `[ userinfo "@" ] host [ ":" port ]`.
fn authority_host(authority: &str) -> Result<&str, Malformed> {
    let host_and_port = match authority.split_once('@') {
        Some((userinfo, rest)) if encoded(userinfo, |byte| reg_name_byte(byte) || byte == b':') => {
            rest
        }
        Some(_) => return Err(Malformed),
        None => authority,
    };
    let (host, port) = if host_and_port.starts_with('[') {
        let end = host_and_port.find(']').ok_or(Malformed)? + 1;
        let (literal, rest) = host_and_port.split_at(end);
        if !ipv6address(&literal[1..end - 1]) {
            return Err(Malformed);
        }
        (literal, rest)
    } else {
        let end = host_and_port.find(':').unwrap_or(host_and_port.len());
        let (name, rest) = host_and_port.split_at(end);
        if !encoded(name, reg_name_byte) {
            return Err(Malformed);
        }
        (name, rest)
    };
    let port_well_formed = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()));
    if port_well_formed {
        Ok(host)
    } else {
        Err(Malformed)
    }
}

/// RFC 3986's `IPv6address`: eight `h16`, or fewer around one `::` that
/// stands for at least one, the last two of which may be an `IPv4address`.
fn ipv6address(text: &str) -> bool {
    match text.split_once("::") {
        None => groups(text) == Some(8),
        Some((left, right)) => {
            let left = if left.is_empty() {
                Some(0)
            } else {
                left.split(':').all(h16).then(|| left.split(':').count())
            };
            let right = if right.is_empty() {
                Some(0)
            } else {
                groups(right)
            };
            matches!((left, right), (Some(left), Some(right)) if left + right <= 7)
        }
    }
}

/// How many groups `h16 *( ":" h16 )` holds, its last piece an
/// `IPv4address` counting two.
fn groups(text: &str) -> Option<usize> {
    let pieces: Vec<&str> = text.split(':').collect();
    let (last, leading) = pieces.split_last()?;
    if !leading.iter().all(|piece| h16(piece)) {
        None
    } else if h16(last) {
        Some(pieces.len())
    } else if ipv4address(last) {
        Some(pieces.len() + 1)
    } else {
        None
    }
}

fn h16(piece: &str) -> bool {
    (1..=4).contains(&piece.len()) && piece.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `dec-octet "." dec-octet "." dec-octet "." dec-octet`.
fn ipv4address(text: &str) -> bool {
    let octets: Vec<&str> = text.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            (1..=3).contains(&octet.len())
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && !(octet.len() > 1 && octet.starts_with('0'))
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// Every byte allowed by `allowed`, or a `%` followed by two hex digits.
fn encoded(text: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if !bytes
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            index += 3;
        } else if allowed(bytes[index]) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

/// `unreserved / sub-delims`, without `:`: what `reg-name` allows besides
/// percent-encodings.
fn reg_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

/// `pchar`, without its percent-encodings.
fn segment_byte(byte: u8) -> bool {
    reg_name_byte(byte) || matches!(byte, b':' | b'@')
}

/// Ruby's grammar takes any query that has no `#`; `URI::Generic#query=`
/// then refuses one where a `%` is followed by two bytes that are not hex
/// digits, once tabs and line breaks are gone.
fn query_escapes(query: &str) -> bool {
    let bytes: Vec<u8> = query
        .bytes()
        .filter(|byte| !matches!(byte, b'\t' | b'\r' | b'\n'))
        .collect();
    !bytes.windows(3).any(|window| {
        window[0] == b'%' && !window[1].is_ascii_hexdigit() && !window[2].is_ascii_hexdigit()
    })
}
