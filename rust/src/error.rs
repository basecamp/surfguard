use std::fmt;

/// `UNRESOLVABLE_MESSAGE`.
pub const UNRESOLVABLE_MESSAGE: &str = "Host could not be resolved";
/// `BLOCKED_MESSAGE`.
pub const BLOCKED_MESSAGE: &str = "Refusing blocked address";
/// `MALFORMED_MESSAGE`.
pub const MALFORMED_MESSAGE: &str = "Refusing malformed address";

/// `Surfguard::Unresolvable`: the resolver failed, answered nothing, or
/// answered more than [`MAX_ADDRESSES`](crate::MAX_ADDRESSES). Retry later;
/// it says nothing about whether the target is allowed.
///
/// It carries nothing from the resolver, whose errors can hold
/// attacker-controlled detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unresolvable;

impl fmt::Display for Unresolvable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(UNRESOLVABLE_MESSAGE)
    }
}

impl std::error::Error for Unresolvable {}

/// `Surfguard::Violation`: the target is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Violation {
    /// An address the host resolves to, or the literal it names, is blocked.
    Blocked,
    /// The URL or its host is malformed.
    Malformed,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Violation::Blocked => BLOCKED_MESSAGE,
            Violation::Malformed => MALFORMED_MESSAGE,
        })
    }
}

impl std::error::Error for Violation {}

/// Why [`enforce_public_ip`](crate::enforce_public_ip) refused: a
/// [`Violation`] means deactivate the target, [`Unresolvable`] means retry
/// later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The target is refused.
    Violation(Violation),
    /// The host could not be resolved.
    Unresolvable(Unresolvable),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Violation(violation) => violation.fmt(formatter),
            Error::Unresolvable(unresolvable) => unresolvable.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {}

impl From<Violation> for Error {
    fn from(violation: Violation) -> Self {
        Error::Violation(violation)
    }
}

impl From<Unresolvable> for Error {
    fn from(unresolvable: Unresolvable) -> Self {
        Error::Unresolvable(unresolvable)
    }
}
