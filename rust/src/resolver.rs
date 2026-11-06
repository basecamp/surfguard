use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Looks a name up. The seam the gem fills with `Resolv.getaddresses`;
/// tests substitute a closure that answers as they need.
///
/// A lookup blocks the calling thread and has no deadline of its own, as
/// the gem's does not: the caller applies a deadline around the whole
/// operation, and an async caller runs it where blocking is allowed.
///
/// Any error means the host could not be resolved, and so does an empty
/// answer. The resolver is asked only for names, never for an address
/// literal or a legacy numeric spelling.
pub trait Resolver {
    /// The addresses `host` resolves to, in the resolver's order.
    ///
    /// # Errors
    ///
    /// Any failure to look the name up.
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

impl<F: Fn(&str) -> io::Result<Vec<IpAddr>>> Resolver for F {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self(host)
    }
}

/// The platform's resolver, `getaddrinfo` through [`ToSocketAddrs`]: the
/// hosts file and DNS, and whatever else the platform's name service
/// switch consults.
///
/// An answer that carries an IPv6 zone invalidates the lookup, as a zoned
/// answer does in the gem.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        (host, 0)
            .to_socket_addrs()?
            .map(|answer| match answer {
                SocketAddr::V6(answer) if answer.scope_id() != 0 => {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "zoned answer"))
                }
                answer => Ok(answer.ip()),
            })
            .collect()
    }
}
