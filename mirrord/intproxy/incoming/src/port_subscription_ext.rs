//! Utilities for handling incoming port subscriptions and listen-address resolution.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use mirrord_intproxy_protocol::PortSubscription;
use mirrord_protocol::{
    ClientMessage, Port,
    tcp::{LayerTcp, LayerTcpSteal, MIRROR_HTTP_FILTER_VERSION, MirrorType, StealType},
};
use rand::seq::IndexedRandom;

/// Retrieves subscribed port from the given [`StealType`].
fn get_port(steal_type: &StealType) -> Port {
    match steal_type {
        StealType::All(port) => *port,
        StealType::FilteredHttp(port, _) => *port,
        StealType::FilteredHttpEx(port, _) => *port,
    }
}

/// Trait for [`PortSubscription`] that handles differences in [`mirrord_protocol::tcp`] between the
/// `steal` and the `mirror` flow. Allows to unify logic for both flows.
pub trait PortSubscriptionExt {
    /// Returns the subscribed port.
    fn port(&self) -> Port;

    /// Returns a subscribe request to be sent to the agent.
    fn agent_subscribe(&self, protocol_version: Option<&semver::Version>) -> ClientMessage;

    /// Returns an unsubscribe request to be sent to the agent.
    fn wrap_agent_unsubscribe(&self) -> ClientMessage;
}

impl PortSubscriptionExt for PortSubscription {
    fn port(&self) -> Port {
        match self {
            Self::Mirror(mirror_type) => mirror_type.get_port(),
            Self::Steal(steal_type) => get_port(steal_type),
        }
    }

    /// [`LayerTcp::PortSubscribe`], [`LayerTcp::PortSubscribeFilteredHttp`], or
    /// [`LayerTcpSteal::PortSubscribe`].
    fn agent_subscribe(&self, protocol_version: Option<&semver::Version>) -> ClientMessage {
        match self {
            Self::Mirror(mirror_type) => match mirror_type {
                MirrorType::FilteredHttp(port, filter) => {
                    // Check if the agent supports filtered HTTP mirroring
                    if protocol_version
                        .is_some_and(|version| MIRROR_HTTP_FILTER_VERSION.matches(version))
                    {
                        ClientMessage::Tcp(LayerTcp::PortSubscribeFilteredHttp(
                            *port,
                            filter.clone(),
                        ))
                    } else {
                        // For older agents or when protocol version is unknown, fall back to
                        // regular mirroring without filter
                        tracing::warn!(
                            ?protocol_version,
                            "Negotiated mirrord-protocol version does not allow for using an HTTP filter when mirroring incoming traffic. \
                            The filter will be ignored."
                        );
                        ClientMessage::Tcp(LayerTcp::PortSubscribe(*port))
                    }
                }
                MirrorType::All(_) => {
                    ClientMessage::Tcp(LayerTcp::PortSubscribe(mirror_type.get_port()))
                }
            },
            Self::Steal(steal_type) => {
                ClientMessage::TcpSteal(LayerTcpSteal::PortSubscribe(steal_type.clone()))
            }
        }
    }

    /// [`LayerTcp::PortUnsubscribe`] or [`LayerTcpSteal::PortUnsubscribe`].
    fn wrap_agent_unsubscribe(&self) -> ClientMessage {
        match self {
            Self::Mirror(mirror_type) => {
                ClientMessage::Tcp(LayerTcp::PortUnsubscribe(mirror_type.get_port()))
            }
            Self::Steal(steal_type) => {
                ClientMessage::TcpSteal(LayerTcpSteal::PortUnsubscribe(get_port(steal_type)))
            }
        }
    }
}

/// Normalizes unspecified addresses (0.0.0.0, ::) to localhost for connection purposes.
///
/// This is needed because while servers can bind to unspecified addresses (meaning "listen on all
/// interfaces"), clients need a specific address to connect to. Connecting to unspecified addresses
/// can be problematic due to networking stack behavior and security policies.
fn normalize_connection_address(listen_addr: SocketAddr) -> SocketAddr {
    match listen_addr.ip() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) => {
            tracing::debug!("Converting IPv4 unspecified {} to localhost", listen_addr);
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listen_addr.port())
        }
        IpAddr::V6(Ipv6Addr::UNSPECIFIED) => {
            tracing::debug!("Converting IPv6 unspecified {} to localhost", listen_addr);
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), listen_addr.port())
        }
        _ => listen_addr,
    }
}

/// Resolves `ListeningOn` values into a connectable socket address.
pub trait ListeningOnExt {
    fn resolve_addr(&self) -> impl Future<Output = io::Result<SocketAddr>>;
}

impl ListeningOnExt for mirrord_intproxy_protocol::ListeningOn {
    async fn resolve_addr(&self) -> io::Result<SocketAddr> {
        let addr = match self {
            Self::Socket(addr) => *addr,
            Self::Hostname { host, port } => {
                let addrs = tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .collect::<Vec<_>>();
                *addrs.choose(&mut rand::rng()).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("DNS lookup for {host}:{port} returned no addresses"),
                    )
                })?
            }
        };

        Ok(normalize_connection_address(addr))
    }
}
