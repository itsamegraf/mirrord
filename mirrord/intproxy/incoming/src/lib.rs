//! Reusable runtime helpers for mirrord's incoming-traffic support.
//!
//! This crate contains the state and transport helpers shared by the intproxy incoming flow and
//! future remote/serverless incoming adapters.

pub mod bound_socket;
pub mod error;
pub mod http;
pub mod metadata_store;
pub mod port_subscription_ext;
pub mod remote_resources;
pub mod subscriptions;
pub mod tasks;
pub mod tls;

pub use bound_socket::BoundTcpSocket;
pub use error::IncomingProxyError;
pub use http::{
    ClientStore, LocalHttpClient, LocalHttpError, ResponseMode, StreamingBody,
    mirrord_error_response,
};
pub use metadata_store::MetadataStore;
pub use port_subscription_ext::ListeningOnExt;
pub use subscriptions::{SubscriptionsManager, ToLayer};
pub use tasks::{HttpGatewayId, HttpOut, InProxyTask, InProxyTaskError, InProxyTaskMessage};
pub use tls::{LocalTlsSetup, LocalTlsSetupError};
