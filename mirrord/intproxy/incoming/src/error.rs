use std::io;

use mirrord_protocol::ResponseError;
use semver::Version;
use thiserror::Error;

/// Errors that can occur in the reusable incoming runtime helpers.
#[derive(Error, Debug)]
pub enum IncomingProxyError {
    #[error("failed to prepare a TCP socket: {0}")]
    SocketSetupFailed(#[source] io::Error),
    #[error("subscribing port failed: {0}")]
    SubscriptionFailed(#[source] ResponseError),

    #[error("HTTP method filter is not supported for this protocol version {0:?}!")]
    HttpMethodFilterNotSupported(Option<Version>),
}
