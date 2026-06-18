use std::{collections::HashMap, io, net::SocketAddr, time::Duration};

use mirrord_intproxy_protocol::{
    LayerId, LayerToProxyMessage, LocalMessage, ProxyToLayerMessage, codec::CodecError,
};
use mirrord_protocol::{
    CLIENT_READY_FOR_LOGS, ClientMessage, DaemonMessage, LogLevel, LogMessage, VERSION,
};
use mirrord_protocol_io::{Client, TxHandle};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::{
    agent_conn::{AgentConnection, AgentConnectionError, AgentConnectionTaskError},
    background_tasks::{BackgroundTasks, TaskError, TaskSender, TaskUpdate},
    layer_conn::LayerConnection,
    layer_initializer::{LayerInitializer, LayerInitializerError},
    main_tasks::{LayerClosed, LayerForked, ProxyMessage},
    proxies::incoming::{IncomingProxy, IncomingProxyError, IncomingProxyMessage},
    session_monitor::MonitorTx,
};

/// Configuration for the incoming-only remote proxy host.
#[derive(Debug, Clone)]
pub struct RemoteProxyConfig {
    pub listen_address: SocketAddr,
    pub sidecar_address: SocketAddr,
    pub idle_local_http_connection_timeout: Duration,
}

impl RemoteProxyConfig {
    pub fn new(listen_address: SocketAddr, sidecar_address: SocketAddr) -> Self {
        Self {
            listen_address,
            sidecar_address,
            idle_local_http_connection_timeout: Duration::from_secs(30),
        }
    }
}

/// Errors that can occur while running the incoming-only remote proxy.
#[derive(Debug, Error)]
pub enum RemoteProxyError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("failed to accept a layer connection: {0}")]
    LayerInitializer(#[from] LayerInitializerError),
    #[error("layer connection failed: {0}")]
    LayerConnection(#[from] CodecError),
    #[error("incoming proxy failed: {0}")]
    IncomingProxy(#[from] IncomingProxyError),
    #[error("sidecar connection failed: {0}")]
    SidecarConnection(#[from] AgentConnectionError),
    #[error("sidecar task failed: {0}")]
    SidecarTask(#[from] AgentConnectionTaskError),
    #[error("unsupported layer message: {0:?}")]
    UnsupportedLayerMessage(LayerToProxyMessage),
    #[error("agent closed connection with error: {0}")]
    AgentFailed(String),
    #[error("background task {0} exited unexpectedly")]
    TaskExit(RemoteTaskId),
    #[error("background task {0} panicked")]
    TaskPanic(RemoteTaskId),
}

/// Background task identifiers used by [`RemoteIntProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteTaskId {
    LayerInitializer,
    AgentConnection,
    IncomingProxy,
    LayerConnection(LayerId),
}

impl std::fmt::Display for RemoteTaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LayerInitializer => f.write_str("REMOTE_LAYER_INITIALIZER"),
            Self::AgentConnection => f.write_str("REMOTE_AGENT_CONNECTION"),
            Self::IncomingProxy => f.write_str("REMOTE_INCOMING_PROXY"),
            Self::LayerConnection(id) => write!(f, "REMOTE_LAYER_CONNECTION_{}", id.0),
        }
    }
}

struct TaskTxs {
    layers: HashMap<LayerId, TaskSender<LayerConnection>>,
    _layer_initializer: TaskSender<LayerInitializer>,
    _agent: TaskSender<AgentConnection>,
    incoming: TaskSender<IncomingProxy>,
}

/// Incoming-only remote proxy host.
pub struct RemoteIntProxy {
    background_tasks: BackgroundTasks<RemoteTaskId, ProxyMessage, RemoteProxyError>,
    task_txs: TaskTxs,
    agent_tx: TxHandle<Client>,
    protocol_version: Option<semver::Version>,
}

impl RemoteIntProxy {
    const CHANNEL_SIZE: usize = 512;

    pub async fn new(config: RemoteProxyConfig) -> Result<Self, RemoteProxyError> {
        let agent_conn = connect_sidecar(config.sidecar_address).await?;
        let agent_tx = agent_conn.connection.tx_handle();

        let mut background_tasks = BackgroundTasks::new(agent_tx.another());
        background_tasks.suspend_messages(RemoteTaskId::LayerInitializer);

        let layer_listener = TcpListener::bind(config.listen_address).await?;
        let layer_initializer = background_tasks.register(
            LayerInitializer::new(layer_listener),
            RemoteTaskId::LayerInitializer,
            Self::CHANNEL_SIZE,
        );

        let incoming = background_tasks.register(
            IncomingProxy::new(
                config.idle_local_http_connection_timeout,
                Default::default(),
                MonitorTx::disabled(),
            ),
            RemoteTaskId::IncomingProxy,
            Self::CHANNEL_SIZE,
        );

        let agent = background_tasks.register(
            agent_conn,
            RemoteTaskId::AgentConnection,
            Self::CHANNEL_SIZE,
        );

        Ok(Self {
            background_tasks,
            task_txs: TaskTxs {
                layers: HashMap::new(),
                _layer_initializer: layer_initializer,
                _agent: agent,
                incoming,
            },
            agent_tx,
            protocol_version: None,
        })
    }

    pub async fn run(mut self) -> Result<(), RemoteProxyError> {
        while let Some((task_id, task_update)) = self.background_tasks.next().await {
            self.handle_task_update(task_id, task_update).await?;
        }

        Ok(())
    }

    async fn handle_task_update(
        &mut self,
        task_id: RemoteTaskId,
        update: TaskUpdate<ProxyMessage, RemoteProxyError>,
    ) -> Result<(), RemoteProxyError> {
        match (task_id, update) {
            (RemoteTaskId::LayerConnection(layer_id), TaskUpdate::Finished(result)) => {
                match result {
                    Ok(()) => tracing::info!(layer_id = layer_id.0, "layer connection closed"),
                    Err(TaskError::Error(error)) => {
                        tracing::warn!(layer_id = layer_id.0, %error, "layer connection failed");
                    }
                    Err(TaskError::Panic) => {
                        tracing::error!(layer_id = layer_id.0, "layer connection panicked");
                    }
                }

                self.task_txs.layers.remove(&layer_id);
                self.task_txs
                    .incoming
                    .send(IncomingProxyMessage::LayerClosed(LayerClosed {
                        id: layer_id,
                    }))
                    .await;
            }
            (RemoteTaskId::LayerInitializer, TaskUpdate::Finished(result)) => match result {
                Ok(()) => return Err(RemoteProxyError::TaskExit(RemoteTaskId::LayerInitializer)),
                Err(TaskError::Error(error)) => return Err(error),
                Err(TaskError::Panic) => {
                    return Err(RemoteProxyError::TaskPanic(RemoteTaskId::LayerInitializer));
                }
            },
            (RemoteTaskId::IncomingProxy, TaskUpdate::Finished(result)) => match result {
                Ok(()) => return Err(RemoteProxyError::TaskExit(RemoteTaskId::IncomingProxy)),
                Err(TaskError::Error(error)) => return Err(error),
                Err(TaskError::Panic) => {
                    return Err(RemoteProxyError::TaskPanic(RemoteTaskId::IncomingProxy));
                }
            },
            (RemoteTaskId::AgentConnection, TaskUpdate::Finished(result)) => match result {
                Ok(()) => return Err(RemoteProxyError::TaskExit(RemoteTaskId::AgentConnection)),
                Err(TaskError::Error(error)) => return Err(error),
                Err(TaskError::Panic) => {
                    return Err(RemoteProxyError::TaskPanic(RemoteTaskId::AgentConnection));
                }
            },
            (_, TaskUpdate::Message(msg)) => self.handle(msg).await?,
        }

        Ok(())
    }

    async fn handle(&mut self, msg: ProxyMessage) -> Result<(), RemoteProxyError> {
        match msg {
            ProxyMessage::NewLayer(new_layer) => {
                let tx = self.background_tasks.register(
                    LayerConnection::new(new_layer.stream, new_layer.id),
                    RemoteTaskId::LayerConnection(new_layer.id),
                    Self::CHANNEL_SIZE,
                );
                self.task_txs.layers.insert(new_layer.id, tx);

                if let Some(parent_id) = new_layer.parent_id {
                    self.task_txs
                        .incoming
                        .send(IncomingProxyMessage::LayerForked(LayerForked {
                            child: new_layer.id,
                            parent: parent_id,
                        }))
                        .await;
                }
            }
            ProxyMessage::FromLayer(msg) => {
                let layer_id = msg.layer_id;
                let response = match msg.message {
                    LayerToProxyMessage::Incoming(req) => {
                        self.task_txs
                            .incoming
                            .send(IncomingProxyMessage::LayerRequest(
                                msg.message_id,
                                layer_id,
                                req,
                            ))
                            .await;
                        None
                    }
                    other => Some(unsupported_layer_message_response(msg.message_id, other)),
                };

                if let Some(response) = response
                    && let Some(tx) = self.task_txs.layers.get(&layer_id)
                {
                    tx.send(response).await;
                }
            }
            ProxyMessage::ToLayer(msg) => {
                if let Some(tx) = self.task_txs.layers.get(&msg.layer_id) {
                    tx.send(LocalMessage {
                        message_id: msg.message_id,
                        inner: msg.message,
                    })
                    .await;
                }
            }
            ProxyMessage::FromAgent(msg) => self.handle_agent_message(msg).await?,
            ProxyMessage::ConnectionRefresh(_) => {
                return Err(RemoteProxyError::AgentFailed(
                    "connection refresh is not supported by intproxy-remote".to_owned(),
                ));
            }
        }

        Ok(())
    }

    async fn handle_agent_message(
        &mut self,
        message: DaemonMessage,
    ) -> Result<(), RemoteProxyError> {
        match message {
            DaemonMessage::SwitchProtocolVersionResponse(version) => {
                let previous = self.protocol_version.replace(version.clone());
                if previous.is_none() {
                    self.background_tasks
                        .resume_messages(RemoteTaskId::LayerInitializer);
                }

                if CLIENT_READY_FOR_LOGS.matches(&version) {
                    self.agent_tx.send(ClientMessage::ReadyForLogs).await;
                }

                self.task_txs
                    .incoming
                    .send(IncomingProxyMessage::AgentProtocolVersion(version))
                    .await;
            }
            DaemonMessage::Tcp(msg) => {
                self.task_txs
                    .incoming
                    .send(IncomingProxyMessage::AgentMirror(msg))
                    .await;
            }
            DaemonMessage::TcpSteal(msg) => {
                self.task_txs
                    .incoming
                    .send(IncomingProxyMessage::AgentSteal(msg))
                    .await;
            }
            DaemonMessage::Close(reason) => return Err(RemoteProxyError::AgentFailed(reason)),
            DaemonMessage::LogMessage(LogMessage { level, message }) => match level {
                LogLevel::Error => {
                    tracing::error!(message = %message, "received a log message from the sidecar")
                }
                LogLevel::Warn => {
                    tracing::warn!(message = %message, "received a log message from the sidecar")
                }
                LogLevel::Info => {
                    tracing::info!(message = %message, "received a log message from the sidecar")
                }
            },
            DaemonMessage::Pong => {
                tracing::trace!("received an unexpected pong from the sidecar");
            }
            other => {
                tracing::warn!(message = ?other, "ignoring unsupported sidecar message");
            }
        }

        Ok(())
    }
}

async fn connect_sidecar(sidecar_address: SocketAddr) -> Result<AgentConnection, RemoteProxyError> {
    let mut connection = AgentConnection::new_for_raw_address(sidecar_address).await?;

    connection.connection.send(ClientMessage::Ping).await;
    loop {
        match connection.connection.recv().await {
            Some(DaemonMessage::Pong) => break,
            Some(DaemonMessage::Close(reason)) => {
                return Err(RemoteProxyError::AgentFailed(reason));
            }
            Some(DaemonMessage::LogMessage(LogMessage { level, message })) => match level {
                LogLevel::Error => {
                    tracing::error!(message = %message, "received a log message from the sidecar during handshake")
                }
                LogLevel::Warn => {
                    tracing::warn!(message = %message, "received a log message from the sidecar during handshake")
                }
                LogLevel::Info => {
                    tracing::info!(message = %message, "received a log message from the sidecar during handshake")
                }
            },
            Some(DaemonMessage::OperatorPing(id)) => {
                connection
                    .connection
                    .send(ClientMessage::OperatorPong(id))
                    .await;
            }
            Some(other) => {
                tracing::debug!(message = ?other, "ignoring non-handshake sidecar message while waiting for pong");
            }
            None => {
                return Err(RemoteProxyError::AgentFailed(
                    "sidecar closed connection during handshake".to_owned(),
                ));
            }
        }
    }

    connection
        .connection
        .send(ClientMessage::SwitchProtocolVersion(VERSION.clone()))
        .await;

    Ok(connection)
}

fn unsupported_layer_message_response(
    message_id: u64,
    message: LayerToProxyMessage,
) -> LocalMessage<ProxyToLayerMessage> {
    let unsupported = RemoteProxyError::UnsupportedLayerMessage(message);
    LocalMessage {
        message_id,
        inner: ProxyToLayerMessage::ProxyFailed(format!(
            "intproxy-remote only supports incoming traffic: {unsupported}"
        )),
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use mirrord_intproxy_protocol::{
        IncomingRequest, LayerToProxyMessage, PortSubscribe, PortSubscription,
    };
    use mirrord_protocol::{GetEnvVarsRequest, tcp::StealType};

    use super::{ProxyToLayerMessage, unsupported_layer_message_response};

    #[test]
    fn unsupported_message_responds_with_proxy_failed() {
        let response = unsupported_layer_message_response(
            7,
            LayerToProxyMessage::GetEnv(GetEnvVarsRequest {
                env_vars_filter: HashSet::new(),
                env_vars_select: HashSet::new(),
            }),
        );

        assert_eq!(response.message_id, 7);
        assert!(matches!(
            response.inner,
            ProxyToLayerMessage::ProxyFailed(_)
        ));
    }

    #[test]
    fn incoming_message_is_still_classified_as_supported() {
        let msg = LayerToProxyMessage::Incoming(IncomingRequest::PortSubscribe(PortSubscribe {
            listening_on: "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            subscription: PortSubscription::Steal(StealType::All(80)),
        }));

        match msg {
            LayerToProxyMessage::Incoming(_) => {}
            _ => panic!("incoming message should be supported"),
        }
    }
}
