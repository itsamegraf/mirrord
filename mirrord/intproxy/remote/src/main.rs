use std::{env, net::SocketAddr};

use mirrord_intproxy::remote::{RemoteIntProxy, RemoteProxyConfig};

#[tokio::main]
async fn main() {
    init_tracing();

    let listen_address = read_socket_addr("MIRRORD_REMOTE_LISTEN_ADDR", "127.0.0.1:7777");
    let sidecar_address = read_socket_addr("MIRRORD_REMOTE_SIDECAR_ADDR", "127.0.0.1:7778");

    let config = RemoteProxyConfig::new(listen_address, sidecar_address);
    if let Err(error) = async {
        let proxy = RemoteIntProxy::new(config).await?;
        proxy.run().await
    }
    .await
    {
        tracing::error!(%error, "intproxy-remote exited with an error");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .with_ansi(false)
        .try_init();
}

fn read_socket_addr(name: &str, default: &str) -> SocketAddr {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .unwrap_or_else(|error| panic!("failed to parse {name}: {error}"))
}
