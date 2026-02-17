use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;

use vsql_sync_core::config::{Config, Mode};

#[derive(Clone)]
struct AppState {
    node_id: u32,
    mode: String,
}

#[derive(Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub node_id: u32,
    pub mode: String,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        node_id: state.node_id,
        mode: state.mode.clone(),
    })
}

fn build_router(config: &Config) -> Router {
    let mode_str = match config.server.mode {
        Mode::Dev => "dev",
        Mode::Prod => "prod",
    };

    let state = AppState {
        node_id: config.cluster.node_id,
        mode: mode_str.to_string(),
    };

    Router::new()
        .route("/health", get(health))
        .with_state(state)
}

/// Start the health endpoint server. In prod mode, binds with TLS. In dev mode, plain HTTP.
pub async fn run_server(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(config);
    let addr: SocketAddr = config.server.listen_addr.parse()?;

    match config.server.mode {
        Mode::Prod => {
            let tls = config
                .server
                .tls
                .as_ref()
                .expect("prod mode requires TLS config (should be caught by validation)");

            let cert_pem = tokio::fs::read(&tls.cert_path).await?;
            let key_pem = tokio::fs::read(&tls.key_path).await?;

            let certs = rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut &key_pem[..])?
                .ok_or("no private key found in key file")?;

            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?;

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
            let listener = TcpListener::bind(addr).await?;

            eprintln!("vsql-sync health endpoint listening on https://{addr}");

            loop {
                let (stream, _remote_addr) = listener.accept().await?;
                let acceptor = tls_acceptor.clone();
                let tower_service = app.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            let hyper_service =
                                hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                    let svc = tower_service.clone();
                                    async move {
                                        use tower::ServiceExt;
                                        // Router error type is Infallible, so unwrap is safe
                                        let resp = svc.oneshot(request).await.unwrap();
                                        Ok::<_, std::convert::Infallible>(resp)
                                    }
                                });
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, hyper_service)
                            .await
                            {
                                eprintln!("TLS connection error: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("TLS accept error: {e}");
                        }
                    }
                });
            }
        }
        Mode::Dev => {
            eprintln!("vsql-sync health endpoint listening on http://{addr} (dev mode, no TLS)");
            let listener = TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vsql_sync_core::config::*;

    fn test_dev_config() -> Config {
        Config {
            cluster: ClusterConfig {
                name: "test-cluster".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "testdb".to_string(),
                user: "testuser".to_string(),
            },
            server: ServerConfig {
                mode: Mode::Dev,
                listen_addr: "127.0.0.1:0".to_string(),
                tls: None,
            },
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![],
        }
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let config = test_dev_config();
        let app = build_router(&config);

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(health.status, "ok");
        assert_eq!(health.node_id, 1);
        assert_eq!(health.mode, "dev");
    }

    #[tokio::test]
    async fn health_endpoint_404_on_unknown_path() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let config = test_dev_config();
        let app = build_router(&config);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
