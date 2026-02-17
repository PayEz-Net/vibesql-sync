use serde::Serialize;

use crate::config::{Config, Mode};

/// Status of a configured peer.
#[derive(Debug, Clone, Serialize)]
pub struct PeerStatus {
    pub node_id: u32,
    pub node_name: String,
    pub mode: String,
    /// Placeholder for Phase 2 — actual connectivity check requires a live connection.
    pub reachable: Option<bool>,
}

/// Clock skew monitoring configuration (Phase 2 will add actual NTP checks).
#[derive(Debug, Clone, Serialize)]
pub struct ClockSkewStatus {
    pub max_clock_skew_ms: Option<u64>,
    pub clock_check_interval: Option<String>,
    /// Placeholder — actual skew measurement is Phase 2.
    pub measured_skew_ms: Option<i64>,
}

/// Summary status for a vsql-sync node.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: u32,
    pub node_name: String,
    pub cluster_name: String,
    pub mode: String,
    pub listen_addr: String,
    pub tls_configured: bool,
    pub signing_key_configured: bool,
    pub audit_enabled: bool,
    pub peers: Vec<PeerStatus>,
    pub publications_count: usize,
    pub clock_skew: ClockSkewStatus,
}

/// Build a `NodeStatus` from the loaded config.
/// Phase 1: reports config summary, peer list, signing key presence.
/// Phase 2 will add live connectivity checks, NTP skew measurement, replication slot status.
pub fn check_status(config: &Config) -> NodeStatus {
    let mode_str = match config.server.mode {
        Mode::Dev => "dev",
        Mode::Prod => "prod",
    };

    let peers: Vec<PeerStatus> = config
        .peers
        .iter()
        .map(|p| PeerStatus {
            node_id: p.node_id,
            node_name: p.node_name.clone(),
            mode: p.mode.clone(),
            reachable: None, // Phase 2
        })
        .collect();

    NodeStatus {
        node_id: config.cluster.node_id,
        node_name: config.cluster.node_name.clone(),
        cluster_name: config.cluster.name.clone(),
        mode: mode_str.to_string(),
        listen_addr: config.server.listen_addr.clone(),
        tls_configured: config.server.tls.is_some(),
        signing_key_configured: config.audit.signing_key_path.is_some(),
        audit_enabled: config.audit.enabled,
        peers,
        publications_count: config.publications.len(),
        clock_skew: ClockSkewStatus {
            max_clock_skew_ms: None,  // parsed from [conflict] when available
            clock_check_interval: None,
            measured_skew_ms: None,   // Phase 2
        },
    }
}
