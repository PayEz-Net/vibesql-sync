use vsql_sync_core::config::*;
use vsql_sync_core::status::check_status;

fn dev_config_with_peers() -> Config {
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
        server: ServerConfig::default(),
        audit: AuditConfig::default(),
        peers: vec![
            PeerConfig {
                node_id: 2,
                node_name: "node-b".to_string(),
                connection: "host=node-b port=5432 dbname=testdb user=testuser".to_string(),
                mode: "uni-directional".to_string(),
            },
            PeerConfig {
                node_id: 3,
                node_name: "node-c".to_string(),
                connection: "host=node-c port=5432 dbname=testdb user=testuser".to_string(),
                mode: "bidirectional".to_string(),
            },
        ],
        publications: vec![
            PublicationConfig {
                name: "analytics".to_string(),
                mode: Some("uni-directional".to_string()),
                tables: vec![],
            },
        ],
    }
}

#[test]
fn status_reports_node_identity() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert_eq!(status.node_id, 1);
    assert_eq!(status.node_name, "node-a");
    assert_eq!(status.cluster_name, "test-cluster");
}

#[test]
fn status_reports_dev_mode() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert_eq!(status.mode, "dev");
    assert!(!status.tls_configured);
    assert!(!status.signing_key_configured);
}

#[test]
fn status_reports_prod_mode() {
    let config = Config {
        cluster: ClusterConfig {
            name: "prod-cluster".to_string(),
            node_id: 10,
            node_name: "node-prod".to_string(),
        },
        connection: ConnectionConfig {
            host: "db.example.com".to_string(),
            port: 5432,
            database: "vibesql".to_string(),
            user: "vsql_sync".to_string(),
        },
        server: ServerConfig {
            mode: Mode::Prod,
            listen_addr: "0.0.0.0:8444".to_string(),
            tls: Some(TlsConfig {
                cert_path: "/certs/tls.crt".to_string(),
                key_path: "/certs/tls.key".to_string(),
            }),
        },
        audit: AuditConfig {
            signing_key_path: Some("/keys/signing.key".to_string()),
            ..AuditConfig::default()
        },
        peers: vec![],
        publications: vec![],
    };
    let status = check_status(&config);
    assert_eq!(status.mode, "prod");
    assert!(status.tls_configured);
    assert!(status.signing_key_configured);
}

#[test]
fn status_reports_peers() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert_eq!(status.peers.len(), 2);
    assert_eq!(status.peers[0].node_id, 2);
    assert_eq!(status.peers[0].node_name, "node-b");
    assert_eq!(status.peers[0].mode, "uni-directional");
    assert!(status.peers[0].reachable.is_none()); // Phase 2
    assert_eq!(status.peers[1].node_id, 3);
    assert_eq!(status.peers[1].mode, "bidirectional");
}

#[test]
fn status_reports_publication_count() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert_eq!(status.publications_count, 1);
}

#[test]
fn status_clock_skew_placeholder() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert!(status.clock_skew.max_clock_skew_ms.is_none());
    assert!(status.clock_skew.clock_check_interval.is_none());
    assert!(status.clock_skew.measured_skew_ms.is_none());
}

#[test]
fn status_default_listen_addr() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert_eq!(status.listen_addr, "0.0.0.0:8444");
}

#[test]
fn status_audit_enabled_by_default() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    assert!(status.audit_enabled);
}

#[test]
fn status_serializes_to_json() {
    let config = dev_config_with_peers();
    let status = check_status(&config);
    let json = serde_json::to_string_pretty(&status).expect("should serialize");
    assert!(json.contains("\"node_id\": 1"));
    assert!(json.contains("\"mode\": \"dev\""));
    assert!(json.contains("\"cluster_name\": \"test-cluster\""));
}
