use std::io::Write;

use vsql_sync_core::config::{self, Mode};

fn write_temp_config(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn dev_mode_without_tls_or_signing_parses_ok() {
    let toml = r#"
[cluster]
name = "test-cluster"
node_id = 1
node_name = "node-a"

[connection]
host = "localhost"
database = "testdb"
user = "testuser"

[server]
mode = "dev"
"#;
    let f = write_temp_config(toml);
    let cfg = config::load_config(f.path()).expect("should parse");
    assert_eq!(cfg.server.mode, Mode::Dev);
    assert!(cfg.server.tls.is_none());
    assert!(cfg.audit.signing_key_path.is_none());
    config::validate_config(&cfg).expect("dev mode should validate without TLS/signing");
}

#[test]
fn prod_mode_without_tls_errors() {
    let toml = r#"
[cluster]
name = "test-cluster"
node_id = 1
node_name = "node-a"

[connection]
host = "localhost"
database = "testdb"
user = "testuser"

[server]
mode = "prod"

[audit]
signing_key_path = "/path/to/key"
"#;
    let f = write_temp_config(toml);
    let cfg = config::load_config(f.path()).expect("should parse");
    let err = config::validate_config(&cfg).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("tls") || msg.contains("cert_path"),
        "expected TLS error, got: {msg}"
    );
}

#[test]
fn prod_mode_without_signing_key_errors() {
    let toml = r#"
[cluster]
name = "test-cluster"
node_id = 1
node_name = "node-a"

[connection]
host = "localhost"
database = "testdb"
user = "testuser"

[server]
mode = "prod"

[server.tls]
cert_path = "/certs/tls.crt"
key_path = "/certs/tls.key"
"#;
    let f = write_temp_config(toml);
    let cfg = config::load_config(f.path()).expect("should parse");
    let err = config::validate_config(&cfg).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("signing_key_path"),
        "expected signing key error, got: {msg}"
    );
}

#[test]
fn prod_mode_with_all_paths_parses_ok() {
    let toml = r#"
[cluster]
name = "prod-cluster"
node_id = 1
node_name = "node-a-us-east"

[connection]
host = "db.example.com"
port = 5432
database = "vibesql"
user = "vsql_sync"

[server]
mode = "prod"
listen_addr = "0.0.0.0:8444"

[server.tls]
cert_path = "/certs/tls.crt"
key_path = "/certs/tls.key"

[audit]
signing_key_path = "/etc/vsql-sync/vsql-sync-signing.key"

[[peers]]
node_id = 2
node_name = "node-b-eu-west"
connection = "host=node-b port=5432 dbname=vibesql user=vsql_sync"
mode = "uni-directional"

[[publications]]
name = "analytics_replica"
mode = "uni-directional"

[[publications.tables]]
name = "payments"
columns = ["id", "merchant_id", "amount_cents", "currency", "status", "created_at"]
exclude_pci = true

[[publications.tables]]
name = "merchants"
columns = "all"
"#;
    let f = write_temp_config(toml);
    let cfg = config::load_config(f.path()).expect("should parse");
    config::validate_config(&cfg).expect("fully specified prod config should validate");
    assert_eq!(cfg.server.mode, Mode::Prod);
    assert_eq!(cfg.cluster.name, "prod-cluster");
    assert_eq!(cfg.peers.len(), 1);
    assert_eq!(cfg.publications.len(), 1);
    assert_eq!(cfg.publications[0].tables.len(), 2);
    assert!(cfg.publications[0].tables[0].exclude_pci);
    assert!(!cfg.publications[0].tables[1].exclude_pci);
}

#[test]
fn default_mode_is_dev() {
    let toml = r#"
[cluster]
name = "test-cluster"
node_id = 1
node_name = "node-a"

[connection]
host = "localhost"
database = "testdb"
user = "testuser"
"#;
    let f = write_temp_config(toml);
    let cfg = config::load_config(f.path()).expect("should parse");
    assert_eq!(cfg.server.mode, Mode::Dev);
}
