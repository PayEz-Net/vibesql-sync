use vsql_sync_core::config::*;
use vsql_sync_core::publication::*;
use vsql_sync_core::signing::generate_keypair;

fn make_config(pubs: Vec<PublicationConfig>, mode: Mode) -> Config {
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
            mode,
            listen_addr: "0.0.0.0:8444".to_string(),
            tls: None,
        },
        audit: AuditConfig::default(),
        peers: vec![],
        publications: pubs,
    }
}

fn analytics_pub() -> PublicationConfig {
    PublicationConfig {
        name: "analytics_replica".to_string(),
        mode: Some("uni-directional".to_string()),
        tables: vec![
            TableConfig {
                name: "payments".to_string(),
                columns: ColumnSpec::List(vec![
                    "id".to_string(),
                    "merchant_id".to_string(),
                    "amount_cents".to_string(),
                    "currency".to_string(),
                    "status".to_string(),
                    "created_at".to_string(),
                ]),
                exclude_pci: true,
                row_filter: None,
                primary_key: None,
            },
            TableConfig {
                name: "merchants".to_string(),
                columns: ColumnSpec::All("all".to_string()),
                exclude_pci: false,
                row_filter: None,
                primary_key: None,
            },
            TableConfig {
                name: "transactions".to_string(),
                columns: ColumnSpec::List(vec![
                    "id".to_string(),
                    "merchant_id".to_string(),
                    "amount".to_string(),
                    "currency".to_string(),
                    "status".to_string(),
                    "created_at".to_string(),
                ]),
                exclude_pci: true,
                row_filter: None,
                primary_key: Some("transactions_pk".to_string()),
            },
        ],
    }
}

// --- SQL generation tests ---

#[test]
fn generates_correct_create_publication_sql() {
    let pub_config = analytics_pub();
    let sql = generate_publication_sql(&pub_config).unwrap();

    assert!(sql.create_publication.starts_with("CREATE PUBLICATION analytics_replica FOR TABLE"));
    assert!(sql.create_publication.contains("payments (id, merchant_id, amount_cents, currency, status, created_at)"));
    assert!(sql.create_publication.contains("merchants"));
    assert!(sql.create_publication.contains("transactions (id, merchant_id, amount, currency, status, created_at)"));
}

#[test]
fn generates_replica_identity_for_pci_tables() {
    let pub_config = analytics_pub();
    let sql = generate_publication_sql(&pub_config).unwrap();

    // Two tables with exclude_pci = true
    assert_eq!(sql.alter_replica_identity.len(), 2);
    assert!(sql.alter_replica_identity[0].contains("payments"));
    assert!(sql.alter_replica_identity[0].contains("payments_pkey")); // default PK name
    assert!(sql.alter_replica_identity[1].contains("transactions"));
    assert!(sql.alter_replica_identity[1].contains("transactions_pk")); // custom PK name
}

#[test]
fn row_filter_in_sql() {
    let pub_config = PublicationConfig {
        name: "filtered".to_string(),
        mode: None,
        tables: vec![TableConfig {
            name: "audit_log".to_string(),
            columns: ColumnSpec::All("all".to_string()),
            exclude_pci: false,
            row_filter: Some("log_level != 'DEBUG'".to_string()),
            primary_key: None,
        }],
    };

    let sql = generate_publication_sql(&pub_config).unwrap();
    assert!(sql.create_publication.contains("audit_log WHERE (log_level != 'DEBUG')"));
    assert!(sql.alter_replica_identity.is_empty());
}

#[test]
fn empty_tables_rejected() {
    let pub_config = PublicationConfig {
        name: "empty".to_string(),
        mode: None,
        tables: vec![],
    };
    let err = generate_publication_sql(&pub_config).unwrap_err();
    assert!(err.to_string().contains("no tables"));
}

#[test]
fn empty_column_list_rejected() {
    let pub_config = PublicationConfig {
        name: "bad".to_string(),
        mode: None,
        tables: vec![TableConfig {
            name: "t".to_string(),
            columns: ColumnSpec::List(vec![]),
            exclude_pci: false,
            row_filter: None,
            primary_key: None,
        }],
    };
    let err = generate_publication_sql(&pub_config).unwrap_err();
    assert!(err.to_string().contains("empty column list"));
}

// --- Scope report tests ---

#[test]
fn scope_report_structure() {
    let config = make_config(vec![analytics_pub()], Mode::Dev);
    let report = generate_scope_report(&config, "analytics_replica").unwrap();

    assert_eq!(report.report_type, "pci_scope_reduction");
    assert_eq!(report.publication, "analytics_replica");
    assert_eq!(report.mode, "dev");
    assert_eq!(report.tables.len(), 3);

    // payments: exclude_pci=true
    assert!(report.tables[0].exclude_pci);
    assert!(!report.tables[0].subscriber_can_contain_pci);
    assert!(report.tables[0].replica_identity.contains("payments_pkey"));

    // merchants: exclude_pci=false
    assert!(!report.tables[1].exclude_pci);
    assert!(report.tables[1].subscriber_can_contain_pci);
    assert_eq!(report.tables[1].replica_identity, "DEFAULT");
}

#[test]
fn scope_report_partial_conclusion() {
    let config = make_config(vec![analytics_pub()], Mode::Dev);
    let report = generate_scope_report(&config, "analytics_replica").unwrap();
    // Mix of exclude_pci true/false -> partial
    assert!(report.conclusion.contains("partially"));
}

#[test]
fn scope_report_all_excluded_conclusion() {
    let all_pci_pub = PublicationConfig {
        name: "safe_replica".to_string(),
        mode: Some("uni-directional".to_string()),
        tables: vec![
            TableConfig {
                name: "payments".to_string(),
                columns: ColumnSpec::List(vec!["id".to_string(), "status".to_string()]),
                exclude_pci: true,
                row_filter: None,
                primary_key: None,
            },
            TableConfig {
                name: "transactions".to_string(),
                columns: ColumnSpec::List(vec!["id".to_string(), "amount".to_string()]),
                exclude_pci: true,
                row_filter: None,
                primary_key: None,
            },
        ],
    };

    let config = make_config(vec![all_pci_pub], Mode::Dev);
    let report = generate_scope_report(&config, "safe_replica").unwrap();
    assert!(report.conclusion.contains("outside CDE"));
}

#[test]
fn scope_report_dev_mode_warning() {
    let config = make_config(vec![analytics_pub()], Mode::Dev);
    let report = generate_scope_report(&config, "analytics_replica").unwrap();
    assert!(report.signature.is_none());
    assert!(report.unsigned_warning.is_some());
    assert!(report.unsigned_warning.as_ref().unwrap().contains("dev mode"));
}

#[test]
fn scope_report_not_found() {
    let config = make_config(vec![], Mode::Dev);
    let err = generate_scope_report(&config, "nonexistent").unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn scope_report_sign_verify_roundtrip() {
    let (sk, vk) = generate_keypair();
    let config = make_config(vec![analytics_pub()], Mode::Dev);

    let mut report = generate_scope_report(&config, "analytics_replica").unwrap();
    let sig = sign_scope_report(&report, &sk).unwrap();
    report.signature = Some(sig);

    // Verify passes
    verify_scope_report_signature(&report, &vk).unwrap();
}

#[test]
fn scope_report_tampered_content_fails_verification() {
    let (sk, vk) = generate_keypair();
    let config = make_config(vec![analytics_pub()], Mode::Dev);

    let mut report = generate_scope_report(&config, "analytics_replica").unwrap();
    let sig = sign_scope_report(&report, &sk).unwrap();
    report.signature = Some(sig);

    // Tamper
    report.tables[0].exclude_pci = false;
    assert!(verify_scope_report_signature(&report, &vk).is_err());
}

#[test]
fn scope_report_wrong_key_fails_verification() {
    let (sk, _vk) = generate_keypair();
    let (_sk2, vk2) = generate_keypair();
    let config = make_config(vec![analytics_pub()], Mode::Dev);

    let mut report = generate_scope_report(&config, "analytics_replica").unwrap();
    let sig = sign_scope_report(&report, &sk).unwrap();
    report.signature = Some(sig);

    assert!(verify_scope_report_signature(&report, &vk2).is_err());
}

#[test]
fn scope_report_json_serialization() {
    let config = make_config(vec![analytics_pub()], Mode::Dev);
    let report = generate_scope_report(&config, "analytics_replica").unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();

    // Should contain expected fields
    assert!(json.contains("pci_scope_reduction"));
    assert!(json.contains("analytics_replica"));
    assert!(json.contains("payments"));
    assert!(json.contains("exclude_pci"));
    assert!(json.contains("subscriber_can_contain_pci"));
}
