use chrono::Utc;
use serde::Serialize;

use crate::config::{ColumnSpec, Config, Mode, PublicationConfig};
use crate::error::{Result, VsqlSyncError};
use crate::signing;

/// SQL statements generated for a publication.
#[derive(Debug, Clone)]
pub struct PublicationSql {
    pub create_publication: String,
    pub alter_replica_identity: Vec<String>,
}

/// Generate the SQL to create a PostgreSQL logical replication publication.
pub fn generate_publication_sql(pub_config: &PublicationConfig) -> Result<PublicationSql> {
    if pub_config.tables.is_empty() {
        return Err(VsqlSyncError::Validation(format!(
            "publication '{}' has no tables configured",
            pub_config.name
        )));
    }

    let mut table_clauses = Vec::new();
    let mut alter_stmts = Vec::new();

    for table in &pub_config.tables {
        let clause = match &table.columns {
            ColumnSpec::All(_) => {
                // All columns — no column list needed
                table.name.clone()
            }
            ColumnSpec::List(cols) => {
                if cols.is_empty() {
                    return Err(VsqlSyncError::Validation(format!(
                        "table '{}' has an empty column list",
                        table.name
                    )));
                }
                format!("{} ({})", table.name, cols.join(", "))
            }
        };

        // Add row filter if present (PG15+)
        let clause = if let Some(ref filter) = table.row_filter {
            format!("{clause} WHERE ({filter})")
        } else {
            clause
        };

        table_clauses.push(clause);

        // QSA Finding S-4: enforce REPLICA IDENTITY using PK index for exclude_pci tables
        if table.exclude_pci {
            let default_pk = format!("{}_pkey", table.name);
            let pk = table.primary_key.as_deref().unwrap_or(&default_pk);
            alter_stmts.push(format!(
                "ALTER TABLE {} REPLICA IDENTITY USING INDEX {}",
                table.name, pk
            ));
        }
    }

    let sql = format!(
        "CREATE PUBLICATION {} FOR TABLE {}",
        pub_config.name,
        table_clauses.join(", ")
    );

    Ok(PublicationSql {
        create_publication: sql,
        alter_replica_identity: alter_stmts,
    })
}

/// A single table entry in the scope report.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeReportTable {
    pub table: String,
    pub replicated_columns: ScopeReportColumns,
    pub exclude_pci: bool,
    pub subscriber_can_contain_pci: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_filter: Option<String>,
    pub replica_identity: String,
}

/// Column info — either "all" or a specific list.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ScopeReportColumns {
    All(String),
    List(Vec<String>),
}

/// The full PCI scope reduction report.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeReport {
    pub report_type: String,
    pub publication: String,
    pub generated_at: String,
    pub mode: String,
    pub tables: Vec<ScopeReportTable>,
    pub conclusion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_warning: Option<String>,
}

/// Generate a PCI scope reduction report for QSA review.
pub fn generate_scope_report(
    config: &Config,
    publication_name: &str,
) -> Result<ScopeReport> {
    let pub_config = config
        .publications
        .iter()
        .find(|p| p.name == publication_name)
        .ok_or_else(|| {
            VsqlSyncError::Validation(format!(
                "publication '{}' not found in config",
                publication_name
            ))
        })?;

    let is_prod = config.server.mode == Mode::Prod;
    let mut any_pci_excluded = false;
    let mut all_pci_excluded = true;

    let tables: Vec<ScopeReportTable> = pub_config
        .tables
        .iter()
        .map(|t| {
            let replicated_columns = match &t.columns {
                ColumnSpec::All(_) => ScopeReportColumns::All("all".to_string()),
                ColumnSpec::List(cols) => ScopeReportColumns::List(cols.clone()),
            };

            if t.exclude_pci {
                any_pci_excluded = true;
            } else {
                all_pci_excluded = false;
            }

            let replica_identity = if t.exclude_pci {
                let default_pk = format!("{}_pkey", t.name);
                let pk = t.primary_key.as_deref().unwrap_or(&default_pk);
                format!("USING INDEX {pk}")
            } else {
                "DEFAULT".to_string()
            };

            ScopeReportTable {
                table: t.name.clone(),
                replicated_columns,
                exclude_pci: t.exclude_pci,
                subscriber_can_contain_pci: !t.exclude_pci,
                row_filter: t.row_filter.clone(),
                replica_identity,
            }
        })
        .collect();

    // No tables means nothing to check
    if tables.is_empty() {
        all_pci_excluded = false;
    }

    let conclusion = if any_pci_excluded && all_pci_excluded {
        "Subscriber receives no PCI-scoped columns. Architecturally outside CDE.".to_string()
    } else if any_pci_excluded {
        "Some tables exclude PCI columns; others do not. Subscriber is partially in PCI scope."
            .to_string()
    } else {
        "No tables have exclude_pci set. Subscriber PCI scope is unchanged.".to_string()
    };

    let generated_at = Utc::now().to_rfc3339();

    let mut report = ScopeReport {
        report_type: "pci_scope_reduction".to_string(),
        publication: publication_name.to_string(),
        generated_at,
        mode: if is_prod {
            "prod".to_string()
        } else {
            "dev".to_string()
        },
        tables,
        conclusion,
        signature: None,
        unsigned_warning: None,
    };

    // Sign in prod mode, warn in dev mode
    if is_prod {
        if let Some(ref key_path) = config.audit.signing_key_path {
            let signing_key =
                signing::load_signing_key(std::path::Path::new(key_path))?;
            let report_json = serde_json::to_string(&report)?;
            let sig = signing::sign(&signing_key, report_json.as_bytes());
            report.signature = Some(format!("ed25519:{}", hex::encode(sig.to_bytes())));
        }
    } else {
        report.unsigned_warning =
            Some("WARNING: report generated in dev mode — unsigned, not for QSA submission".to_string());
    }

    Ok(report)
}

/// Sign a scope report with the provided signing key bytes (for testing / programmatic use).
pub fn sign_scope_report(
    report: &ScopeReport,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String> {
    // Serialize without the signature field to get canonical bytes
    let mut unsigned = report.clone();
    unsigned.signature = None;
    let json = serde_json::to_string(&unsigned)?;
    let sig = signing::sign(signing_key, json.as_bytes());
    Ok(format!("ed25519:{}", hex::encode(sig.to_bytes())))
}

/// Verify a scope report signature.
pub fn verify_scope_report_signature(
    report: &ScopeReport,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    let sig_str = report.signature.as_ref().ok_or_else(|| {
        VsqlSyncError::Signing("scope report has no signature".to_string())
    })?;

    let hex_sig = sig_str.strip_prefix("ed25519:").ok_or_else(|| {
        VsqlSyncError::Signing("signature does not start with 'ed25519:'".to_string())
    })?;

    let sig_bytes = hex::decode(hex_sig)
        .map_err(|e| VsqlSyncError::Signing(format!("invalid signature hex: {e}")))?;

    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        VsqlSyncError::Signing("invalid signature length: expected 64 bytes".to_string())
    })?;

    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Verify against the report without signature
    let mut unsigned = report.clone();
    unsigned.signature = None;
    let json = serde_json::to_string(&unsigned)?;

    signing::verify(verifying_key, json.as_bytes(), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::signing::generate_keypair;

    fn test_pub_config() -> PublicationConfig {
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
            ],
        }
    }

    #[test]
    fn sql_generation_with_column_list() {
        let config = test_pub_config();
        let sql = generate_publication_sql(&config).unwrap();
        assert!(sql
            .create_publication
            .contains("payments (id, merchant_id, amount_cents)"));
        assert!(sql.create_publication.contains("merchants"));
        assert!(sql
            .create_publication
            .starts_with("CREATE PUBLICATION analytics_replica FOR TABLE"));
    }

    #[test]
    fn replica_identity_enforced_for_exclude_pci() {
        let config = test_pub_config();
        let sql = generate_publication_sql(&config).unwrap();
        assert_eq!(sql.alter_replica_identity.len(), 1);
        assert!(sql.alter_replica_identity[0]
            .contains("REPLICA IDENTITY USING INDEX payments_pkey"));
    }

    #[test]
    fn custom_primary_key_used() {
        let config = PublicationConfig {
            name: "test".to_string(),
            mode: None,
            tables: vec![TableConfig {
                name: "payments".to_string(),
                columns: ColumnSpec::List(vec!["id".to_string()]),
                exclude_pci: true,
                row_filter: None,
                primary_key: Some("payments_id_idx".to_string()),
            }],
        };
        let sql = generate_publication_sql(&config).unwrap();
        assert!(sql.alter_replica_identity[0].contains("payments_id_idx"));
    }

    #[test]
    fn row_filter_included() {
        let config = PublicationConfig {
            name: "test".to_string(),
            mode: None,
            tables: vec![TableConfig {
                name: "audit_log".to_string(),
                columns: ColumnSpec::All("all".to_string()),
                exclude_pci: false,
                row_filter: Some("log_level != 'DEBUG'".to_string()),
                primary_key: None,
            }],
        };
        let sql = generate_publication_sql(&config).unwrap();
        assert!(sql
            .create_publication
            .contains("WHERE (log_level != 'DEBUG')"));
    }

    #[test]
    fn empty_tables_rejected() {
        let config = PublicationConfig {
            name: "empty".to_string(),
            mode: None,
            tables: vec![],
        };
        assert!(generate_publication_sql(&config).is_err());
    }

    #[test]
    fn scope_report_dev_mode_unsigned() {
        let config = Config {
            cluster: ClusterConfig {
                name: "test".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "test".to_string(),
                user: "test".to_string(),
            },
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![test_pub_config()],
        };

        let report = generate_scope_report(&config, "analytics_replica").unwrap();
        assert_eq!(report.report_type, "pci_scope_reduction");
        assert_eq!(report.mode, "dev");
        assert!(report.signature.is_none());
        assert!(report.unsigned_warning.is_some());
        assert_eq!(report.tables.len(), 2);
        assert!(!report.tables[0].subscriber_can_contain_pci); // payments exclude_pci
        assert!(report.tables[1].subscriber_can_contain_pci); // merchants normal
    }

    #[test]
    fn scope_report_conclusion_partial() {
        let config = Config {
            cluster: ClusterConfig {
                name: "test".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "test".to_string(),
                user: "test".to_string(),
            },
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![test_pub_config()],
        };

        let report = generate_scope_report(&config, "analytics_replica").unwrap();
        assert!(report.conclusion.contains("partially"));
    }

    #[test]
    fn scope_report_sign_and_verify() {
        let (sk, vk) = generate_keypair();
        let config = Config {
            cluster: ClusterConfig {
                name: "test".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "test".to_string(),
                user: "test".to_string(),
            },
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![test_pub_config()],
        };

        let mut report = generate_scope_report(&config, "analytics_replica").unwrap();
        let sig = sign_scope_report(&report, &sk).unwrap();
        report.signature = Some(sig);

        verify_scope_report_signature(&report, &vk).unwrap();
    }

    #[test]
    fn scope_report_tampered_signature_fails() {
        let (sk, vk) = generate_keypair();
        let config = Config {
            cluster: ClusterConfig {
                name: "test".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "test".to_string(),
                user: "test".to_string(),
            },
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![test_pub_config()],
        };

        let mut report = generate_scope_report(&config, "analytics_replica").unwrap();
        let sig = sign_scope_report(&report, &sk).unwrap();
        report.signature = Some(sig);

        // Tamper with the report
        report.conclusion = "TAMPERED".to_string();
        assert!(verify_scope_report_signature(&report, &vk).is_err());
    }

    #[test]
    fn publication_not_found_error() {
        let config = Config {
            cluster: ClusterConfig {
                name: "test".to_string(),
                node_id: 1,
                node_name: "node-a".to_string(),
            },
            connection: ConnectionConfig {
                host: "localhost".to_string(),
                port: 5432,
                database: "test".to_string(),
                user: "test".to_string(),
            },
            server: ServerConfig::default(),
            audit: AuditConfig::default(),
            peers: vec![],
            publications: vec![],
        };

        let err = generate_scope_report(&config, "nonexistent").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
