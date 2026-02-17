use serde::Deserialize;
use std::path::Path;

use crate::error::{Result, VsqlSyncError};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Dev,
    Prod,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub cluster: ClusterConfig,
    pub connection: ConnectionConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub publications: Vec<PublicationConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    pub node_id: u32,
    pub node_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub database: String,
    pub user: String,
}

fn default_port() -> u16 {
    5432
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub tls: Option<TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            listen_addr: default_listen_addr(),
            tls: None,
        }
    }
}

fn default_listen_addr() -> String {
    "0.0.0.0:8444".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub hash_chain: bool,
    #[serde(default = "default_true")]
    pub merkle_roots: bool,
    #[serde(default = "default_signature_algorithm")]
    pub signature_algorithm: String,
    pub signing_key_path: Option<String>,
    #[serde(default = "default_audit_table")]
    pub audit_table: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hash_chain: true,
            merkle_roots: true,
            signature_algorithm: default_signature_algorithm(),
            signing_key_path: None,
            audit_table: default_audit_table(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_signature_algorithm() -> String {
    "ed25519".to_string()
}

fn default_audit_table() -> String {
    "vsql_sync_audit".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub node_id: u32,
    pub node_name: String,
    pub connection: String,
    #[serde(default = "default_peer_mode")]
    pub mode: String,
}

fn default_peer_mode() -> String {
    "uni-directional".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicationConfig {
    pub name: String,
    #[serde(default = "default_pub_mode")]
    pub mode: Option<String>,
    #[serde(default)]
    pub tables: Vec<TableConfig>,
}

fn default_pub_mode() -> Option<String> {
    Some("uni-directional".to_string())
}

#[derive(Debug, Clone, Deserialize)]
pub struct TableConfig {
    pub name: String,
    #[serde(default)]
    pub columns: ColumnSpec,
    #[serde(default)]
    pub exclude_pci: bool,
    pub row_filter: Option<String>,
    pub primary_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ColumnSpec {
    All(String),
    List(Vec<String>),
}

impl Default for ColumnSpec {
    fn default() -> Self {
        ColumnSpec::All("all".to_string())
    }
}

impl ColumnSpec {
    pub fn is_all(&self) -> bool {
        matches!(self, ColumnSpec::All(s) if s == "all")
    }
}

pub fn load_config(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn validate_config(config: &Config) -> Result<()> {
    if config.server.mode == Mode::Prod {
        match &config.server.tls {
            None => {
                return Err(VsqlSyncError::Validation(
                    "prod mode requires [server.tls] with cert_path and key_path".to_string(),
                ));
            }
            Some(tls) => {
                if tls.cert_path.is_empty() {
                    return Err(VsqlSyncError::Validation(
                        "prod mode requires server.tls.cert_path".to_string(),
                    ));
                }
                if tls.key_path.is_empty() {
                    return Err(VsqlSyncError::Validation(
                        "prod mode requires server.tls.key_path".to_string(),
                    ));
                }
            }
        }

        if config.audit.signing_key_path.is_none() {
            return Err(VsqlSyncError::Validation(
                "prod mode requires audit.signing_key_path".to_string(),
            ));
        }
        if let Some(ref p) = config.audit.signing_key_path {
            if p.is_empty() {
                return Err(VsqlSyncError::Validation(
                    "prod mode requires a non-empty audit.signing_key_path".to_string(),
                ));
            }
        }
    }

    Ok(())
}
