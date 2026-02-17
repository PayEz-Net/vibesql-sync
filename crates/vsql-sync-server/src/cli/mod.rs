pub mod key;
pub mod publication;
pub mod status;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(subcommand)]
    Key(KeyCommands),
    #[command(subcommand)]
    Publication(PublicationCommands),
    #[command(subcommand)]
    Audit(AuditCommands),
    /// Show node status summary
    Status,
    /// Start the health endpoint server
    Serve,
}

#[derive(Debug, Subcommand)]
pub enum KeyCommands {
    Generate {
        #[arg(long)]
        output: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PublicationCommands {
    Create {
        name: String,
    },
    ScopeReport {
        name: String,
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuditCommands {
    Verify,
    Export {
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        output: String,
    },
}
