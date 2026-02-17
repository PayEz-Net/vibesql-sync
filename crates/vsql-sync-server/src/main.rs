use std::path::PathBuf;
use std::process;

use clap::Parser;

use vsql_sync_core::config::{self, Mode};

mod cli;
mod server;

#[derive(Debug, Parser)]
#[command(name = "vsql-sync", about = "Governed replication for VibeSQL")]
struct Cli {
    #[arg(short, long, default_value = "vsql-sync.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: cli::Commands,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = match config::load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to load config: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = config::validate_config(&config) {
        eprintln!("error: config validation failed: {e}");
        process::exit(1);
    }

    if config.server.mode == Mode::Dev {
        eprintln!(
            "WARNING: running in dev mode \u{2014} audit trail is unsigned, not for production use"
        );
    }

    match cli.command {
        cli::Commands::Key(sub) => match sub {
            cli::KeyCommands::Generate { output } => {
                cli::key::run_generate(&output);
            }
        },
        cli::Commands::Publication(sub) => match sub {
            cli::PublicationCommands::Create { name } => {
                cli::publication::run_create(&config, &name);
            }
            cli::PublicationCommands::ScopeReport { name, output } => {
                cli::publication::run_scope_report(&config, &name, output.as_deref());
            }
        },
        cli::Commands::Audit(sub) => match sub {
            cli::AuditCommands::Verify => {
                println!("audit verify (not yet implemented)");
            }
            cli::AuditCommands::Export { format, output } => {
                println!("audit export: format={format} output={output} (not yet implemented)");
            }
        },
        cli::Commands::Status => {
            cli::status::run_status(&config);
        }
        cli::Commands::Serve => {
            if let Err(e) = server::run_server(&config).await {
                eprintln!("error: server failed: {e}");
                process::exit(1);
            }
        }
    }
}
