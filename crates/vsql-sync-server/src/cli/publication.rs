use std::process;

use vsql_sync_core::config::Config;
use vsql_sync_core::publication;

pub fn run_scope_report(config: &Config, name: &str, output: Option<&str>) {
    let report = match publication::generate_scope_report(config, name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to generate scope report: {e}");
            process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&report) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: failed to serialize scope report: {e}");
            process::exit(1);
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &json) {
                eprintln!("error: failed to write scope report to {path}: {e}");
                process::exit(1);
            }
            println!("scope report written to {path}");
        }
        None => {
            println!("{json}");
        }
    }
}

pub fn run_create(config: &Config, name: &str) {
    let pub_config = match config.publications.iter().find(|p| p.name == name) {
        Some(p) => p,
        None => {
            eprintln!("error: publication '{name}' not found in config");
            process::exit(1);
        }
    };

    let sql = match publication::generate_publication_sql(pub_config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to generate publication SQL: {e}");
            process::exit(1);
        }
    };

    // Print the SQL that would be executed (actual execution requires a DB connection)
    println!("-- Publication: {name}");
    for stmt in &sql.alter_replica_identity {
        println!("{stmt};");
    }
    println!("{};", sql.create_publication);
    println!();
    println!(
        "To apply, connect to PostgreSQL and run the above statements, \
         or use vsql-sync with a live connection."
    );
}
