use std::path::Path;
use std::process;

pub fn run_generate(output: &str) {
    let dir = Path::new(output);
    match vsql_sync_core::signing::write_keypair(dir) {
        Ok(_) => {
            println!("Ed25519 keypair written to {}", dir.display());
            println!(
                "  private key: {}",
                dir.join("vsql-sync-signing.key").display()
            );
            println!(
                "  public key:  {}",
                dir.join("vsql-sync-signing.pub").display()
            );
        }
        Err(e) => {
            eprintln!("error: failed to generate keypair: {e}");
            process::exit(1);
        }
    }
}
