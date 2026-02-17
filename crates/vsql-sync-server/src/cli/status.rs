use vsql_sync_core::config::Config;
use vsql_sync_core::status::check_status;

pub fn run_status(config: &Config) {
    let status = check_status(config);

    println!("vsql-sync status");
    println!("================");
    println!("Cluster:    {}", status.cluster_name);
    println!("Node:       {} (id={})", status.node_name, status.node_id);
    println!("Mode:       {}", status.mode);
    println!("Listen:     {}", status.listen_addr);
    println!("TLS:        {}", if status.tls_configured { "configured" } else { "not configured" });
    println!("Signing:    {}", if status.signing_key_configured { "configured" } else { "not configured" });
    println!("Audit:      {}", if status.audit_enabled { "enabled" } else { "disabled" });
    println!("Publications: {}", status.publications_count);

    println!();
    if status.peers.is_empty() {
        println!("Peers: (none)");
    } else {
        println!("Peers:");
        for peer in &status.peers {
            let reachable = match peer.reachable {
                Some(true) => "reachable",
                Some(false) => "unreachable",
                None => "unknown",
            };
            println!(
                "  - {} (id={}) mode={} status={}",
                peer.node_name, peer.node_id, peer.mode, reachable
            );
        }
    }

    println!();
    println!("Clock skew monitoring:");
    match status.clock_skew.max_clock_skew_ms {
        Some(ms) => println!("  max_clock_skew_ms: {}ms", ms),
        None => println!("  max_clock_skew_ms: (not configured)"),
    }
    match &status.clock_skew.clock_check_interval {
        Some(interval) => println!("  check_interval:    {}", interval),
        None => println!("  check_interval:    (not configured)"),
    }
    match status.clock_skew.measured_skew_ms {
        Some(ms) => println!("  measured_skew:     {}ms", ms),
        None => println!("  measured_skew:     (Phase 2 — not yet measured)"),
    }
}
