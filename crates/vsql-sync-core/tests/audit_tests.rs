use vsql_sync_core::audit;
use vsql_sync_core::signing;

fn make_entry(
    sk: &ed25519_dalek::SigningKey,
    prev: Option<&audit::AuditEntry>,
) -> audit::AuditEntry {
    audit::create_signed_entry(
        "replication_batch",
        "node-a",
        "node-b",
        Some("vsql_sync_slot_node_a"),
        "0/1000000",
        "0/1000100",
        vec!["payments".to_string()],
        10,
        true,
        Some(vec!["card_number".to_string()]),
        &[b"row-1".to_vec(), b"row-2".to_vec(), b"row-3".to_vec()],
        prev,
        sk,
        "node-a",
    )
}

#[test]
fn full_audit_trail_lifecycle() {
    let (sk, vk) = signing::generate_keypair();

    // Build a 5-entry chain
    let e1 = make_entry(&sk, None);
    let e2 = make_entry(&sk, Some(&e1));
    let e3 = make_entry(&sk, Some(&e2));
    let e4 = make_entry(&sk, Some(&e3));
    let e5 = make_entry(&sk, Some(&e4));

    let trail = vec![e1, e2, e3, e4, e5];

    // Verify entire trail
    let result = audit::verify_trail(&trail, &vk);
    assert!(result.is_valid(), "errors: {:?}", result.errors);
    assert_eq!(result.total_entries, 5);
    assert_eq!(result.valid_signatures, 5);
    assert_eq!(result.valid_chain_links, 4);

    // Export to JSON and re-parse
    let json = audit::export_json(&trail).expect("export should succeed");
    let parsed: Vec<audit::AuditEntry> =
        serde_json::from_str(&json).expect("should parse back");
    assert_eq!(parsed.len(), 5);

    // Verify the parsed trail still passes
    let result2 = audit::verify_trail(&parsed, &vk);
    assert!(result2.is_valid(), "errors after roundtrip: {:?}", result2.errors);
}

#[test]
fn tampered_entry_mid_chain_detected() {
    let (sk, vk) = signing::generate_keypair();

    let e1 = make_entry(&sk, None);
    let e2 = make_entry(&sk, Some(&e1));
    let mut e3 = make_entry(&sk, Some(&e2));
    let e4 = make_entry(&sk, Some(&e3));

    // Tamper with e3's row_count after signing
    e3.row_count = 999;

    let result = audit::verify_trail(&[e1, e2, e3, e4], &vk);
    assert!(!result.is_valid());
    // e3 signature is invalid, and e4's chain link to e3 may also break
    assert!(result.errors.len() >= 1);
}

#[test]
fn pci_fields_present_in_audit() {
    let (sk, _vk) = signing::generate_keypair();
    let entry = make_entry(&sk, None);
    assert!(entry.contains_pci);
    assert_eq!(
        entry.pci_columns,
        Some(vec!["card_number".to_string()])
    );
}

#[test]
fn different_event_types() {
    let (sk, vk) = signing::generate_keypair();
    let entry = audit::create_signed_entry(
        "air_gap_export",
        "node-a",
        "air-gap-target",
        None,
        "0/2000000",
        "0/2000500",
        vec!["transactions".to_string()],
        100,
        false,
        None,
        &[b"batch-data".to_vec()],
        None,
        &sk,
        "node-a",
    );
    assert_eq!(entry.event_type, "air_gap_export");
    assert!(entry.replication_slot.is_none());
    audit::verify_entry_signature(&entry, &vk).expect("should verify");
}
