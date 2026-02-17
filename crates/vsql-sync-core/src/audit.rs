use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Result, VsqlSyncError};
use crate::merkle;
use crate::signing;

/// Mirrors the vsql_sync_audit table schema from the spec (Section 8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: String,
    pub event_type: String,
    pub event_timestamp: DateTime<Utc>,

    // Source and target
    pub source_node_id: String,
    pub target_node_id: String,

    // What was replicated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication_slot: Option<String>,
    pub batch_lsn_start: String,
    pub batch_lsn_end: String,
    pub tables_affected: Vec<String>,
    pub row_count: u64,

    // PCI scope
    pub contains_pci: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_columns: Option<Vec<String>>,

    // Encryption (Phase 3 — None in Phase 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dek_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_id: Option<String>,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    // Integrity
    #[serde(with = "hex_bytes")]
    pub merkle_root: Vec<u8>,
    #[serde(
        default,
        with = "hex_bytes_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub prev_event_hash: Option<Vec<u8>>,

    // Signature
    pub signer_node_id: String,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

fn default_algorithm() -> String {
    "AES-256-GCM".to_string()
}

/// Canonical bytes for signing/hashing. Deterministic field ordering.
fn canonical_bytes(entry: &AuditEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(entry.event_id.as_bytes());
    buf.extend_from_slice(entry.event_type.as_bytes());
    buf.extend_from_slice(entry.event_timestamp.to_rfc3339().as_bytes());
    buf.extend_from_slice(entry.source_node_id.as_bytes());
    buf.extend_from_slice(entry.target_node_id.as_bytes());
    if let Some(ref slot) = entry.replication_slot {
        buf.extend_from_slice(slot.as_bytes());
    }
    buf.extend_from_slice(entry.batch_lsn_start.as_bytes());
    buf.extend_from_slice(entry.batch_lsn_end.as_bytes());
    for t in &entry.tables_affected {
        buf.extend_from_slice(t.as_bytes());
    }
    buf.extend_from_slice(&entry.row_count.to_le_bytes());
    buf.push(entry.contains_pci as u8);
    if let Some(ref cols) = entry.pci_columns {
        for c in cols {
            buf.extend_from_slice(c.as_bytes());
        }
    }
    if let Some(ref dek) = entry.dek_id {
        buf.extend_from_slice(dek.as_bytes());
    }
    if let Some(ref kek) = entry.kek_id {
        buf.extend_from_slice(kek.as_bytes());
    }
    buf.extend_from_slice(entry.algorithm.as_bytes());
    buf.extend_from_slice(&entry.merkle_root);
    if let Some(ref prev) = entry.prev_event_hash {
        buf.extend_from_slice(prev);
    }
    buf.extend_from_slice(entry.signer_node_id.as_bytes());
    buf
}

/// Build and sign an audit entry for a replication batch.
pub fn create_signed_entry(
    event_type: &str,
    source_node_id: &str,
    target_node_id: &str,
    replication_slot: Option<&str>,
    batch_lsn_start: &str,
    batch_lsn_end: &str,
    tables_affected: Vec<String>,
    row_count: u64,
    contains_pci: bool,
    pci_columns: Option<Vec<String>>,
    tuple_data: &[Vec<u8>],
    prev_entry: Option<&AuditEntry>,
    signing_key: &SigningKey,
    signer_node_id: &str,
) -> AuditEntry {
    let merkle_root = merkle::compute_merkle_root(tuple_data);
    let prev_event_hash = prev_entry.map(|e| compute_entry_hash(e));

    let mut entry = AuditEntry {
        event_id: Uuid::new_v4().to_string(),
        event_type: event_type.to_string(),
        event_timestamp: Utc::now(),
        source_node_id: source_node_id.to_string(),
        target_node_id: target_node_id.to_string(),
        replication_slot: replication_slot.map(|s| s.to_string()),
        batch_lsn_start: batch_lsn_start.to_string(),
        batch_lsn_end: batch_lsn_end.to_string(),
        tables_affected,
        row_count,
        contains_pci,
        pci_columns,
        dek_id: None,
        kek_id: None,
        algorithm: default_algorithm(),
        merkle_root: merkle_root.to_vec(),
        prev_event_hash,
        signer_node_id: signer_node_id.to_string(),
        signature: Vec::new(), // placeholder, filled below
    };

    let sig = signing::sign(signing_key, &canonical_bytes(&entry));
    entry.signature = sig.to_bytes().to_vec();
    entry
}

/// SHA-256 of the previous entry's signature — the hash chain link.
pub fn compute_entry_hash(entry: &AuditEntry) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&entry.signature);
    hasher.finalize().to_vec()
}

/// Verify a single audit entry's Ed25519 signature.
pub fn verify_entry_signature(entry: &AuditEntry, verifying_key: &VerifyingKey) -> Result<()> {
    let sig_bytes: [u8; 64] = entry.signature.as_slice().try_into().map_err(|_| {
        VsqlSyncError::Signing(format!(
            "invalid signature length {} for event {}",
            entry.signature.len(),
            entry.event_id
        ))
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    signing::verify(verifying_key, &canonical_bytes(entry), &sig)
        .map_err(|e| VsqlSyncError::Signing(format!("event {}: {e}", entry.event_id)))
}

/// Verify the hash chain link between two consecutive entries.
pub fn verify_chain_link(current: &AuditEntry, previous: &AuditEntry) -> Result<()> {
    let expected = compute_entry_hash(previous);
    match &current.prev_event_hash {
        Some(actual) if actual == &expected => Ok(()),
        Some(actual) => Err(VsqlSyncError::Signing(format!(
            "hash chain broken at event {}: expected {} got {}",
            current.event_id,
            hex::encode(&expected),
            hex::encode(actual),
        ))),
        None => Err(VsqlSyncError::Signing(format!(
            "event {} missing prev_event_hash but has predecessor {}",
            current.event_id, previous.event_id,
        ))),
    }
}

/// Result of verifying an audit trail.
#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub total_entries: usize,
    pub valid_signatures: usize,
    pub valid_chain_links: usize,
    pub errors: Vec<String>,
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Walk an ordered audit trail and verify every signature + hash chain link.
pub fn verify_trail(entries: &[AuditEntry], verifying_key: &VerifyingKey) -> VerifyResult {
    let mut result = VerifyResult {
        total_entries: entries.len(),
        valid_signatures: 0,
        valid_chain_links: 0,
        errors: Vec::new(),
    };

    for (i, entry) in entries.iter().enumerate() {
        // Verify signature
        match verify_entry_signature(entry, verifying_key) {
            Ok(()) => result.valid_signatures += 1,
            Err(e) => result.errors.push(e.to_string()),
        }

        // Verify hash chain link (skip first entry)
        if i > 0 {
            match verify_chain_link(entry, &entries[i - 1]) {
                Ok(()) => result.valid_chain_links += 1,
                Err(e) => result.errors.push(e.to_string()),
            }
        } else {
            // First entry: prev_event_hash should be None
            if entry.prev_event_hash.is_some() {
                result
                    .errors
                    .push(format!("first event {} has prev_event_hash but should not", entry.event_id));
            }
        }
    }

    result
}

/// Export audit trail as JSON (for QSA review).
pub fn export_json(entries: &[AuditEntry]) -> Result<String> {
    serde_json::to_string_pretty(entries).map_err(VsqlSyncError::from)
}

// --- hex serde helpers ---

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_bytes_option {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_keypair;

    fn make_test_entry(
        signing_key: &SigningKey,
        prev: Option<&AuditEntry>,
    ) -> AuditEntry {
        create_signed_entry(
            "replication_batch",
            "node-a",
            "node-b",
            Some("vsql_sync_slot_node_a"),
            "0/1000000",
            "0/1000100",
            vec!["payments".to_string(), "merchants".to_string()],
            42,
            false,
            None,
            &[b"tuple-1".to_vec(), b"tuple-2".to_vec()],
            prev,
            signing_key,
            "node-a",
        )
    }

    #[test]
    fn create_and_verify_single_entry() {
        let (sk, vk) = generate_keypair();
        let entry = make_test_entry(&sk, None);
        assert!(entry.prev_event_hash.is_none());
        verify_entry_signature(&entry, &vk).expect("signature should verify");
    }

    #[test]
    fn chain_of_three_entries_verifies() {
        let (sk, vk) = generate_keypair();
        let e1 = make_test_entry(&sk, None);
        let e2 = make_test_entry(&sk, Some(&e1));
        let e3 = make_test_entry(&sk, Some(&e2));

        assert!(e1.prev_event_hash.is_none());
        assert!(e2.prev_event_hash.is_some());
        assert!(e3.prev_event_hash.is_some());

        let result = verify_trail(&[e1, e2, e3], &vk);
        assert!(result.is_valid(), "errors: {:?}", result.errors);
        assert_eq!(result.valid_signatures, 3);
        assert_eq!(result.valid_chain_links, 2);
    }

    #[test]
    fn tampered_signature_detected() {
        let (sk, vk) = generate_keypair();
        let mut entry = make_test_entry(&sk, None);
        entry.signature[0] ^= 0xff; // flip a byte
        assert!(verify_entry_signature(&entry, &vk).is_err());
    }

    #[test]
    fn broken_chain_link_detected() {
        let (sk, vk) = generate_keypair();
        let e1 = make_test_entry(&sk, None);
        let mut e2 = make_test_entry(&sk, Some(&e1));
        // Corrupt the chain link
        if let Some(ref mut h) = e2.prev_event_hash {
            h[0] ^= 0xff;
        }
        let result = verify_trail(&[e1, e2], &vk);
        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("hash chain broken")));
    }

    #[test]
    fn wrong_key_rejects() {
        let (sk, _vk) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let entry = make_test_entry(&sk, None);
        assert!(verify_entry_signature(&entry, &vk2).is_err());
    }

    #[test]
    fn json_export_roundtrip() {
        let (sk, _vk) = generate_keypair();
        let e1 = make_test_entry(&sk, None);
        let e2 = make_test_entry(&sk, Some(&e1));
        let json = export_json(&[e1.clone(), e2.clone()]).expect("export should work");
        let parsed: Vec<AuditEntry> = serde_json::from_str(&json).expect("should parse back");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].event_id, e1.event_id);
        assert_eq!(parsed[1].event_id, e2.event_id);
        // Verify signatures still valid after roundtrip
        assert_eq!(parsed[0].signature, e1.signature);
        assert_eq!(parsed[1].merkle_root, e2.merkle_root);
    }

    #[test]
    fn merkle_root_computed_from_tuple_data() {
        let (sk, _vk) = generate_keypair();
        let entry = make_test_entry(&sk, None);
        let expected = merkle::compute_merkle_root(&[b"tuple-1".to_vec(), b"tuple-2".to_vec()]);
        assert_eq!(entry.merkle_root, expected.to_vec());
    }
}
