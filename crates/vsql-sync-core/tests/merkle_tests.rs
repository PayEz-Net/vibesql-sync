use sha2::{Digest, Sha256};
use vsql_sync_core::merkle;

#[test]
fn empty_leaves_returns_zero_hash() {
    let root = merkle::compute_merkle_root(&[]);
    assert_eq!(root, [0u8; 32]);
}

#[test]
fn single_leaf_returns_hash_of_leaf() {
    let leaf = b"single leaf".to_vec();
    let root = merkle::compute_merkle_root(&[leaf.clone()]);

    // Single leaf: the while loop doesn't execute, so root = H(leaf)
    let expected: [u8; 32] = Sha256::digest(&leaf).into();

    assert_eq!(root, expected);
}

#[test]
fn two_leaves_known_hash() {
    let a = b"leaf-a".to_vec();
    let b = b"leaf-b".to_vec();
    let root = merkle::compute_merkle_root(&[a.clone(), b.clone()]);

    let ha: [u8; 32] = Sha256::digest(&a).into();
    let hb: [u8; 32] = Sha256::digest(&b).into();

    let mut hasher = Sha256::new();
    hasher.update(ha);
    hasher.update(hb);
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(root, expected);
}

#[test]
fn three_leaves_odd_duplication() {
    let a = b"a".to_vec();
    let b_data = b"b".to_vec();
    let c = b"c".to_vec();
    let root = merkle::compute_merkle_root(&[a.clone(), b_data.clone(), c.clone()]);

    let ha: [u8; 32] = Sha256::digest(&a).into();
    let hb: [u8; 32] = Sha256::digest(&b_data).into();
    let hc: [u8; 32] = Sha256::digest(&c).into();

    let mut h_ab = Sha256::new();
    h_ab.update(ha);
    h_ab.update(hb);
    let hab: [u8; 32] = h_ab.finalize().into();

    let mut h_cc = Sha256::new();
    h_cc.update(hc);
    h_cc.update(hc);
    let hcc: [u8; 32] = h_cc.finalize().into();

    let mut h_root = Sha256::new();
    h_root.update(hab);
    h_root.update(hcc);
    let expected: [u8; 32] = h_root.finalize().into();

    assert_eq!(root, expected);
}

#[test]
fn deterministic_same_input_same_output() {
    let leaves: Vec<Vec<u8>> = (0..10).map(|i| format!("leaf-{i}").into_bytes()).collect();
    let root1 = merkle::compute_merkle_root(&leaves);
    let root2 = merkle::compute_merkle_root(&leaves);
    assert_eq!(root1, root2);
}

#[test]
fn different_input_different_output() {
    let leaves_a = vec![b"x".to_vec(), b"y".to_vec()];
    let leaves_b = vec![b"y".to_vec(), b"x".to_vec()];
    let root_a = merkle::compute_merkle_root(&leaves_a);
    let root_b = merkle::compute_merkle_root(&leaves_b);
    assert_ne!(root_a, root_b);
}
