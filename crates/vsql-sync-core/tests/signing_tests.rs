use vsql_sync_core::signing;

#[test]
fn generate_keypair_produces_valid_pair() {
    let (sk, vk) = signing::generate_keypair();
    assert_eq!(vk, sk.verifying_key());
}

#[test]
fn sign_and_verify_roundtrip() {
    let (sk, vk) = signing::generate_keypair();
    let data = b"hello vsql-sync";
    let sig = signing::sign(&sk, data);
    signing::verify(&vk, data, &sig).expect("signature should verify");
}

#[test]
fn verify_rejects_wrong_data() {
    let (sk, vk) = signing::generate_keypair();
    let sig = signing::sign(&sk, b"original data");
    let result = signing::verify(&vk, b"tampered data", &sig);
    assert!(result.is_err());
}

#[test]
fn verify_rejects_wrong_key() {
    let (sk, _vk) = signing::generate_keypair();
    let (_sk2, vk2) = signing::generate_keypair();
    let sig = signing::sign(&sk, b"some data");
    let result = signing::verify(&vk2, b"some data", &sig);
    assert!(result.is_err());
}

#[test]
fn write_and_load_keypair_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (sk, vk) = signing::write_keypair(dir.path()).expect("write_keypair should succeed");

    let loaded_sk = signing::load_signing_key(&dir.path().join("vsql-sync-signing.key"))
        .expect("load_signing_key should succeed");
    let loaded_vk = signing::load_verifying_key(&dir.path().join("vsql-sync-signing.pub"))
        .expect("load_verifying_key should succeed");

    assert_eq!(sk.to_bytes(), loaded_sk.to_bytes());
    assert_eq!(vk.to_bytes(), loaded_vk.to_bytes());

    let data = b"roundtrip test";
    let sig = signing::sign(&loaded_sk, data);
    signing::verify(&loaded_vk, data, &sig).expect("loaded keys should work");
}

#[test]
fn load_signing_key_rejects_invalid_length() {
    let dir = tempfile::tempdir().unwrap();
    let bad_path = dir.path().join("bad.key");
    std::fs::write(&bad_path, b"too short").unwrap();
    let result = signing::load_signing_key(&bad_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("32 bytes"));
}
