use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

use crate::error::{Result, VsqlSyncError};

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn write_keypair(dir: &Path) -> Result<(SigningKey, VerifyingKey)> {
    std::fs::create_dir_all(dir)?;

    let (signing_key, verifying_key) = generate_keypair();

    let key_path = dir.join("vsql-sync-signing.key");
    let pub_path = dir.join("vsql-sync-signing.pub");

    std::fs::write(&key_path, signing_key.to_bytes())?;
    std::fs::write(&pub_path, verifying_key.to_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
    }

    Ok((signing_key, verifying_key))
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path)?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        VsqlSyncError::Signing("invalid signing key: expected 32 bytes".to_string())
    })?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let bytes = std::fs::read(path)?;
    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        VsqlSyncError::Signing("invalid verifying key: expected 32 bytes".to_string())
    })?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| VsqlSyncError::Signing(format!("invalid verifying key: {e}")))
}

pub fn sign(key: &SigningKey, data: &[u8]) -> Signature {
    key.sign(data)
}

pub fn verify(pubkey: &VerifyingKey, data: &[u8], sig: &Signature) -> Result<()> {
    pubkey
        .verify(data, sig)
        .map_err(|e| VsqlSyncError::Signing(format!("signature verification failed: {e}")))
}
