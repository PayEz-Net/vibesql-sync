use sha2::{Digest, Sha256};

pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut current_level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| {
            let mut hasher = Sha256::new();
            hasher.update(leaf);
            hasher.finalize().into()
        })
        .collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0]);
            if chunk.len() == 2 {
                hasher.update(chunk[1]);
            } else {
                hasher.update(chunk[0]);
            }
            next_level.push(hasher.finalize().into());
        }

        current_level = next_level;
    }

    current_level[0]
}
