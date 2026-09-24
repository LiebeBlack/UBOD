//! Hashing en streaming: SHA-256 y BLAKE3 en una sola pasada.

use sha2::Digest;
use std::io::Read;
use std::path::Path;

/// Par de huellas digitales de un documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashPair {
    pub sha256: String,
    pub blake3: String,
}

impl HashPair {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut sha = sha2::Sha256::new();
        sha.update(bytes);
        HashPair {
            sha256: hex::encode(sha.finalize()),
            blake3: hex::encode(blake3::hash(bytes).as_bytes()),
        }
    }

    /// Calcula ambos hashes leyendo el archivo en streaming (bloques de 256 KiB).
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let f = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, f);
        let mut sha = sha2::Sha256::new();
        let mut blake = blake3::Hasher::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            sha.update(&buf[..n]);
            blake.update(&buf[..n]);
        }
        Ok(HashPair {
            sha256: hex::encode(sha.finalize()),
            blake3: hex::encode(blake.finalize().as_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_vector_hashes() {
        let h = HashPair::from_bytes(b"");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.blake3.len(), 64);
    }

    #[test]
    fn file_and_bytes_agree() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        std::fs::write(&p, vec![7u8; 700_000]).unwrap();
        let hf = HashPair::from_file(&p).unwrap();
        let hb = HashPair::from_bytes(&vec![7u8; 700_000]);
        assert_eq!(hf, hb);
    }
}
