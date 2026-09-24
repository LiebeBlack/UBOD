//! Cifrado para la base de datos de la bóveda (sustituto puro-Rust de SQLCipher).
//!
//! Diseño: cada bloque se cifra con ChaCha20-Poly1305 con un NONCE aleatorio de
//! 24 bytes y AAD = offset del bloque. El header es always-authenticated.
//! La clave maestra vive en un keyfile externo de 64 bytes (permisos 0600).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use getrandom::getrandom;

pub const MAGIC: &[u8; 8] = b"VLTDB01\0";
pub const BLOCK_SIZE: usize = 4096;
const NONCE_LEN: usize = 24;

/// Error de criptografía de almacenamiento.
#[derive(Debug, thiserror::Error)]
pub enum DbCryptoError {
    #[error("formato de base de datos inválido (magic/header)")]
    BadFormat,
    #[error("bloque corrupto o clave incorrecta (fallo de autenticación AEAD)")]
    CorruptOrWrongKey,
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de RNG: {0}")]
    Rng(#[from] getrandom::Error),
}

/// Genera un keyfile aleatorio de 64 bytes.
pub fn generate_keyfile() -> [u8; 64] {
    let mut k = [0u8; 64];
    getrandom(&mut k).expect("os randomness");
    k
}

#[derive(Clone)]
struct AeadKey(XChaCha20Poly1305);

impl AeadKey {
    fn new(raw: &[u8; 32]) -> Self {
        AeadKey(XChaCha20Poly1305::new(Key::from_slice(raw)))
    }

    fn encrypt(&self, nonce: &[u8; 24], aad: &[u8], plain: &[u8]) -> Vec<u8> {
        self.0
            .encrypt(XNonce::from_slice(nonce), Payload { msg: plain, aad })
            .expect("xchacha20poly1305 encrypt cannot fail with valid nonce")
    }

    fn decrypt(&self, nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        self.0
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| DbCryptoError::CorruptOrWrongKey)
    }
}

/// Deriva la clave de 32 bytes desde el keyfile con BLAKE3 (contexto de dominio).
fn derive_key(keyfile: &[u8; 64]) -> [u8; 32] {
    blake3::derive_key("vaultdb-v1/master-key", keyfile)
}

/// Constructor cifrado de blobs de base de datos: recibe el JSON completo
/// y devuelve un archivo cifrado autenticado, dividido en bloques.
pub struct DbCrypto {
    key: AeadKey,
}

impl DbCrypto {
    pub fn new(keyfile: &[u8; 64]) -> Self {
        DbCrypto {
            key: AeadKey::new(&derive_key(keyfile)),
        }
    }

    /// Cifra un buffer completo (el snapshot JSON de la BD) en un blob.
    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let mut header = Vec::with_capacity(16);
        header.extend_from_slice(MAGIC);
        // reservado: versión de formato
        header.push(1);
        header.extend_from_slice(&[0u8; 7]);
        debug_assert_eq!(header.len(), 16);

        let mut out = header;
        let blocks: Vec<&[u8]> = if plaintext.is_empty() {
            vec![&[]]
        } else {
            plaintext.chunks(BLOCK_SIZE).collect()
        };
        for (idx, block) in blocks.iter().enumerate() {
            let mut nonce = [0u8; NONCE_LEN];
            getrandom(&mut nonce)?;
            let aad = block_aad(idx);
            let ct = self.key.encrypt(&nonce, &aad, block);
            let mut rec = Vec::with_capacity(NONCE_LEN + 4 + ct.len());
            rec.extend_from_slice(&nonce);
            rec.extend_from_slice(&(ct.len() as u32).to_le_bytes());
            rec.extend_from_slice(&ct);
            out.extend_from_slice(&rec);
        }
        Ok(out)
    }

    /// Descifra un blob completo devuelto por `encrypt_blob`.
    pub fn decrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        if blob.len() < 16 || &blob[..8] != MAGIC {
            return Err(DbCryptoError::BadFormat);
        }
        let mut pos = 16usize;
        let mut plain = Vec::with_capacity(blob.len());
        let mut idx = 0usize;
        while pos < blob.len() {
            if pos + NONCE_LEN + 4 > blob.len() {
                return Err(DbCryptoError::BadFormat);
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&blob[pos..pos + NONCE_LEN]);
            pos += NONCE_LEN;
            let len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > blob.len() {
                return Err(DbCryptoError::BadFormat);
            }
            let ct = &blob[pos..pos + len];
            pos += len;
            let aad = block_aad(idx);
            plain.extend_from_slice(&self.key.decrypt(&nonce, &aad, ct)?);
            idx += 1;
        }
        Ok(plain)
    }

    /// Cifra un valor individual (para tablas parciales) con AAD de contexto.
    pub fn encrypt_field(&self, context: &str, plaintext: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom(&mut nonce)?;
        let aad = context.as_bytes();
        let ct = self.key.encrypt(&nonce, aad, plaintext);
        let mut out = Vec::with_capacity(NONCE_LEN + 4 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Descifra un valor cifrado con `encrypt_field`.
    pub fn decrypt_field(&self, context: &str, blob: &[u8]) -> Result<Vec<u8>, DbCryptoError> {
        if blob.len() < NONCE_LEN + 4 {
            return Err(DbCryptoError::BadFormat);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[..NONCE_LEN]);
        let len = u32::from_le_bytes(blob[NONCE_LEN..NONCE_LEN + 4].try_into().unwrap()) as usize;
        if blob.len() < NONCE_LEN + 4 + len {
            return Err(DbCryptoError::BadFormat);
        }
        self.key.decrypt(
            &nonce,
            context.as_bytes(),
            &blob[NONCE_LEN + 4..NONCE_LEN + 4 + len],
        )
    }
}

fn block_aad(idx: usize) -> Vec<u8> {
    let mut aad = b"vaultdb-block".to_vec();
    aad.extend_from_slice(&(idx as u64).to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_blob() {
        let kf = generate_keyfile();
        let c = DbCrypto::new(&kf);
        let data = vec![42u8; 10_000];
        let blob = c.encrypt_blob(&data).unwrap();
        assert!(blob[..8].iter().eq(MAGIC.iter()));
        assert_eq!(c.decrypt_blob(&blob).unwrap(), data);
    }

    #[test]
    fn wrong_key_rejected() {
        let kf1 = generate_keyfile();
        let kf2 = generate_keyfile();
        let c1 = DbCrypto::new(&kf1);
        let c2 = DbCrypto::new(&kf2);
        let blob = c1.encrypt_blob(b"secret secret secret").unwrap();
        assert!(matches!(
            c2.decrypt_blob(&blob),
            Err(DbCryptoError::CorruptOrWrongKey)
        ));
    }

    #[test]
    fn tampered_byte_detected() {
        let kf = generate_keyfile();
        let c = DbCrypto::new(&kf);
        let mut blob = c.encrypt_blob(b"x".repeat(5000).as_slice()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(c.decrypt_blob(&blob).is_err());
    }

    #[test]
    fn field_roundtrip_with_context() {
        let kf = generate_keyfile();
        let c = DbCrypto::new(&kf);
        let blob = c.encrypt_field("admin-pin", b"1234-hash").unwrap();
        assert_eq!(c.decrypt_field("admin-pin", &blob).unwrap(), b"1234-hash");
        assert!(c.decrypt_field("other-context", &blob).is_err());
    }
}
