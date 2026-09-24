//! vault-crypto: hashing, cifrado de DB, PKI P-256 y sellado RFC 3161.
//!
//! 100% Rust puro — sin dependencias C ni OpenSSL.

pub mod dbcrypto;
pub mod derutil;
pub mod hashing;
pub mod pki;
pub mod tsa;

pub use dbcrypto::{DbCrypto, DbCryptoError};
pub use hashing::HashPair;
pub use pki::{pem_encode_cert, san_dns, san_ip, DeviceKeyPair, Identity, PkiError};
pub use tsa::{LocalTsa, MessageImprint, RemoteTsaClient, TimestampToken, TsaError};
