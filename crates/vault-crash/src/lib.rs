//! vault-crash: recolección de excepciones y diagnóstico cifrado.
//!
//! Ante cualquier pánico, genera un reporte de estado + volcado parcial
//! (backtrace, metadatos del proceso, versión) y lo cifra de extremo a
//! extremo con criptografía asimétrica ECC (ECIES sobre P-256 + HKDF/SHA-256
//! para la clave de contenido, ChaCha20-Poly1305 como AEAD):
//!
//! - La APP solo conoce la CLAVE PÚBLICA de IT.
//! - Solo la CLAVE PRIVADA de IT (vault-it) puede descifrar los reportes.
//! - Si el archivo de log se intercepta en la red, su contenido es opaco.
//!
//! El modo IT y su documentación viven exclusivamente en `ITConstructedDoor.md`
//! (entregable separado); nada de esto aparece en el código ni en esta doc.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use p256::ecdsa::{Signature as FixedSig, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use FixedSig as _FixedSigAlias;

#[derive(Debug, thiserror::Error)]
pub enum CrashError {
    #[error("reporte inválido: {0}")]
    BadReport(String),
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error criptográfico: {0}")]
    Crypto(String),
    #[error("error de serialización: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Par de claves del Admin IT (solo la privada puede descifrar reportes).
pub struct ItKeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl ItKeyPair {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut rand_core_compat());
        let public = secret.public_key();
        ItKeyPair { secret, public }
    }

    /// Clave pública en formato SEC1 comprimido (hex): la que embebe la APP.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public.to_encoded_point(true).as_bytes())
    }

    /// Clave privada en PKCS8 PEM (guardar SOLO donde vive el modo IT).
    pub fn private_pem(&self) -> String {
        use p256::pkcs8::EncodePrivateKey;
        self.secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pkcs8")
            .to_string()
    }

    pub fn from_private_pem(pem: &str) -> Result<Self, CrashError> {
        use p256::pkcs8::DecodePrivateKey;
        let secret = SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| CrashError::Crypto(format!("PKCS8: {e}")))?;
        Ok(ItKeyPair {
            public: secret.public_key(),
            secret,
        })
    }
}

fn rand_core_compat() -> RngShim {
    RngShim(std::sync::Mutex::new(getrandom_state()))
}

impl rand_core::CryptoRng for RngShim {}

fn getrandom_state() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("os randomness");
    b
}

struct RngShim(std::sync::Mutex<[u8; 32]>);

impl rand_core::RngCore for RngShim {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_be_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_be_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut guard = self.0.lock().unwrap();
        // contador + hash: flujo pseudoaleatorio re-semebrado por SO
        let mut counter = u64::from_be_bytes(guard[0..8].try_into().unwrap());
        counter = counter.wrapping_add(1);
        guard[0..8].copy_from_slice(&counter.to_be_bytes());
        let mut block = Sha256::digest(*guard);
        let mut filled = 0;
        while filled < dest.len() {
            let n = (dest.len() - filled).min(32);
            dest[filled..filled + n].copy_from_slice(&block[..n]);
            block = Sha256::digest(block);
            filled += n;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Reporte de estado generado ante un fallo (antes de cifrar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    /// Momento RFC 3339 UTC.
    pub timestamp: String,
    /// Versión de la aplicación.
    pub app_version: String,
    /// Sistema operativo objetivo.
    pub platform: String,
    /// Tipo de fallo (panic, error lógico, cierre inesperado…).
    pub kind: String,
    /// Mensaje del fallo.
    pub message: String,
    /// Volcado parcial: backtrace del hilo (limitado).
    pub backtrace: Vec<String>,
    /// Contexto de hilo principal.
    pub thread_name: String,
    /// Módulo que falló (si se conoce).
    pub module: String,
}

impl CrashReport {
    /// Construye un reporte desde la información de un pánico.
    pub fn from_panic(info: &std::panic::PanicHookInfo<'_>) -> Self {
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        let frames: Vec<String> = bt
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(40)
            .map(|l| l.trim().to_string())
            .collect();
        CrashReport {
            timestamp: vault_core::now_rfc3339(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            kind: "panic".into(),
            message: info.to_string(),
            backtrace: frames,
            thread_name: std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_string(),
            module: info
                .location()
                .map(|l| l.file().to_string())
                .unwrap_or_default(),
        }
    }

    /// Reporte para errores lógicos no fatales capturados por la app.
    pub fn from_error(kind: &str, module: &str, message: &str) -> Self {
        CrashReport {
            timestamp: vault_core::now_rfc3339(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            kind: kind.to_string(),
            message: message.to_string(),
            backtrace: Vec::new(),
            thread_name: std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_string(),
            module: module.to_string(),
        }
    }
}

/// Reporte cifrado (lo único que se escribe a disco/red).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedReport {
    /// Clave efímera del remitente (SEC1 comprimido, hex).
    pub eph_pub: String,
    /// Nonce de 12 bytes (hex) para ChaCha20-Poly1305.
    pub nonce: String,
    /// Contenido cifrado (base64) = JSON del reporte.
    pub ciphertext: String,
    /// Firma ECDSA del remitente sobre el ciphertext (autenticidad).
    pub signature: Option<String>,
}

/// Cifra un reporte para la clave pública de IT (ECIES).
/// Nadie sin la clave privada puede leer el resultado.
pub fn encrypt_report(
    report: &CrashReport,
    it_public_hex: &str,
) -> Result<EncryptedReport, CrashError> {
    let it_pub_bytes =
        hex::decode(it_public_hex).map_err(|e| CrashError::Crypto(format!("pubkey hex: {e}")))?;
    let point = p256::EncodedPoint::from_bytes(&it_pub_bytes)
        .map_err(|_| CrashError::Crypto("clave pública inválida".into()))?;
    let it_pub = PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| CrashError::Crypto("clave pública inválida".into()))?;

    // clave efímera del remitente
    let eph_secret = SecretKey::random(&mut rand_core_compat());
    let eph_pub: PublicKey = eph_secret.public_key();

    // shared secret ECDH
    let shared = p256::ecdh::diffie_hellman(eph_secret.to_nonzero_scalar(), it_pub.as_affine());

    // HKDF-lite: SHA256(shared || eph_pub || it_pub) → clave AEAD de 32 bytes
    let mut okm_input = Vec::new();
    okm_input.extend_from_slice(shared.raw_secret_bytes());
    okm_input.extend_from_slice(eph_pub.to_encoded_point(true).as_bytes());
    okm_input.extend_from_slice(it_pub.to_encoded_point(true).as_bytes());
    let aead_key = Sha256::digest(&okm_input);

    // nonce de 12 bytes aleatorio
    let mut nonce_b = [0u8; 12];
    getrandom::getrandom(&mut nonce_b).map_err(|e| CrashError::Crypto(e.to_string()))?;

    let plaintext = serde_json::to_vec(report)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_b),
            Payload {
                msg: &plaintext,
                aad: b"vault-crash-report-v1",
            },
        )
        .map_err(|_| CrashError::Crypto("fallo al cifrar reporte".into()))?;

    Ok(EncryptedReport {
        eph_pub: hex::encode(eph_pub.to_encoded_point(true).as_bytes()),
        nonce: hex::encode(nonce_b),
        ciphertext: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct),
        signature: None,
    })
}

/// Descifra un reporte con la CLAVE PRIVADA de IT. Es el único camino de
/// lectura; sin ella el archivo es opaco.
pub fn decrypt_report(
    enc: &EncryptedReport,
    it_private_pem: &str,
) -> Result<CrashReport, CrashError> {
    let it = ItKeyPair::from_private_pem(it_private_pem)?;
    let eph_bytes =
        hex::decode(&enc.eph_pub).map_err(|e| CrashError::Crypto(format!("eph hex: {e}")))?;
    let eph_point = p256::EncodedPoint::from_bytes(&eph_bytes)
        .map_err(|_| CrashError::Crypto("efímera inválida".into()))?;
    let eph_pub = PublicKey::from_encoded_point(&eph_point)
        .into_option()
        .ok_or_else(|| CrashError::Crypto("efímera inválida".into()))?;

    let shared = p256::ecdh::diffie_hellman(it.secret.to_nonzero_scalar(), eph_pub.as_affine());
    let mut okm_input = Vec::new();
    okm_input.extend_from_slice(shared.raw_secret_bytes());
    okm_input.extend_from_slice(eph_pub.to_encoded_point(true).as_bytes());
    okm_input.extend_from_slice(it.public.to_encoded_point(true).as_bytes());
    let aead_key = Sha256::digest(&okm_input);

    let nonce_b: [u8; 12] = hex::decode(&enc.nonce)
        .map_err(|e| CrashError::Crypto(format!("nonce: {e}")))?
        .try_into()
        .map_err(|_| CrashError::Crypto("nonce de longitud incorrecta".into()))?;
    let ct = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &enc.ciphertext)
        .map_err(|e| CrashError::Crypto(format!("b64: {e}")))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce_b),
            Payload {
                msg: &ct,
                aad: b"vault-crash-report-v1",
            },
        )
        .map_err(|_| {
            CrashError::Crypto("autenticación fallida (archivo ajeno o alterado)".into())
        })?;
    Ok(serde_json::from_slice(&plain)?)
}

// ----------------------------------------------------------------------
// Persistencia e instalación del hook global de pánico
// ----------------------------------------------------------------------

/// Guarda el reporte cifrado en `crash_dir` con nombre determinista por hora.
pub fn save_encrypted_report(
    crash_dir: &std::path::Path,
    enc: &EncryptedReport,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(crash_dir)?;
    let mut name = format!("crash-{}.crpt", vault_core::now_rfc3339());
    // el nombre solo admite caracteres de nombre de archivo
    name = name.replace(':', "-");
    let path = crash_dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(enc)?)?;
    Ok(path)
}

// ----------------------------------------------------------------------
// Identidad de la aplicación (firma de procedencia de los reportes)
// ----------------------------------------------------------------------

/// Clave ECDSA de la aplicación: firma cada reporte para que quien lo lea
/// pueda comprobar que lo emitió esta instalación y no un tercero con la
/// clave pública de reportes.
#[derive(Clone)]
pub struct AppSigningKey {
    signing: p256::ecdsa::SigningKey,
}

impl AppSigningKey {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut rand_core_compat());
        AppSigningKey {
            signing: p256::ecdsa::SigningKey::from(&secret),
        }
    }

    /// Clave pública en SEC1 comprimido (hex).
    pub fn public_hex(&self) -> String {
        hex::encode(
            self.signing
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    /// Clave privada en PKCS8 PEM (permisos 0600 en disco).
    pub fn private_pem(&self) -> String {
        use p256::pkcs8::EncodePrivateKey;
        self.signing
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    pub fn from_private_pem(pem: &str) -> Result<Self, CrashError> {
        use p256::pkcs8::DecodePrivateKey;
        let signing = p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CrashError::Crypto(format!("clave de firma: {e}")))?;
        Ok(AppSigningKey { signing })
    }

    /// Firma el ciphertext de un reporte (procedencia verificable).
    pub fn sign(&self, enc: &mut EncryptedReport) {
        sign_ciphertext(enc, &self.signing);
    }
}

/// Reconstruye la clave pública de verificación a partir del hex comprimido.
pub fn verifying_key_from_hex(public_hex: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(public_hex.trim()).ok()?;
    let point = p256::EncodedPoint::from_bytes(bytes).ok()?;
    VerifyingKey::from_encoded_point(&point).ok()
}

/// Carga (o crea, la primera vez) la clave de firma de la aplicación en
/// `dir/app.key.pem` (0600) + `dir/app.pub`.
pub fn load_or_create_app_key(dir: &Path) -> Result<AppSigningKey, CrashError> {
    let key_path = dir.join("app.key.pem");
    let pub_path = dir.join("app.pub");
    if let Ok(pem) = std::fs::read_to_string(&key_path) {
        if let Ok(key) = AppSigningKey::from_private_pem(&pem) {
            if !pub_path.exists() {
                let _ = std::fs::write(&pub_path, format!("{}\n", key.public_hex()));
            }
            return Ok(key);
        }
    }
    std::fs::create_dir_all(dir)?;
    let key = AppSigningKey::generate();
    std::fs::write(&key_path, key.private_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::write(&pub_path, format!("{}\n", key.public_hex()))?;
    Ok(key)
}

/// Clave pública de la aplicación, si existe (para verificar procedencia).
pub fn load_app_verifying_key(dir: &Path) -> Option<VerifyingKey> {
    let hex = std::fs::read_to_string(dir.join("app.pub")).ok()?;
    verifying_key_from_hex(&hex)
}

// ----------------------------------------------------------------------
// Redactor de reportes
// ----------------------------------------------------------------------

/// Único camino de emisión de reportes: sabe a quién cifrar, dónde guardar y
/// con qué clave firmar la procedencia.
#[derive(Clone)]
pub struct CrashReporter {
    it_public_hex: String,
    crash_dir: PathBuf,
    signing: Option<AppSigningKey>,
}

impl CrashReporter {
    /// `it_public_hex` es la CLAVE PÚBLICA de la administración de sistemas —
    /// la aplicación nunca conoce la privada.
    pub fn new(
        it_public_hex: impl Into<String>,
        crash_dir: impl Into<PathBuf>,
        signing: Option<AppSigningKey>,
    ) -> Self {
        CrashReporter {
            it_public_hex: it_public_hex.into(),
            crash_dir: crash_dir.into(),
            signing,
        }
    }

    /// Cifra (y firma, si hay clave) un reporte y lo guarda como `.crpt`.
    pub fn save(&self, report: &CrashReport) -> Result<PathBuf, CrashError> {
        let mut enc = encrypt_report(report, &self.it_public_hex)?;
        if let Some(k) = &self.signing {
            k.sign(&mut enc);
        }
        save_encrypted_report(&self.crash_dir, &enc).map_err(CrashError::Io)
    }

    /// Registra un error lógico no fatal (la aplicación sigue viva).
    pub fn report_logic_error(&self, module: &str, message: &str) -> Result<PathBuf, CrashError> {
        self.save(&CrashReport::from_error("logic_error", module, message))
    }

    /// Instala el hook de pánico global: escribe el reporte cifrado y encadena
    /// con el hook previo (si lo había) para no silenciar nada.
    pub fn install_panic_hook(&self) {
        let prev_hook = std::panic::take_hook();
        let this = self.clone();
        std::panic::set_hook(Box::new(move |info| {
            // 1) generar + cifrar + firmar el reporte (antes de morir)
            if let Err(e) = this.save(&CrashReport::from_panic(info)) {
                eprintln!("no se pudo persistir el reporte cifrado: {e}");
            }
            // 2) comportamiento previo (log estándar)
            prev_hook(info);
        }));
    }
}

/// Utilidad de firma (opcional): firma el ciphertext con una clave ECDSA
/// dedicada de la app para que IT verifique procedencia.
pub fn sign_ciphertext(enc: &mut EncryptedReport, app_signing: &p256::ecdsa::SigningKey) {
    use p256::ecdsa::signature::Signer;
    let sig: p256::ecdsa::Signature = app_signing.sign(enc.ciphertext.as_bytes());
    enc.signature = Some(hex::encode(sig.to_bytes()));
}

/// Verifica la firma del ciphertext con la clave pública de la app.
pub fn verify_ciphertext(enc: &EncryptedReport, app_verifying: &VerifyingKey) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Some(sig_hex) = &enc.signature else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(bytes64) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(&bytes64) else {
        return false;
    };
    app_verifying
        .verify(enc.ciphertext.as_bytes(), &sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let it = ItKeyPair::generate();
        let report = CrashReport::from_error("logic_error", "vault-gui", "fallo de prueba");
        let enc = encrypt_report(&report, &it.public_hex()).unwrap();

        // el ciphertext NO contiene el mensaje en claro
        assert!(!enc.ciphertext.contains("fallo de prueba"));

        // solo la clave privada de IT lo lee
        let decoded = decrypt_report(&enc, &it.private_pem()).unwrap();
        assert_eq!(decoded.message, "fallo de prueba");
        assert_eq!(decoded.kind, "logic_error");
        assert_eq!(decoded.module, "vault-gui");
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let it = ItKeyPair::generate();
        let other = ItKeyPair::generate();
        let report = CrashReport::from_error("panic", "m", "secreto");
        let enc = encrypt_report(&report, &it.public_hex()).unwrap();
        assert!(decrypt_report(&enc, &other.private_pem()).is_err());
    }

    #[test]
    fn tampered_report_rejected() {
        let it = ItKeyPair::generate();
        let enc =
            encrypt_report(&CrashReport::from_error("k", "m", "x"), &it.public_hex()).unwrap();
        let mut enc2 = enc.clone();
        enc2.ciphertext = enc.ciphertext[..enc.ciphertext.len() - 4].to_string();
        assert!(decrypt_report(&enc2, &it.private_pem()).is_err());
    }

    #[test]
    fn save_and_reload_report_file() {
        let it = ItKeyPair::generate();
        let dir = tempfile::tempdir().unwrap();
        let enc = encrypt_report(
            &CrashReport::from_error("panic", "m", "boom"),
            &it.public_hex(),
        )
        .unwrap();
        let path = save_encrypted_report(dir.path(), &enc).unwrap();
        assert!(path.exists());
        assert!(path.extension().unwrap() == "crpt");
        // el archivo en disco no revela nada
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("boom"));
        // y IT puede leerlo
        let enc2: EncryptedReport = serde_json::from_str(&raw).unwrap();
        let decoded = decrypt_report(&enc2, &it.private_pem()).unwrap();
        assert_eq!(decoded.message, "boom");
    }

    #[test]
    fn sign_and_verify_ciphertext() {
        let app_secret = p256::SecretKey::random(&mut rand_core_compat());
        let signing = p256::ecdsa::SigningKey::from(&app_secret);
        let verifying = signing.verifying_key();
        let it = ItKeyPair::generate();
        let mut enc =
            encrypt_report(&CrashReport::from_error("k", "m", "x"), &it.public_hex()).unwrap();
        assert!(!verify_ciphertext(&enc, verifying));
        sign_ciphertext(&mut enc, &signing);
        assert!(verify_ciphertext(&enc, verifying));
        // y sigue descifrando igual
        let decoded = decrypt_report(&enc, &it.private_pem()).unwrap();
        assert_eq!(decoded.message, "x");
    }

    #[test]
    fn app_signing_key_persists_and_signs() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_app_key(dir.path()).unwrap();
        // el archivo privado queda en 0600 y la pública disponible
        assert!(dir.path().join("app.key.pem").exists());
        assert!(dir.path().join("app.pub").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("app.key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "la clave de firma es privada");
        }
        // cargarla de nuevo devuelve la misma identidad
        let k2 = load_or_create_app_key(dir.path()).unwrap();
        assert_eq!(k1.public_hex(), k2.public_hex());
        // y la pública publicada sirve para verificar
        let verifying = load_app_verifying_key(dir.path()).expect("clave pública");

        let it = ItKeyPair::generate();
        let mut enc =
            encrypt_report(&CrashReport::from_error("k", "m", "x"), &it.public_hex()).unwrap();
        assert!(!verify_ciphertext(&enc, &verifying));
        k1.sign(&mut enc);
        assert!(verify_ciphertext(&enc, &verifying));
        assert_eq!(
            decrypt_report(&enc, &it.private_pem()).unwrap().message,
            "x"
        );
    }

    /// Un reporte de error lógico: se guarda cifrado, solo se lee con la clave
    /// privada de administración y la firma acredita la procedencia.
    #[test]
    fn reporter_saves_signed_logic_error() {
        let dir = tempfile::tempdir().unwrap();
        let it = ItKeyPair::generate();
        let app_key = load_or_create_app_key(dir.path()).unwrap();
        let verifying = load_app_verifying_key(dir.path()).unwrap();
        let crash_dir = dir.path().join("crash");
        let reporter = CrashReporter::new(it.public_hex(), crash_dir.clone(), Some(app_key));

        let path = reporter
            .report_logic_error("vault-gui::import", "no se pudo sellar el documento")
            .unwrap();
        assert_eq!(path.extension().unwrap(), "crpt");

        // opaco en disco
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("no se pudo sellar"));

        // legible por la administración de sistemas, con firma válida
        let enc: EncryptedReport = serde_json::from_str(&raw).unwrap();
        assert!(verify_ciphertext(&enc, &verifying), "debe venir firmado");
        let report = decrypt_report(&enc, &it.private_pem()).unwrap();
        assert_eq!(report.kind, "logic_error");
        assert_eq!(report.module, "vault-gui::import");
        assert_eq!(report.message, "no se pudo sellar el documento");

        // La firma acredita QUIÉN la emitió: vale bajo la clave de esa
        // identidad y no bajo la de la aplicación legítima.
        let otra = AppSigningKey::generate();
        let mut enc2 = enc.clone();
        enc2.signature = None;
        otra.sign(&mut enc2);
        assert!(
            verify_ciphertext(&enc2, &verifying_key_from_hex(&otra.public_hex()).unwrap()),
            "firmada por otra identidad"
        );
        assert!(
            !verify_ciphertext(&enc2, &verifying),
            "no procede de esta aplicación"
        );
    }

    #[test]
    fn private_pem_roundtrip() {
        let it = ItKeyPair::generate();
        let pem = it.private_pem();
        let it2 = ItKeyPair::from_private_pem(&pem).unwrap();
        assert_eq!(it.public_hex(), it2.public_hex());
    }
}
