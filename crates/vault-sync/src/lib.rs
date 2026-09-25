//! vault-sync: sincronización LAN con seguridad mTLS.
//!
//! - PKI propia: la bóveda es su propia CA; los dispositivos se emparejan con
//!   un código de un solo uso y reciben un certificado de cliente firmado.
//! - Servidor HTTPS (hyper + rustls) con client-auth.
//! - Endpoints: GET /v1/ping, GET /v1/manifest, POST /v1/upload, POST /v1/pair.
//! - Anuncio mDNS `_vaultsync._tcp.local.` para descubrimiento automático.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::Path;
use std::sync::Arc;
use vault_crypto::pki::{san_dns, san_ip};

pub mod client;
pub mod mdns;
pub mod server;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error TLS: {0}")]
    Tls(String),
    #[error("error PKI: {0}")]
    Pki(#[from] vault_crypto::PkiError),
    #[error("certificado de cliente requerido")]
    ClientCertRequired,
    #[error("dispositivo no autorizado: {0}")]
    UnauthorizedDevice(String),
    #[error("error HTTP: {0}")]
    Http(String),
}

/// Material TLS del servidor: cert + clave + CA para verificar clientes.
pub struct ServerTlsConfig {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub ca_der: CertificateDer<'static>,
}

impl Clone for ServerTlsConfig {
    fn clone(&self) -> Self {
        ServerTlsConfig {
            cert_der: self.cert_der.clone(),
            key_der: self.key_der.clone_key(),
            ca_der: self.ca_der.clone(),
        }
    }
}

impl ServerTlsConfig {
    fn key_clone(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }
}

impl ServerTlsConfig {
    /// Carga o genera la PKI del servidor en `pki_dir` (ca.crt/key, server.crt/key).
    pub fn load_or_create(pki_dir: &Path, server_cn: &str) -> Result<Self, SyncError> {
        std::fs::create_dir_all(pki_dir)?;
        let ca_path = pki_dir.join("ca");
        let server_path = pki_dir.join("server");

        let _ca = if ca_path.with_extension("crt.pem").exists() {
            vault_crypto::Identity::load(pki_dir, "ca")?
        } else {
            let ca = vault_crypto::Identity::generate().self_sign_ca("Boveda Root CA", 3650)?;
            ca.save(pki_dir, "ca")?;
            ca
        };

        // certificado de servidor (hoja firmada por la CA, con SAN de IP/DNS)
        if !server_path.with_extension("crt.pem").exists() {
            let ca = vault_crypto::Identity::load(pki_dir, "ca")?;
            let server_key = vault_crypto::DeviceKeyPair::generate();
            let ip = vault_crypto::pki::detect_local_ip()
                .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]));
            let san = vec![san_ip(ip)?, san_dns("vault.local")?];
            let server_cert =
                ca.sign_leaf_with_san(server_cn, server_key.verifying_key(), true, 825, Some(san))?;
            std::fs::write(
                server_path.with_extension("key.pem"),
                server_key.to_pkcs8_pem(),
            )?;
            std::fs::write(
                server_path.with_extension("crt.pem"),
                vault_crypto::pem_encode_cert(&server_cert),
            )?;
        }

        let key_pem = std::fs::read_to_string(server_path.with_extension("key.pem"))?;
        let cert_pem = std::fs::read_to_string(server_path.with_extension("crt.pem"))?;
        let ca_pem = std::fs::read_to_string(ca_path.with_extension("crt.pem"))?;

        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(pem_to_sync)?;
        let key_der = PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).map_err(pem_to_sync)?,
        );
        let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes()).map_err(pem_to_sync)?;

        Ok(ServerTlsConfig {
            cert_der,
            key_der,
            ca_der,
        })
    }
}

/// Proveedor criptográfico puro-Rust del proceso (RustCrypto).
///
/// Rustls se compila aquí sin `ring` ni `aws-lc-rs` (`default-features = false`),
/// de modo que `CryptoProvider::get_default_or_install_from_crate_features()`
/// **aborta con pánico**. Toda API que consulte el proveedor predeterminado
/// —`WebPkiClientVerifier::builder`, por ejemplo— exige que esté instalado: se
/// instala una sola vez (idempotente y seguro entre hilos) y todas las configs
/// reutilizan ese mismo `Arc`.
pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: std::sync::OnceLock<Arc<rustls::crypto::CryptoProvider>> =
        std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let provider = rustls_rustcrypto::provider();
            let candidato = Arc::new(provider.clone());
            // Si otro hilo ganó la carrera, se respeta el ya instalado. El
            // respaldo mantiene el mismo proveedor aunque la instalación falle.
            let _ = provider.install_default();
            rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or(candidato)
        })
        .clone()
}

/// Construye el `ServerConfig` mTLS: exige certificado de cliente firmado por la CA.
pub fn build_server_config(cfg: &ServerTlsConfig) -> Result<rustls::ServerConfig, SyncError> {
    let provider = crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cfg.ca_der.clone())
        .map_err(|e| SyncError::Tls(e.to_string()))?;
    // Client-auth ofrecido pero opcional: un dispositivo sin certificado aún
    // puede alcanzar /v1/pair (protegido por código de un solo uso); todo lo
    // demás exige dispositivo autorizado (ver server.rs::require_auth).
    //
    // `builder_with_provider` es obligatorio: `builder()` consultaría el
    // proveedor predeterminado y sin `ring`/`aws-lc-rs` eso es un pánico.
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .map_err(|e| SyncError::Tls(e.to_string()))?;

    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| SyncError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cfg.cert_der.clone()], cfg.key_clone())
        .map_err(|e| SyncError::Tls(e.to_string()))?;
    Ok(config)
}

/// Config de cliente mTLS: certificado de dispositivo + CA del servidor.
pub struct ClientTlsConfig {
    pub client_cert_der: CertificateDer<'static>,
    pub client_key_der: PrivateKeyDer<'static>,
    pub ca_der: CertificateDer<'static>,
    pub server_name: String,
}

impl ClientTlsConfig {
    pub fn build(&self) -> Result<rustls::ClientConfig, SyncError> {
        let provider = crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.ca_der.clone())
            .map_err(|e| SyncError::Tls(e.to_string()))?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| SyncError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![self.client_cert_der.clone()],
                self.client_key_der.clone_key(),
            )
            .map_err(|e| SyncError::Tls(e.to_string()))?;
        Ok(config)
    }
}

/// Igual que `ClientTlsConfig::build` pero sin certificado de cliente
/// (solo sirve para alcanzar `/v1/pair`).
pub fn anon_client_config(
    ca_der: CertificateDer<'static>,
) -> Result<rustls::ClientConfig, SyncError> {
    let provider = crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca_der)
        .map_err(|e| SyncError::Tls(e.to_string()))?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| SyncError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// Empareja un dispositivo: genera su par de claves, firma el certificado y
/// devuelve (clave privada PEM, certificado PEM, fingerprint SHA-256).
pub fn pair_new_device(
    ca: &vault_crypto::Identity,
    device_id: &str,
) -> Result<(String, String, String), SyncError> {
    let kp = vault_crypto::DeviceKeyPair::generate();
    let cert_der = ca.sign_leaf(device_id, kp.verifying_key(), false, 825)?;
    let cert_pem = vault_crypto::pem_encode_cert(&cert_der);
    let fingerprint = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(cert_der.as_slice()))
    };
    Ok((kp.to_pkcs8_pem(), cert_pem, fingerprint))
}

pub use server::serve;

/// Convierte un error PEM de rustls en `SyncError`.
fn pem_to_sync(e: rustls::pki_types::pem::Error) -> SyncError {
    SyncError::Tls(format!("PEM: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_load_or_create_and_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg1 = ServerTlsConfig::load_or_create(dir.path(), "vault-server").unwrap();
        let cfg2 = ServerTlsConfig::load_or_create(dir.path(), "vault-server").unwrap();
        assert_eq!(
            cfg1.cert_der.as_ref(),
            cfg2.cert_der.as_ref(),
            "la PKI debe persistir"
        );

        let ca = vault_crypto::Identity::load(dir.path(), "ca").unwrap();
        let (key_pem, cert_pem, fp) = pair_new_device(&ca, "AND_TEST_9").unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        assert!(cert_pem.contains("CERTIFICATE"));
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn server_config_builds() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ServerTlsConfig::load_or_create(dir.path(), "vault-server").unwrap();
        let _sc = build_server_config(&cfg).unwrap();
    }

    /// Regresión del cuelgue que dejaba la CI 6 h en `Build & test`.
    ///
    /// Sin `ring`/`aws-lc-rs`, consultar el proveedor predeterminado de rustls
    /// aborta el proceso: `build_server_config` se apoyaba en
    /// `WebPkiClientVerifier::builder` y el servidor nunca llegaba a publicar su
    /// dirección. Además de usar `builder_with_provider`, el proveedor debe
    /// quedar instalado para cualquier otra API que sí lo consulte.
    #[test]
    fn crypto_provider_is_installed_once() {
        let a = crypto_provider();
        let b = crypto_provider();
        assert!(
            Arc::ptr_eq(&a, &b),
            "el proveedor se reutiliza, no se recrea"
        );
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "el proveedor predeterminado debe quedar instalado"
        );
    }

    /// E2E real: servidor mTLS en 127.0.0.1 + emparejamiento con código de un
    /// solo uso + ping autorizado + manifest + upload verificado en staging.
    #[test]
    fn e2e_pair_ping_manifest_upload() {
        use crate::client::{load_client_tls, VaultClient};
        use sha2::Digest as _;
        use std::net::SocketAddr;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let staging = tempfile::tempdir().unwrap();
        let cfg = ServerTlsConfig::load_or_create(dir.path(), "vault-server").unwrap();
        let ca = std::sync::Arc::new(vault_crypto::Identity::load(dir.path(), "ca").unwrap());

        // uploads verificados (hash real vs envelope) y manifest con esos hashes
        let received: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received2 = received.clone();
        let manifest_fn = Box::new(move |_device: &str| {
            serde_json::json!({ "hashes": received2.lock().unwrap().clone() }).to_string()
        });
        let received3 = received.clone();
        let on_doc = Box::new(
            move |_device: &str, envelope: &str, path: &std::path::PathBuf| {
                let env: serde_json::Value = serde_json::from_str(envelope)
                    .map_err(|e| format!("envelope inválido: {e}"))?;
                let bytes = std::fs::read(path).map_err(|e| format!("staging: {e}"))?;
                let digest = hex::encode(sha2::Sha256::digest(&bytes));
                let claimed = env["payload"]["sha256"].as_str().unwrap_or("");
                if digest != claimed {
                    return Err(format!("hash no coincide: {digest} != {claimed}"));
                }
                received3.lock().unwrap().push(digest);
                Ok(r#"{"status":"accepted"}"#.to_string())
            },
        );

        let state = std::sync::Arc::new(server::SyncState::new(
            staging.path().to_path_buf(),
            64 * 1024 * 1024,
            manifest_fn,
            on_doc,
        ));
        state.set_ca(ca.clone());
        let pairing_code = state.new_pairing_code();

        let (tx, ready_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        state.set_ready_channel(tx);

        let tls_cfg = cfg.clone();
        let st = state.clone();
        rt.spawn(async move {
            let _ = server::serve("127.0.0.1:0".parse().unwrap(), tls_cfg, st).await;
        });

        rt.block_on(async move {
            let addr = ready_rx.await.expect("servidor listo");

            // 1) Emparejamiento sin certificado (solo código de un solo uso)
            let anon = crate::anon_client_config(cfg.ca_der.clone()).unwrap();
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(anon));
            let mut tls = connector
                .connect("vault.local".try_into().unwrap(), tcp)
                .await
                .unwrap();
            let req = format!(
                "POST /v1/pair HTTP/1.1\r\nHost: v\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"code\":\"{pairing_code}\",\"device_id\":\"AND_E2E_1\"}}",
                format!("{{\"code\":\"{pairing_code}\",\"device_id\":\"AND_E2E_1\"}}").len()
            );
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            tls.write_all(req.as_bytes()).await.unwrap();
            tls.flush().await.unwrap();
            let mut raw = Vec::new();
            tls.read_to_end(&mut raw).await.unwrap();
            let resp = String::from_utf8_lossy(&raw);
            assert!(resp.contains("200"), "pair debe ser 200: {resp}");
            let body_start = resp.find('{').unwrap();
            let paired: serde_json::Value =
                serde_json::from_str(resp[body_start..].trim_end()).unwrap();
            let key_pem = paired["client_key_pem"].as_str().unwrap();
            let cert_pem = paired["client_cert_pem"].as_str().unwrap();
            let ca_pem = vault_crypto::pem_encode_cert(cfg.ca_der.as_ref());

            // 2) Cliente mTLS ya emparejado: ping → manifest → upload
            let client_tls = load_client_tls(cert_pem, key_pem, &ca_pem, "vault.local").unwrap();
            let client = VaultClient::connect(&client_tls, addr).unwrap();
            let ping = client.ping().await.unwrap();
            assert_eq!(ping.status, 200, "ping: {}", ping.text());

            let manifest = client.manifest().await.unwrap();
            assert_eq!(manifest.status, 200);
            assert!(manifest.json()["hashes"].is_array());

            let file = b"Tesis Ingenieria 2026 - documento de prueba";
            let digest = hex::encode(sha2::Sha256::digest(file));
            let envelope = serde_json::json!({
                "header": {
                    "device_id": "AND_E2E_1",
                    "timestamp_utc": "2026-09-23T19:13:47Z",
                    "protocol_version": "1.0"
                },
                "payload": {
                    "file_name": "Tesis_Ingenieria_2026_Nicolas.pdf",
                    "file_category": "Tesis",
                    "file_size_bytes": file.len(),
                    "sha256": digest,
                    "department": "Coordinación de Ingeniería",
                    "author": "Yoangel De Dios Nicolás Gómez"
                }
            });
            let ack = client.upload(&envelope.to_string(), file).await.unwrap();
            assert_eq!(ack.status, 200, "upload: {}", ack.text());
            assert!(ack.json()["status"] == "accepted");
            assert_eq!(
                received.lock().unwrap().len(),
                1,
                "la bóveda registró el documento"
            );
        });
    }
}
