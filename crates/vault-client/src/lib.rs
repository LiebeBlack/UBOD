//! vault-client: biblioteca del dispositivo móvil (lado Android/simulador).
//!
//! Reúne lo que un teléfono necesita para hablar con la bóveda:
//!
//! - Construcción del envelope JSON del protocolo (header + payload) a partir
//!   de un archivo local, calculando SHA-256 y BLAKE3.
//! - Clasificación automática de categoría por reglas (vault-index).
//! - Emparejamiento: envía el código de un solo uso y guarda el certificado
//!   de cliente emitido por la bóveda.
//! - Upload mTLS del envelope + bytes, con verificación del ACK.

use rustls::pki_types::pem::PemObject as _;
use sha2::Digest as _;
use vault_core::{TransferEnvelope, TransferHeader, TransferPayload};

#[derive(Debug, thiserror::Error)]
pub enum ClientLibError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error del protocolo: {0}")]
    Protocol(String),
    #[error("respuesta del servidor {status}: {body}")]
    Api { status: u16, body: String },
    #[error("error de sincronización: {0}")]
    Sync(#[from] vault_sync::SyncError),
    #[error("error de cliente mTLS: {0}")]
    VaultClient(#[from] vault_sync::client::ClientError),
}

/// Construye el envelope de transferencia para un archivo local.
///
/// `category_hint` permite forzar una categoría (nombre de carpeta); si es
/// `None` se clasifica con las reglas embebidas y, cuando el nombre no permite
/// decidir, el envío se rechaza en lugar de adivinar.
pub fn build_envelope(
    file_path: &std::path::Path,
    device_id: &str,
    category_hint: Option<&str>,
) -> Result<(TransferEnvelope, u64), ClientLibError> {
    let file_name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| ClientLibError::Protocol("ruta sin nombre de archivo".into()))?;
    let hp = vault_crypto::HashPair::from_file(file_path)?;
    let size = std::fs::metadata(file_path)?.len();

    let category = match category_hint {
        Some(c) => vault_core::Category::from_dir_name(c)
            .ok_or_else(|| ClientLibError::Protocol(format!("categoría desconocida: {c}")))?,
        None => vault_index::Ruleset::default_ruleset()
            .classify(&file_name)
            .ok_or_else(|| {
                ClientLibError::Protocol(format!(
                    "no se pudo clasificar «{file_name}»; indique la categoría manualmente"
                ))
            })?,
    };

    let envelope = TransferEnvelope {
        header: TransferHeader {
            device_id: device_id.to_string(),
            timestamp_utc: vault_core::now_rfc3339(),
            protocol_version: TransferEnvelope::PROTOCOL_VERSION.to_string(),
        },
        payload: TransferPayload {
            file_name: file_name.clone(),
            file_category: category.dir_name().to_string(),
            file_size_bytes: size,
            sha256: hp.sha256,
            department: String::new(),
            author: String::new(),
            title: title_from_file_name(&file_name),
            id_number: None,
            academic_year: None,
        },
    };
    Ok((envelope, size))
}

/// Título legible a partir del nombre de archivo (sin la última extensión).
///
/// `trim_end_matches` repetiría el recorte: «acta.doc.doc» quedaría en «acta».
fn title_from_file_name(file_name: &str) -> String {
    match file_name.rsplit_once('.') {
        Some((stem, _ext)) if !stem.is_empty() => stem.to_string(),
        _ => file_name.to_string(),
    }
}

/// Resultado de un emparejamiento exitoso.
#[derive(Debug, Clone)]
pub struct PairedDevice {
    pub device_id: String,
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 hex del certificado (como lo registra la bóveda).
    pub fingerprint: String,
}

/// Empareja un dispositivo contra una bóveda: pide el certificado de cliente
/// con el código de un solo uso y devuelve los PEM para futuras sesiones mTLS.
pub fn pair(
    vault_addr: std::net::SocketAddr,
    ca_pem: &str,
    code: &str,
    device_id: &str,
) -> Result<PairedDevice, ClientLibError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
    rt.block_on(async move {
        let ca_der = rustls::pki_types::CertificateDer::from_pem_slice(
            cert_pem_from(ca_pem)?.as_bytes(),
        )
        .map_err(|e| ClientLibError::Protocol(format!("CA PEM: {e}")))?;
        let anon_cfg = vault_sync::anon_client_config(ca_der)
            .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(anon_cfg));
        let tcp = tokio::net::TcpStream::connect(vault_addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from("vault.local".to_string())
            .map_err(|e| ClientLibError::Protocol(format!("server name: {e}")))?;
        // El saludo TLS va acotado: una bóveda que acepta la conexión y luego
        // calla no puede dejar la petición colgada (era el síntoma de la CI).
        let handshake = tokio::time::timeout(
            vault_sync::client::NET_TIMEOUT,
            connector.connect(server_name, tcp),
        );
        let mut tls = match handshake.await {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => return Err(ClientLibError::Io(e)),
            Err(_) => return Err(ClientLibError::Protocol("saludo TLS agotado".into())),
        };

        let body = serde_json::json!({ "code": code, "device_id": device_id });
        let body = body.to_string().into_bytes();
        let req = format!(
            "POST /v1/pair HTTP/1.1\r\nHost: vault\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        use tokio::io::AsyncWriteExt;
        tls.write_all(req.as_bytes()).await?;
        tls.write_all(&body).await?;
        tls.flush().await?;
        // La respuesta se delimita por Content-Length (ver vault-sync::client).
        let resp = vault_sync::client::read_response(&mut tls).await?;
        drop(tls);

        let text = String::from_utf8_lossy(&resp.body);
        let json_start = text.find('{').ok_or_else(|| {
            ClientLibError::Protocol(format!("respuesta sin JSON: {}", &text[..text.len().min(120)]))
        })?;
        let parsed: serde_json::Value = serde_json::from_str(text[json_start..].trim_end())
            .map_err(|e| ClientLibError::Protocol(format!("JSON inválido: {e}")))?;
        if parsed["error"].is_string() {
            return Err(ClientLibError::Protocol(
                parsed["error"].as_str().unwrap_or("error").to_string(),
            ));
        }
        let cert_pem = parsed["client_cert_pem"]
            .as_str()
            .ok_or_else(|| ClientLibError::Protocol("sin cert de cliente".into()))?
            .to_string();
        let key_pem = parsed["client_key_pem"]
            .as_str()
            .ok_or_else(|| ClientLibError::Protocol("sin clave de cliente".into()))?
            .to_string();
        let fingerprint = parsed["cert_fingerprint"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Ok(PairedDevice {
            device_id: device_id.to_string(),
            cert_pem,
            key_pem,
            fingerprint,
        })
    })
}

/// Sube un archivo a la bóveda usando una identidad ya emparejada y devuelve
/// el ACK JSON de la bóveda (SealAck o error de validación).
pub fn upload_file(
    vault_addr: std::net::SocketAddr,
    identity: &PairedDevice,
    ca_pem: &str,
    file_path: &std::path::Path,
    category_hint: Option<&str>,
) -> Result<serde_json::Value, ClientLibError> {
    let (envelope, _size) = build_envelope(file_path, &identity.device_id, category_hint)?;
    let bytes = std::fs::read(file_path)?;
    let envelope_json =
        serde_json::to_string(&envelope).map_err(|e| ClientLibError::Protocol(e.to_string()))?;

    let client_tls = vault_sync::client::load_client_tls(
        &identity.cert_pem,
        &identity.key_pem,
        ca_pem,
        "vault.local",
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
    rt.block_on(async move {
        let client = vault_sync::client::VaultClient::connect(&client_tls, vault_addr)?;
        let ack = client
            .upload(&envelope_json, &bytes)
            .await
            .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
        if ack.status != 200 {
            return Err(ClientLibError::Api {
                status: ack.status,
                body: ack.text(),
            });
        }
        Ok(ack.json())
    })
}

/// Consulta el estado del servidor (`/v1/ping`).
pub fn ping(
    vault_addr: std::net::SocketAddr,
    identity: &PairedDevice,
    ca_pem: &str,
) -> Result<bool, ClientLibError> {
    let client_tls = vault_sync::client::load_client_tls(
        &identity.cert_pem,
        &identity.key_pem,
        ca_pem,
        "vault.local",
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
    rt.block_on(async move {
        let client = vault_sync::client::VaultClient::connect(&client_tls, vault_addr)?;
        let pong = client
            .ping()
            .await
            .map_err(|e| ClientLibError::Protocol(e.to_string()))?;
        Ok(pong.status == 200)
    })
}

// ---------------------------------------------------------------------------
// utilidades PEM
// ---------------------------------------------------------------------------

fn cert_pem_from(ca_pem: &str) -> Result<String, ClientLibError> {
    // Acepta tanto PEM como DER hex; normaliza a PEM.
    if ca_pem.contains("BEGIN CERTIFICATE") {
        Ok(ca_pem.to_string())
    } else {
        let der = hex::decode(ca_pem.trim())
            .map_err(|e| ClientLibError::Protocol(format!("CA ni PEM ni hex: {e}")))?;
        Ok(vault_crypto::pem_encode_cert(&der))
    }
}

/// Extrae el primer certificado de un PEM multi-línea como DER.
pub fn cert_der_from_pem(pem: &str) -> Result<Vec<u8>, ClientLibError> {
    let start = pem
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or_else(|| ClientLibError::Protocol("PEM sin bloque CERTIFICATE".into()))?;
    let body: String = pem[start..]
        .lines()
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| ClientLibError::Protocol(format!("base64 PEM: {e}")))
}

/// Huella SHA-256 hex de un certificado PEM (para comparar con el manifest).
pub fn fingerprint_of_pem(pem: &str) -> Result<String, ClientLibError> {
    Ok(hex::encode(sha2::Sha256::digest(cert_der_from_pem(pem)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_built_from_file_with_hint() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("Tesis_Ingenieria_2026_Nicolas.pdf");
        std::fs::write(&f, b"contenido de tesis").unwrap();
        let (env, size) = build_envelope(&f, "AND_TEST_9", Some("Tesis")).unwrap();
        assert_eq!(env.header.device_id, "AND_TEST_9");
        assert_eq!(env.header.protocol_version, "1.0");
        assert_eq!(env.payload.file_category, "Tesis");
        assert_eq!(env.payload.file_size_bytes, size);
        assert_eq!(size, 18);
        let digest = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"contenido de tesis"))
        };
        assert_eq!(env.payload.sha256, digest);
    }

    #[test]
    fn envelope_classifies_by_rules() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("foto_pizarra_clase.jpg");
        std::fs::write(&f, b"jpg").unwrap();
        let (env, _) = build_envelope(&f, "AND_TEST_9", None).unwrap();
        assert_eq!(env.payload.file_category, "Fotografia_Documental");
    }

    #[test]
    fn unclassifiable_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("random.xyz");
        std::fs::write(&f, b"?").unwrap();
        assert!(build_envelope(&f, "AND_TEST_9", None).is_err());
    }

    #[test]
    fn title_and_extension_from_names() {
        // no debe comerse extensiones repetidas del nombre
        assert_eq!(title_from_file_name("acta.doc.doc"), "acta.doc");
        assert_eq!(title_from_file_name("Tesis_2026.pdf"), "Tesis_2026");
        assert_eq!(title_from_file_name("sin_extension"), "sin_extension");

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("acta.doc.doc");
        std::fs::write(&f, b"x").unwrap();
        let (env, _) = build_envelope(&f, "AND_T", Some("Tesis")).unwrap();
        assert_eq!(env.payload.title, "acta.doc");
    }

    #[test]
    fn pem_fingerprint_roundtrip() {
        // PEM sintético: el parseo no depende de un certificado real
        let der = b"der-irrelevante-para-el-test".to_vec();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
        assert_eq!(cert_der_from_pem(&pem).unwrap(), der);
        assert_eq!(fingerprint_of_pem(&pem).unwrap(), {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(&der))
        });
    }
}
