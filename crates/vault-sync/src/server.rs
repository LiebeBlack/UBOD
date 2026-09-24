//! Servidor HTTPS mTLS del canal de sincronización.
//!
//! Protocolo (JSON + binario):
//! - `GET  /v1/ping`   → estado del servidor (mTLS)
//! - `GET  /v1/manifest` → hashes ya presentes en la bóveda (mTLS)
//! - `POST /v1/upload` → envelope JSON (1 línea) + bytes crudos (mTLS)
//! - `POST /v1/pair`   → {code, device_id} → certificado de cliente (sin mTLS)

use crate::{build_server_config, ServerTlsConfig, SyncError};
use der::Decode as _;
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Código de emparejamiento de un solo uso.
#[derive(Clone)]
pub struct PairingCode {
    pub code: String,
    pub expires_at: u64,
}

/// Devuelve el JSON del manifest de hashes para un dispositivo.
pub type ManifestFn = Box<dyn Fn(&str) -> String + Send>;
/// Ingesta: (device_id, envelope_json, ruta_staging) -> ACK JSON.
pub type IngestFn = Box<dyn Fn(&str, &str, &PathBuf) -> Result<String, String> + Send>;
/// Persistencia de emparejamiento: (device_id, fingerprint).
pub type PairedFn = Box<dyn Fn(&str, &str) + Send>;

/// Estado compartido del servidor de sincronización.
pub struct SyncState {
    /// Canal de una sola uso para señalizar la dirección real de escucha.
    pub(crate) ready_tx: StdMutex<Option<tokio::sync::oneshot::Sender<SocketAddr>>>,
    pub staging_dir: PathBuf,
    pub max_body: u64,
    pub pairings: StdMutex<Vec<PairingCode>>,
    /// device_id -> fingerprint sha256 del certificado (autorizados).
    pub devices: StdMutex<HashMap<String, String>>,
    /// CA del servidor para emitir certificados de cliente.
    pub ca: StdMutex<Option<Arc<vault_crypto::Identity>>>,
    /// Devuelve el JSON del manifest de hashes para un dispositivo.
    pub manifest: StdMutex<ManifestFn>,
    /// Ingesta de documentos recibidos.
    pub on_document: StdMutex<IngestFn>,
    /// Persistencia de emparejamiento: la bóveda registra el dispositivo en
    /// su BD para autorizarlo tras reinicios.
    pub on_paired: StdMutex<PairedFn>,
}

impl SyncState {
    pub fn new(
        staging_dir: PathBuf,
        max_body: u64,
        manifest: ManifestFn,
        on_document: IngestFn,
    ) -> Self {
        SyncState {
            ready_tx: StdMutex::new(None),
            staging_dir,
            max_body,
            pairings: StdMutex::new(Vec::new()),
            devices: StdMutex::new(HashMap::new()),
            ca: StdMutex::new(None),
            manifest: StdMutex::new(manifest),
            on_document: StdMutex::new(on_document),
            on_paired: StdMutex::new(Box::new(|_, _| {})),
        }
    }

    /// Registra el callback de persistencia de emparejamientos.
    pub fn set_on_paired(&self, f: PairedFn) {
        *self.on_paired.lock().unwrap() = f;
    }

    /// Registra el canal para recibir la dirección real del listener.
    pub fn set_ready_channel(&self, tx: tokio::sync::oneshot::Sender<SocketAddr>) {
        *self.ready_tx.lock().unwrap() = Some(tx);
    }

    pub fn set_ca(&self, ca: Arc<vault_crypto::Identity>) {
        *self.ca.lock().unwrap() = Some(ca);
    }

    /// Genera un código de emparejamiento válido 10 minutos.
    pub fn new_pairing_code(&self) -> String {
        let mut b = [0u8; 4];
        let _ = getrandom::getrandom(&mut b);
        let code: String = b.iter().map(|x| format!("{x:02X}")).collect();
        self.pairings.lock().unwrap().push(PairingCode {
            code: code.clone(),
            expires_at: now_epoch() + 600,
        });
        code
    }

    fn consume_pairing_code(&self, code: &str) -> bool {
        let mut pairings = self.pairings.lock().unwrap();
        let now = now_epoch();
        pairings.retain(|p| p.expires_at > now);
        let before = pairings.len();
        pairings.retain(|p| p.code != code);
        pairings.len() < before
    }

    fn register_device(&self, device_id: &str, fingerprint: &str) {
        self.devices
            .lock()
            .unwrap()
            .insert(device_id.to_string(), fingerprint.to_string());
    }

    fn is_authorized(&self, device_id: &str, fingerprint: &str) -> bool {
        match self.devices.lock().unwrap().get(device_id) {
            Some(fp) => fp == fingerprint,
            None => false,
        }
    }

    /// Emite certificado de cliente para un dispositivo emparejado.
    fn issue_client_certificate(&self, device_id: &str) -> Option<(String, String, String)> {
        let ca = self.ca.lock().unwrap().clone()?;
        crate::pair_new_device(&ca, device_id).ok()
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pone en marcha el servidor mTLS en `addr`. Devuelve la dirección real
/// (útil cuando se pasa puerto 0 en pruebas).
pub async fn serve(
    addr: SocketAddr,
    tls: ServerTlsConfig,
    state: Arc<SyncState>,
) -> Result<SocketAddr, SyncError> {
    let config = Arc::new(build_server_config(&tls)?);
    let acceptor = TlsAcceptor::from(config);
    let listener = TcpListener::bind(addr).await?;
    let real_addr = listener.local_addr()?;
    tracing::info!("vault-sync escuchando en {real_addr} (mTLS 1.3)");

    // Señaliza la dirección real para quien hizo spawn de esta tarea.
    if let Some(tx) = state.ready_tx.lock().unwrap().take() {
        let _ = tx.send(real_addr);
    }

    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_conn(tls_stream, state).await {
                        tracing::warn!("conexión: {e}");
                    }
                }
                Err(e) => tracing::warn!("handshake TLS fallido: {e}"),
            }
        });
    }
}

/// Extrae (device_id=CN, fingerprint) del certificado de cliente presentado.
fn client_identity(
    tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<(String, String)> {
    let (_, session) = tls_stream.get_ref();
    let certs = session.peer_certificates()?;
    let leaf = certs.first()?;
    Some(cert_identity(leaf))
}

fn cert_identity(cert: &CertificateDer<'_>) -> (String, String) {
    let cn = parse_cn(cert).unwrap_or_default();
    let fingerprint = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(cert.as_ref()))
    };
    (cn, fingerprint)
}

fn parse_cn(cert: &CertificateDer<'_>) -> Option<String> {
    let parsed = x509_cert::Certificate::from_der(cert.as_ref()).ok()?;
    for rdn in parsed.tbs_certificate.subject.0.iter() {
        for attr in rdn.0.iter() {
            if attr.oid.to_string() == "2.5.4.3" {
                if let Ok(s) = attr.value.decode_as::<der::asn1::Utf8StringRef>() {
                    return Some(s.to_string());
                }
                if let Ok(s) = attr.value.decode_as::<der::asn1::PrintableStringRef>() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Tiempo máximo de inactividad entre peticiones de una misma conexión.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn handle_conn(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<SyncState>,
) -> Result<(), SyncError> {
    let identity = client_identity(&tls_stream);
    loop {
        // Ninguna conexión puede quedar colgada esperando indefinidamente.
        let request = match tokio::time::timeout(
            IDLE_TIMEOUT,
            read_http_request(&mut tls_stream, state.max_body),
        )
        .await
        {
            Ok(Ok(Some(r))) => r,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };

        let (method, path, headers, body) = request;
        // El cliente indica si quiere cerrar; hay que honrarlo (si no, un
        // cliente que espera el fin de la respuesta nunca lo recibe).
        let close = headers
            .get("connection")
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);
        let (status, json) = match (method.as_str(), path.as_str()) {
            ("GET", "/v1/ping") => match require_auth(&identity, &state) {
                Ok(_) => (
                    200,
                    r#"{"status":"ok","service":"vault-sync","protocol":"1.0"}"#.to_string(),
                ),
                Err(e) => (403, format!(r#"{{"error":"{e}"}}"#)),
            },
            ("GET", "/v1/manifest") => match require_auth(&identity, &state) {
                Ok(_) => {
                    let device_id = identity
                        .as_ref()
                        .map(|(d, _)| d.clone())
                        .unwrap_or_default();
                    let manifest = state.manifest.lock().unwrap()(&device_id);
                    (200, manifest)
                }
                Err(e) => (403, format!(r#"{{"error":"{e}"}}"#)),
            },
            ("POST", "/v1/upload") => {
                match require_auth(&identity, &state) {
                    Ok(_) => {
                        let device_id = identity
                            .as_ref()
                            .map(|(d, _)| d.clone())
                            .unwrap_or_default();
                        match body {
                            None => (400, r#"{"error":"body requerido"}"#.to_string()),
                            // envelope: primera línea del body; el resto: bytes del archivo
                            Some(body) => match body.iter().position(|&b| b == b'\n') {
                                None => (
                                    400,
                                    r#"{"error":"envelope inválido: falta salto de línea"}"#
                                        .to_string(),
                                ),
                                Some(nl) => {
                                    let envelope = String::from_utf8_lossy(&body[..nl]).to_string();
                                    let file_bytes = &body[nl + 1..];
                                    let digest = {
                                        use sha2::Digest;
                                        hex::encode(sha2::Sha256::digest(file_bytes))
                                    };
                                    let staging_path =
                                        state.staging_dir.join(format!("{digest}.incoming"));
                                    if let Err(e) =
                                        tokio::fs::write(&staging_path, file_bytes).await
                                    {
                                        (500, format!(r#"{{"error":"staging: {e}"}}"#))
                                    } else {
                                        match state.on_document.lock().unwrap()(
                                            &device_id,
                                            &envelope,
                                            &staging_path,
                                        ) {
                                            Ok(ack) => (200, ack),
                                            Err(e) => (422, format!(r#"{{"error":"{e}"}}"#)),
                                        }
                                    }
                                }
                            },
                        }
                    }
                    Err(e) => (403, format!(r#"{{"error":"{e}"}}"#)),
                }
            }
            ("POST", "/v1/pair") => {
                // sin mTLS: requiere código de un solo uso
                let body = body.unwrap_or_default();
                match serde_json::from_slice::<serde_json::Value>(&body) {
                    Err(e) => (400, format!(r#"{{"error":"json: {e}"}}"#)),
                    Ok(req) => {
                        let code = req["code"].as_str().unwrap_or("").to_string();
                        let device_id = req["device_id"].as_str().unwrap_or("").to_string();
                        if device_id.is_empty() {
                            (400, r#"{"error":"device_id requerido"}"#.to_string())
                        } else if !state.consume_pairing_code(&code) {
                            (
                                403,
                                r#"{"error":"código de emparejamiento inválido o expirado"}"#
                                    .to_string(),
                            )
                        } else {
                            match state.issue_client_certificate(&device_id) {
                                Some((key_pem, cert_pem, fingerprint)) => {
                                    state.register_device(&device_id, &fingerprint);
                                    state.on_paired.lock().unwrap()(&device_id, &fingerprint);
                                    let json = serde_json::json!({
                                        "status": "paired",
                                        "client_key_pem": key_pem,
                                        "client_cert_pem": cert_pem,
                                        "cert_fingerprint": fingerprint,
                                    });
                                    (200, json.to_string())
                                }
                                None => (
                                    500,
                                    r#"{"error":"no se pudo emitir el certificado"}"#.to_string(),
                                ),
                            }
                        }
                    }
                }
            }
            _ => (404, r#"{"error":"no encontrado"}"#.to_string()),
        };
        write_json(&mut tls_stream, status, &json, close).await?;
        if close {
            // Cierre ordenado: quien pidió cerrar recibe el fin del flujo.
            let _ = tls_stream.shutdown().await;
            return Ok(());
        }
    }
}

async fn write_json(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    status: u16,
    json: &str,
    close: bool,
) -> Result<(), SyncError> {
    let response = json_response(status, json, close);
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

fn require_auth(
    identity: &Option<(String, String)>,
    state: &Arc<SyncState>,
) -> Result<(), SyncError> {
    let (device_id, fingerprint) = identity.clone().ok_or(SyncError::ClientCertRequired)?;
    if state.is_authorized(&device_id, &fingerprint) {
        Ok(())
    } else {
        Err(SyncError::UnauthorizedDevice(device_id))
    }
}

/// Lee una petición HTTP/1.1 completa del stream TLS.
async fn read_http_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    max_body: u64,
) -> Result<Option<(String, String, HashMap<String, String>, Option<Vec<u8>>)>, SyncError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(SyncError::Http("conexión cortada en headers".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(SyncError::Http("headers demasiado grandes".into()));
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| SyncError::Http("petición vacía".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    // Solo se acepta cuerpo delimitado por Content-Length: con un framing
    // desconocido se corta la conexión en lugar de desincronizar el flujo.
    if headers
        .get("transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return Err(SyncError::Http(
            "transfer-encoding no soportado: use Content-Length".into(),
        ));
    }
    let content_length: u64 = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > max_body {
        return Err(SyncError::Http("body demasiado grande".into()));
    }
    let mut body: Vec<u8> = buf[header_end + 4..].to_vec();
    while body.len() < content_length as usize {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(SyncError::Http("conexión cortada en body".into()));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length as usize);
    let body_opt = if content_length > 0 { Some(body) } else { None };
    Ok(Some((method, path, headers, body_opt)))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn json_response(status: u16, json: &str, close: bool) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        _ => "Error",
    };
    let connection = if close { "close" } else { "keep-alive" };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n{json}",
        json.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_response_declares_length_and_connection() {
        let keep = String::from_utf8(json_response(200, r#"{"a":1}"#, false)).unwrap();
        assert!(keep.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(keep.contains("Content-Length: 7\r\n"));
        assert!(keep.contains("Connection: keep-alive\r\n"));
        assert!(keep.ends_with(r#"{"a":1}"#));

        let close = String::from_utf8(json_response(403, r#"{"e":1}"#, true)).unwrap();
        assert!(close.contains("403 Forbidden"));
        assert!(close.contains("Connection: close\r\n"));
    }

    #[test]
    fn pairing_code_is_single_use_and_expires() {
        let state = SyncState::new(
            std::env::temp_dir(),
            1024,
            Box::new(|_| "{}".to_string()),
            Box::new(|_, _, _| Ok("{}".to_string())),
        );
        let code = state.new_pairing_code();
        assert_eq!(code.len(), 8, "código de 4 bytes en hex");
        assert!(state.consume_pairing_code(&code), "el primer uso vale");
        assert!(!state.consume_pairing_code(&code), "el segundo uso NO vale");
        assert!(!state.consume_pairing_code("00000000"));

        // código caducado: nunca se acepta
        state.pairings.lock().unwrap().push(PairingCode {
            code: "AAAA1111".into(),
            expires_at: now_epoch().saturating_sub(1),
        });
        assert!(!state.consume_pairing_code("AAAA1111"));
    }

    #[test]
    fn only_authorized_fingerprints_pass() {
        let state = SyncState::new(
            std::env::temp_dir(),
            1024,
            Box::new(|_| "{}".to_string()),
            Box::new(|_, _, _| Ok("{}".to_string())),
        );
        let state = Arc::new(state);
        assert!(matches!(
            require_auth(&None, &state),
            Err(SyncError::ClientCertRequired)
        ));
        let unknown = Some(("AND_1".to_string(), "aa".repeat(32)));
        assert!(matches!(
            require_auth(&unknown, &state),
            Err(SyncError::UnauthorizedDevice(_))
        ));

        state.register_device("AND_1", &"aa".repeat(32));
        assert!(require_auth(&unknown, &state).is_ok());
        // misma identidad, huella distinta (certificado rotado) → rechazado
        let rotated = Some(("AND_1".to_string(), "bb".repeat(32)));
        assert!(require_auth(&rotated, &state).is_err());
    }

    #[test]
    fn header_end_detection_and_oversized_headers() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(14));
        assert_eq!(find_header_end(b"sin fin de cabeceras"), None);
    }
}
