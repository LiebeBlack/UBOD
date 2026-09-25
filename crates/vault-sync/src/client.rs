//! Cliente mTLS de sincronización: lo usa `vaultctl`, el simulador de móvil
//! y las pruebas E2E. Implementa el flujo completo del protocolo:
//! emparejar (código de un solo uso) → ping → manifest → upload → ACK.

use crate::ClientTlsConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error TLS: {0}")]
    Tls(String),
    #[error("respuesta HTTP inválida: {0}")]
    Http(String),
    #[error("el servidor devolvió {status}: {body}")]
    Api { status: u16, body: String },
    #[error("tiempo de espera agotado: la bóveda no respondió a tiempo")]
    Timeout,
}

/// Tope de tiempo de cada operación de red del canal: conexión, saludo TLS,
/// lectura de la respuesta y de cada parte de ella.
///
/// Sin él, un servidor que acepta la conexión y luego calla (o una respuesta
/// truncada) dejaría al cliente esperando para siempre; en la CI eso equivale a
/// un test colgado durante horas.
pub const NET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Resultado de una respuesta HTTP.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Cliente mTLS conectado a una bóveda.
pub struct VaultClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    addr: std::net::SocketAddr,
}

impl VaultClient {
    /// Se conecta usando configuración TLS de dispositivo (cert + CA).
    pub fn connect(cfg: &ClientTlsConfig, addr: std::net::SocketAddr) -> Result<Self, ClientError> {
        let tls = Arc::new(cfg.build().map_err(|e| ClientError::Tls(e.to_string()))?);
        let server_name = ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| ClientError::Tls(format!("server name: {e}")))?;
        Ok(VaultClient {
            connector: TlsConnector::from(tls),
            server_name,
            addr,
        })
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Response, ClientError> {
        let exchange = async {
            let tcp = TcpStream::connect(self.addr).await?;
            let mut tls = self
                .connector
                .connect(self.server_name.clone(), tcp)
                .await?;
            let body = body.unwrap_or_default();
            let head = format!(
                "{method} {path} HTTP/1.1\r\nHost: vault\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(head.as_bytes()).await?;
            if !body.is_empty() {
                tls.write_all(&body).await?;
            }
            tls.flush().await?;
            // La respuesta se delimita por Content-Length: esperar el fin del flujo
            // dejaría la petición bloqueada para siempre (el servidor mantiene viva
            // la conexión hasta que se le pide cerrar).
            read_response(&mut tls).await
        };
        // Tope global: ni la conexión, ni el handshake, ni la respuesta pueden
        // eternizarse.
        match tokio::time::timeout(NET_TIMEOUT, exchange).await {
            Ok(result) => result,
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// GET /v1/ping — verifica sesión mTLS y autorización del dispositivo.
    pub async fn ping(&self) -> Result<Response, ClientError> {
        self.request("GET", "/v1/ping", None).await
    }

    /// GET /v1/manifest — hashes presentes en la bóveda.
    pub async fn manifest(&self) -> Result<Response, ClientError> {
        self.request("GET", "/v1/manifest", None).await
    }

    /// POST /v1/pair — sin mTLS: código de un solo uso → certificado de cliente.
    pub async fn pair(&self, code: &str, device_id: &str) -> Result<Response, ClientError> {
        let body = serde_json::json!({ "code": code, "device_id": device_id });
        self.request("POST", "/v1/pair", Some(body.to_string().into_bytes()))
            .await
    }

    /// POST /v1/upload — envelope JSON + bytes; devuelve el ACK de la bóveda.
    pub async fn upload(
        &self,
        envelope_json: &str,
        file_bytes: &[u8],
    ) -> Result<Response, ClientError> {
        let mut body = envelope_json.as_bytes().to_vec();
        body.push(b'\n');
        body.extend_from_slice(file_bytes);
        self.request("POST", "/v1/upload", Some(body)).await
    }
}

/// Cabeceras relevantes de una respuesta HTTP/1.1.
#[derive(Debug, Clone, Copy)]
struct ResponseHead {
    status: u16,
    content_length: usize,
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_head(head: &str) -> Result<ResponseHead, ClientError> {
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ClientError::Http("línea de estado inválida".into()))?;
    let content_length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .ok_or_else(|| ClientError::Http("falta Content-Length en la respuesta".into()))?;
    Ok(ResponseHead {
        status,
        content_length,
    })
}

/// Lee del stream con [`NET_TIMEOUT`]: una lectura que nunca llega se traduce
/// en error en lugar de colgar la petición.
async fn read_bounded<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    tmp: &mut [u8],
) -> Result<usize, ClientError> {
    tokio::time::timeout(NET_TIMEOUT, stream.read(tmp))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::from)
}

/// Lee una respuesta completa: cabeceras y **exactamente** `Content-Length`
/// bytes de cuerpo.
///
/// Esperar el fin del flujo (`read_to_end`) bloquearía la petición: el
/// servidor mantiene viva la conexión hasta que se le pide cerrar.
pub async fn read_response<S: AsyncReadExt + Unpin>(
    stream: &mut S,
) -> Result<Response, ClientError> {
    const MAX_HEADERS: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(p) = find_header_end(&buf) {
            break p;
        }
        let n = read_bounded(stream, &mut tmp).await?;
        if n == 0 {
            return Err(ClientError::Http(
                "conexión cerrada antes de recibir las cabeceras".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEADERS {
            return Err(ClientError::Http("cabeceras demasiado grandes".into()));
        }
    };
    let head = parse_head(&String::from_utf8_lossy(&buf[..header_end]))?;
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < head.content_length {
        let n = read_bounded(stream, &mut tmp).await?;
        if n == 0 {
            return Err(ClientError::Http(format!(
                "cuerpo incompleto: {} de {} bytes",
                body.len(),
                head.content_length
            )));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(head.content_length);
    Ok(Response {
        status: head.status,
        body,
    })
}

/// Cargo/crea la identidad de un dispositivo cliente desde disco.
pub struct DeviceIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn load_client_tls(
    cert_pem: &str,
    key_pem: &str,
    ca_pem: &str,
    server_name: &str,
) -> Result<ClientTlsConfig, ClientError> {
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    let key = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| ClientError::Tls(e.to_string()))?,
    );
    let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .map_err(|e| ClientError::Tls(e.to_string()))?;
    Ok(ClientTlsConfig {
        client_cert_der: cert,
        client_key_der: key,
        ca_der: ca,
        server_name: server_name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_head_reads_status_and_length() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\nConnection: close";
        let h = parse_head(head).unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.content_length, 17);

        // minúsculas y espacios: igual de válido
        let h = parse_head("HTTP/1.1 403 Forbidden\ncontent-length: 2").unwrap();
        assert_eq!(h.status, 403);
        assert_eq!(h.content_length, 2);
    }

    #[test]
    fn parse_head_rejects_invalid() {
        assert!(parse_head("no-es-http\r\nContent-Length: 1").is_err());
        assert!(parse_head("HTTP/1.1 200 OK\r\nServer: x").is_err());
    }

    #[test]
    fn read_response_waits_only_for_declared_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\n{\"a\":1}"
                .to_vec();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Aunque la conexión siga abierta (bytes de más), la lectura termina
        // al completar el cuerpo declarado: eso evita el bloqueo.
        let mut with_extra = raw.clone();
        with_extra.extend_from_slice(b"siguiente respuesta");
        let mut src: &[u8] = &with_extra;
        let resp = rt.block_on(read_response(&mut src)).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text(), "{\"a\":1}");
    }

    #[test]
    fn read_response_detects_truncated_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\ncorto".to_vec();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut src: &[u8] = &raw;
        let err = rt.block_on(read_response(&mut src)).unwrap_err();
        assert!(format!("{err}").contains("incompleto"), "error: {err}");
    }
}
