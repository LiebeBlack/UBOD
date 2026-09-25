//! E2E del canal mTLS: servidor real ([`vault_sync::serve`]) contra cliente real
//! ([`vault_client`]) en loopback, **sin el daemon de por medio**.
//!
//! Cubre el camino completo del dispositivo móvil:
//!
//! 1. emparejamiento con código de un solo uso (sin mTLS todavía),
//! 2. sesión mTLS con el certificado emitido por la CA de la bóveda,
//! 3. `ping` autenticado y `upload` del documento (envelope + bytes),
//! 4. y los rechazos que protegen la bóveda.
//!
//! El servidor vive en un runtime de Tokio propio; el cliente es síncrono por
//! diseño (crea su propio runtime), así que las llamadas se hacen desde el hilo
//! del test y nunca dentro de un contexto de runtime.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use vault_client::{pair, ping, upload_file, PairedDevice};
use vault_sync::server::SyncState;
use vault_sync::ServerTlsConfig;

/// Documento recibido por el servidor (lo captura el callback de ingesta).
#[derive(Debug, Clone)]
struct Received {
    device_id: String,
    envelope: String,
    bytes: Vec<u8>,
}

/// Tope de tiempo para que el servidor mTLS publique su dirección de escucha.
/// Sin él, un arranque fallido dejaría la prueba esperando para siempre.
const STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Servidor mTLS real escuchando en un puerto libre de loopback.
struct Server {
    addr: std::net::SocketAddr,
    ca_pem: String,
    state: Arc<SyncState>,
    received: Arc<Mutex<Vec<Received>>>,
    paired: Arc<Mutex<Vec<(String, String)>>>,
    /// Mantiene viva la PKI temporal durante el test.
    _dir: tempfile::TempDir,
}

impl Server {
    /// Arranca el servidor dentro de `rt` y devuelve un handle ya escuchando.
    fn start(rt: &tokio::runtime::Runtime) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let pki = dir.path().join("pki");
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let tls = ServerTlsConfig::load_or_create(&pki, "vault-server").unwrap();
        let ca = Arc::new(vault_crypto::Identity::load(&pki, "ca").unwrap());
        let ca_pem = vault_crypto::pem_encode_cert(&ca.cert_der);

        let received: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
        let paired: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));

        let sink = received.clone();
        let on_document = Box::new(
            move |device_id: &str, envelope: &str, path: &PathBuf| -> Result<String, String> {
                let bytes = std::fs::read(path).map_err(|e| format!("staging: {e}"))?;
                let mut guard = sink.lock().unwrap();
                let idx = guard.len();
                guard.push(Received {
                    device_id: device_id.to_string(),
                    envelope: envelope.to_string(),
                    bytes,
                });
                Ok(serde_json::json!({
                    "status": "pending_admission",
                    "submission_id": format!("SUB-{idx:04}"),
                })
                .to_string())
            },
        );
        let manifest = Box::new(|device_id: &str| {
            serde_json::json!({
                "protocol": "1.0",
                "device": device_id,
                "hashes": ["aa".repeat(32)],
            })
            .to_string()
        });

        let state = Arc::new(SyncState::new(
            staging,
            8 * 1024 * 1024,
            manifest,
            on_document,
        ));
        state.set_ca(ca);
        let paired_sink = paired.clone();
        state.set_on_paired(Box::new(move |device_id: &str, fingerprint: &str| {
            paired_sink
                .lock()
                .unwrap()
                .push((device_id.to_string(), fingerprint.to_string()));
        }));

        // `serve()` nunca termina: se lanza como tarea y la dirección real llega
        // por el canal de preparación del propio estado. La espera va acotada:
        // si el servidor falla al arrancar, la prueba falla en segundos en vez
        // de quedarse colgada (6 h de CI) como ocurría antes.
        let (tx, rx) = tokio::sync::oneshot::channel();
        state.set_ready_channel(tx);
        let serving = state.clone();
        rt.spawn(async move {
            let _ = vault_sync::serve("127.0.0.1:0".parse().unwrap(), tls, serving).await;
        });
        // El temporizador se crea DENTRO del runtime (`block_on` entra en él
        // sólo al sondear el futuro): fuera de ahí no hay reactor y `timeout`
        // aborta con «there is no reactor running».
        let addr = rt
            .block_on(async { tokio::time::timeout(STARTUP_TIMEOUT, rx).await })
            .expect("el servidor mTLS no publicó su dirección a tiempo")
            .expect("el servidor debe publicar su dirección");

        Server {
            addr,
            ca_pem,
            state,
            received,
            paired,
            _dir: dir,
        }
    }

    fn code(&self) -> String {
        self.state.new_pairing_code()
    }

    fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Camino feliz completo: emparejar, verificar la sesión mTLS y subir.
#[test]
fn mtls_pair_ping_and_upload_roundtrip() {
    let rt = runtime();
    let server = Server::start(&rt);

    // 1) Emparejamiento con código de un solo uso (sin mTLS todavía).
    let code = server.code();
    let device: PairedDevice = pair(server.addr, &server.ca_pem, &code, "AND_LOCAL").expect("pair");
    assert_eq!(device.device_id, "AND_LOCAL");
    assert!(device.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(device.key_pem.contains("PRIVATE KEY"));
    assert_eq!(device.fingerprint.len(), 64, "huella SHA-256 en hex");

    // El emparejamiento queda persistido en la bóveda (sobrevive reinicios).
    let paired = server.paired.lock().unwrap().clone();
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].0, "AND_LOCAL");
    assert_eq!(paired[0].1, device.fingerprint);

    // 2) Sesión mTLS autenticada.
    assert!(ping(server.addr, &device, &server.ca_pem).expect("ping"));

    // 3) Subida del documento: envelope + bytes.
    let docs = tempfile::tempdir().unwrap();
    let path = docs.path().join("Tesis_Ingenieria_2026.pdf");
    let content = b"Contenido completo de la tesis - E2E del canal mTLS";
    std::fs::write(&path, content).unwrap();

    let ack =
        upload_file(server.addr, &device, &server.ca_pem, &path, Some("Tesis")).expect("upload");
    assert_eq!(ack["status"], "pending_admission");
    assert_eq!(ack["submission_id"], "SUB-0000");

    // 4) El servidor recibió exactamente el contenido y conoce el dispositivo.
    let got = server.received();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].device_id, "AND_LOCAL");
    assert_eq!(got[0].bytes, content, "los bytes deben llegar íntegros");
    assert!(
        got[0].envelope.contains("Tesis_Ingenieria_2026.pdf"),
        "el envelope lleva los metadatos: {}",
        got[0].envelope
    );
    assert!(
        got[0].envelope.contains("sha256"),
        "el envelope lleva los hashes: {}",
        got[0].envelope
    );
}

/// Un código de emparejamiento inventado no abre la bóveda.
#[test]
fn pairing_rejects_unknown_code() {
    let rt = runtime();
    let server = Server::start(&rt);

    let err = pair(server.addr, &server.ca_pem, "CODIGO-FALSO", "AND_X")
        .expect_err("un código inventado no debe emparejar");
    let msg = format!("{err}");
    assert!(
        !msg.is_empty(),
        "el rechazo debe venir con un mensaje explicable"
    );
    assert!(server.paired.lock().unwrap().is_empty());
}

/// El código de emparejamiento es de UN SOLO USO: el segundo intento falla.
#[test]
fn pairing_code_is_single_use() {
    let rt = runtime();
    let server = Server::start(&rt);
    let code = server.code();

    let first = pair(server.addr, &server.ca_pem, &code, "AND_1").expect("primer uso válido");
    assert_eq!(first.device_id, "AND_1");

    let segundo = pair(server.addr, &server.ca_pem, &code, "AND_2");
    assert!(
        segundo.is_err(),
        "el mismo código no puede emparejar un segundo dispositivo"
    );
    assert_eq!(server.paired.lock().unwrap().len(), 1);
}

/// Un certificado emitido por OTRA autoridad no sirve para el canal de la bóveda.
#[test]
fn foreign_certificate_cannot_use_the_channel() {
    let rt = runtime();
    let server = Server::start(&rt);

    let otra_ca = vault_crypto::Identity::generate()
        .self_sign_ca("Otra CA", 3650)
        .unwrap();
    let (key_pem, cert_pem, fingerprint) =
        vault_sync::pair_new_device(&otra_ca, "AND_INTRUSO").unwrap();
    let intruso = PairedDevice {
        device_id: "AND_INTRUSO".into(),
        cert_pem,
        key_pem,
        fingerprint,
    };

    // El cliente verifica el servidor con la CA legítima, pero se presenta con
    // un certificado ajeno: la sesión no puede darse por buena.
    let res = ping(server.addr, &intruso, &server.ca_pem);
    assert!(
        matches!(res, Err(_) | Ok(false)),
        "un certificado ajeno no debe autenticar: {res:?}"
    );

    // Y tampoco puede colar un documento.
    let docs = tempfile::tempdir().unwrap();
    let path = docs.path().join("intruso.pdf");
    std::fs::write(&path, b"documento no autorizado").unwrap();
    let up = upload_file(server.addr, &intruso, &server.ca_pem, &path, None);
    assert!(up.is_err(), "la subida sin autorización debe rechazarse");
    assert!(
        server.received().is_empty(),
        "nada debe llegar a staging desde un dispositivo ajeno"
    );
}

/// El canal exige un certificado de cliente: sin sesión mTLS no hay servicio.
#[test]
fn channel_requires_a_client_certificate() {
    use std::io::{Read, Write};

    let rt = runtime();
    let server = Server::start(&rt);

    // Conexión TCP desnuda: sin handshake TLS no hay respuesta del servicio.
    let mut stream = std::net::TcpStream::connect(server.addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let _ = stream.write_all(b"GET /v1/ping HTTP/1.1\r\nHost: vault.local\r\n\r\n");

    let mut buf = Vec::new();
    // El servidor intenta el handshake TLS y descarta la conexión: el cliente
    // recibe EOF o un error de lectura, nunca un 200.
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(
        !text.contains("200"),
        "una conexión sin TLS no puede obtener una respuesta 200: {text:?}"
    );
    assert!(server.received().is_empty());
}
