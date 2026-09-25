//! vaultd — daemon del Sistema Integral de Bóveda (Linux).
//!
//! Responsabilidades:
//! - Crear/mantener la estructura de la bóveda, el keyfile (0600) y la BD cifrada.
//! - Servir el canal de sincronización mTLS + mDNS para dispositivos móviles.
//! - Ingerir entregas: envelope + bytes → staging → cola de admisión.
//! - Barridos periódicos de integridad (anti bit-rot) y destrucciones vencidas.
//! - Panel de administración web en 127.0.0.1.
//!
//! Uso:
//!   vaultd [--config RUTA] [--init PIN]
//!
//! Config por defecto: ./vaultd.toml (se genera si no existe).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use serde::{Deserialize, Serialize};
use vault_admin::AdminService;
use vault_crypto::dbcrypto::generate_keyfile;
use vault_crypto::LocalTsa;
use vault_fs::VaultLayout;
use vault_store::VaultDb;
use vault_sync::server::SyncState;
use vault_sync::ServerTlsConfig;
use vault_webui::WebUiState;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de configuración: {0}")]
    Config(String),
    #[error("error de almacenamiento: {0}")]
    Store(#[from] vault_store::StoreError),
    #[error("error de sincronización: {0}")]
    Sync(#[from] vault_sync::SyncError),
    #[error("error criptográfico: {0}")]
    Crypto(String),
    #[error("error PKI: {0}")]
    Pki(#[from] vault_crypto::PkiError),
    #[error("error del sistema de archivos: {0}")]
    Fs(#[from] vault_fs::FsError),
}

/// Configuración persistente del daemon (vaultd.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Carpeta que contendrá la bóveda (documentos, staging, tombstones).
    pub vault_root: PathBuf,
    /// Carpeta de datos internos: keyfile, BD cifrada, PKI, TSA.
    pub data_dir: PathBuf,
    /// Dirección del panel de administración (siempre local).
    pub webui_listen: String,
    /// Dirección del canal de sincronización mTLS.
    pub sync_listen: String,
    /// Habilitar canal móvil (mTLS + mDNS).
    pub enable_sync: bool,
    /// Nombre de instancia para mDNS.
    pub mdns_instance: String,
    /// CN del certificado de servidor.
    pub server_cn: String,
}

impl Default for Config {
    fn default() -> Self {
        Config::single_machine()
    }
}

impl Config {
    /// Escenario soportado: TODO en un solo computador Linux, sin servidor
    /// externo. Todo vive bajo `~/.boveda/` del usuario (no requiere root).
    pub fn single_machine() -> Self {
        let base = dirs_home().join(".boveda");
        Config {
            vault_root: base.join("vault"),
            data_dir: base.join("data"),
            webui_listen: "127.0.0.1:8443".into(),
            // solo esta máquina se conecta a sí misma: loopback basta
            sync_listen: "127.0.0.1:8642".into(),
            enable_sync: false,
            mdns_instance: "Boveda".into(),
            server_cn: "vault-server".into(),
        }
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Config {
    /// Carga la config de `path`; si no existe, la crea con valores por defecto.
    pub fn load_or_create(path: &Path) -> Result<Config, DaemonError> {
        if path.exists() {
            let s = std::fs::read_to_string(path)?;
            toml::from_str(&s).map_err(|e| DaemonError::Config(e.to_string()))
        } else {
            let cfg = Config::single_machine();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let text =
                toml::to_string_pretty(&cfg).map_err(|e| DaemonError::Config(e.to_string()))?;
            std::fs::write(path, text)?;
            tracing::info!("config generada en {}", path.display());
            Ok(cfg)
        }
    }
}

/// Estado abierto del daemon. El `AdminService` se comparte entre el panel
/// web (hilos std) y los callbacks del servidor sync (tareas tokio) mediante
/// `Arc<Mutex<…>>`: una sola vista de la BD cifrada en memoria.
pub struct Vault {
    pub config: Config,
    pub admin: Arc<StdMutex<AdminService>>,
}

impl Vault {
    /// Abre (o inicializa) la bóveda completa: keyfile, BD, layout y TSA.
    pub fn open(config: Config) -> Result<Vault, DaemonError> {
        std::fs::create_dir_all(&config.vault_root)?;
        std::fs::create_dir_all(&config.data_dir)?;

        // keyfile de 64 bytes con permisos 0600: NUNCA se regenera.
        let keyfile_path = config.data_dir.join("vault.key");
        let keyfile: [u8; 64] = if keyfile_path.exists() {
            let raw = std::fs::read(&keyfile_path)?;
            let len = raw.len();
            raw.try_into().map_err(|_| {
                DaemonError::Crypto(format!(
                    "keyfile inválido: se esperaban 64 bytes, hay {len}"
                ))
            })?
        } else {
            let kf = generate_keyfile();
            std::fs::write(&keyfile_path, kf)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&keyfile_path, std::fs::Permissions::from_mode(0o600))?;
            }
            tracing::warn!(
                "keyfile nuevo en {} — respáldelo: sin él la bóveda es IRRECUPERABLE",
                keyfile_path.display()
            );
            kf
        };

        // Escritura exclusiva: el servicio es el único escritor de la BD. Si
        // otro proceso (p. ej. la app gráfica) la tiene abierta, se avisa en
        // lugar de arrancar con dos estados en memoria que se pisarían.
        let db = VaultDb::open_writer(&config.data_dir.join("db"), &keyfile)?;

        // usuarios conocidos (primer componente de las rutas ya custodiadas)
        let users: Vec<String> = db
            .documents()
            .iter()
            .map(|d| d.rel_path.split('/').next().unwrap_or("_").to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let layout = VaultLayout::new(&config.vault_root);
        layout.init(&users)?;

        let tsa = LocalTsa::new_persisted(&config.data_dir.join("tsa"))
            .map_err(|e| DaemonError::Crypto(e.to_string()))?;

        Ok(Vault {
            config,
            admin: Arc::new(StdMutex::new(AdminService::new(db, layout, tsa))),
        })
    }

    /// Configura el PIN de administrador inicial (solo si no existe).
    pub fn init_pin(&mut self, pin: &str) -> Result<(), DaemonError> {
        self.admin
            .lock()
            .unwrap()
            .set_admin_pin(None, pin)
            .map_err(|e| DaemonError::Config(format!("PIN: {e}")))?;
        Ok(())
    }

    /// Tope de tiempo para que el canal mTLS publique su dirección de escucha.
    const SYNC_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// Abre el canal móvil: servidor mTLS + anuncio mDNS. Devuelve el guard
    /// mDNS (retener mientras el daemon viva) y la dirección real de escucha.
    pub async fn start_sync(
        &self,
    ) -> Result<(Option<vault_sync::mdns::MdnsGuard>, std::net::SocketAddr), DaemonError> {
        let pki_dir = self.config.data_dir.join("pki");
        let tls = ServerTlsConfig::load_or_create(&pki_dir, &self.config.server_cn)?;
        let ca = Arc::new(vault_crypto::Identity::load(&pki_dir, "ca")?);

        let staging = self.config.vault_root.join(".staging");
        let admin_for_manifest = self.admin.clone();
        let manifest_fn = Box::new(move |device_id: &str| {
            let admin = admin_for_manifest.lock().unwrap();
            let hashes: Vec<String> = admin
                .db()
                .documents()
                .iter()
                .map(|d| d.sha256.clone())
                .collect();
            serde_json::json!({
                "protocol": "1.0",
                "device": device_id,
                "hashes": hashes,
            })
            .to_string()
        });

        let admin_for_ingest = self.admin.clone();
        let on_document = Box::new(
            move |device_id: &str,
                  envelope_json: &str,
                  staging_path: &PathBuf|
                  -> Result<String, String> {
                ingest_to_staging(&admin_for_ingest, device_id, envelope_json, staging_path)
            },
        );

        let state = Arc::new(SyncState::new(
            staging,
            512 * 1024 * 1024, // 512 MiB por entrega
            manifest_fn,
            on_document,
        ));
        state.set_ca(ca);

        // Emparejamientos → BD cifrada (sobrevive reinicios).
        let admin_for_pairing = self.admin.clone();
        state.set_on_paired(Box::new(move |device_id: &str, fingerprint: &str| {
            let mut svc = admin_for_pairing.lock().unwrap();
            svc.pair_device(device_id, fingerprint, "vaultd").ok();
        }));

        let listen: std::net::SocketAddr = self
            .config
            .sync_listen
            .parse()
            .map_err(|e| DaemonError::Config(format!("sync_listen: {e}")))?;
        // `serve()` atiende indefinidamente: se lanza como tarea y la dirección
        // real de escucha llega por el canal de preparación del estado. Si se
        // esperara a que `serve()` retornara, el daemon nunca arrancaría (ni el
        // panel ni el canal quedarían disponibles) y las pruebas E2E colgarían.
        let (tx, rx) = tokio::sync::oneshot::channel();
        state.set_ready_channel(tx);
        tokio::spawn(async move {
            if let Err(e) = vault_sync::serve(listen, tls, state).await {
                tracing::error!("canal de sincronización detenido: {e}");
            }
        });
        // Si el canal no llega a escuchar (PKI inválida, puerto ocupado) se falla
        // aquí con un error explícito, nunca en un bucle silencioso.
        let addr = match tokio::time::timeout(Self::SYNC_START_TIMEOUT, rx).await {
            Ok(Ok(addr)) => addr,
            Ok(Err(_)) => return Err(DaemonError::Config("PKI del canal no válida".into())),
            Err(_) => return Err(DaemonError::Config("el canal mTLS no arrancó".into())),
        };

        let guard = if self.config.enable_sync {
            match vault_sync::mdns::announce(addr.port(), &self.config.mdns_instance) {
                Ok(g) => Some(g),
                Err(e) => {
                    tracing::warn!("mDNS no disponible: {e}");
                    None
                }
            }
        } else {
            None
        };
        Ok((guard, addr))
    }

    /// Sirve el panel de administración local. Devuelve la dirección real.
    pub fn start_webui(&self) -> Result<std::net::SocketAddr, DaemonError> {
        let listen: std::net::SocketAddr = self
            .config
            .webui_listen
            .parse()
            .map_err(|e| DaemonError::Config(format!("webui_listen: {e}")))?;
        let state = WebUiState::new(self.admin.clone());
        Ok(vault_webui::serve(listen, state)?)
    }

    /// Ejecuta un barrido de integridad completo.
    pub fn sweep_now(&self) -> Result<vault_audit::SweepReport, vault_audit::AuditError> {
        let layout = VaultLayout::new(&self.config.vault_root);
        let mut admin = self.admin.lock().unwrap();
        vault_audit::sweep(admin.db_mut(), &layout)
    }

    /// Ejecuta destrucciones cuya ventana de gracia venció.
    pub fn process_due_destructions(&self) -> Result<usize, vault_admin::AdminError> {
        self.admin
            .lock()
            .unwrap()
            .process_due_destructions("vaultd")
    }
}

/// PIN aleatorio de 8 dígitos (para --quickstart sin PIN explícito).
fn random_pin() -> String {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).expect("os randomness");
    let n = u32::from_be_bytes(b) % 100_000_000;
    format!("{n:08}")
}

/// Ingresa una entrega: valida envelope + hashes y la deja en la cola de
/// admisión. Es la función `on_document` del servidor de sincronización.
fn ingest_to_staging(
    admin: &Arc<StdMutex<AdminService>>,
    device_id: &str,
    envelope_json: &str,
    staging_path: &PathBuf,
) -> Result<String, String> {
    let envelope: vault_core::TransferEnvelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("envelope inválido: {e}"))?;
    if envelope.header.protocol_version != vault_core::TransferEnvelope::PROTOCOL_VERSION {
        return Err(format!(
            "versión de protocolo no soportada: {}",
            envelope.header.protocol_version
        ));
    }
    let bytes = std::fs::read(staging_path).map_err(|e| format!("staging: {e}"))?;
    let hp = vault_crypto::HashPair::from_bytes(&bytes);
    if hp.sha256 != envelope.payload.sha256 {
        // el archivo no es lo declarado: descartarlo de inmediato
        let _ = std::fs::remove_file(staging_path);
        return Err("hash SHA-256 no coincide con el envelope".into());
    }
    if bytes.len() as u64 != envelope.payload.file_size_bytes {
        let _ = std::fs::remove_file(staging_path);
        return Err("tamaño no coincide con el envelope".into());
    }

    // nombre definitivo dentro de staging (hash → trazable y sin colisiones)
    let final_name = format!("{}.incoming", hp.sha256);
    let final_path = staging_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(final_name);
    std::fs::rename(staging_path, &final_path).map_err(|e| format!("staging rename: {e}"))?;

    let category = vault_core::Category::from_dir_name(&envelope.payload.file_category)
        .ok_or_else(|| format!("categoría desconocida: {}", envelope.payload.file_category))?;

    let sub = vault_core::Submission {
        submission_id: vault_core::new_id(),
        device_id: device_id.to_string(),
        meta: vault_core::DocumentMeta {
            title: if envelope.payload.title.is_empty() {
                envelope.payload.file_name.clone()
            } else {
                envelope.payload.title.clone()
            },
            category,
            author: envelope.payload.author.clone(),
            id_number: envelope.payload.id_number.clone(),
            department: envelope.payload.department.clone(),
            registered_at: vault_core::now_rfc3339(),
            academic_year: envelope.payload.academic_year,
            file_name: envelope.payload.file_name.clone(),
            extension: envelope
                .payload
                .file_name
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_lowercase(),
        },
        sha256: hp.sha256,
        blake3: hp.blake3,
        size_bytes: bytes.len() as u64,
        staging_path: final_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        received_at: vault_core::now_rfc3339(),
        state: vault_core::AdmissionState::Pending,
    };

    let ack = serde_json::json!({
        "status": "pending_admission",
        "submission_id": sub.submission_id,
        "sha256": sub.sha256,
        "blake3": sub.blake3,
        "message": "recibido; en cola de admisión",
    });

    let mut svc = admin.lock().unwrap();
    svc.db_mut().add_submission(sub);
    svc.db_mut().append_audit(
        device_id,
        "upload_received",
        &envelope.payload.sha256,
        &format!(
            "archivo={} categoría={}",
            envelope.payload.file_name, envelope.payload.file_category
        ),
    );
    svc.db_mut().flush().map_err(|e| format!("bd: {e}"))?;
    Ok(ack.to_string())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    let mut arg_iter = std::env::args().skip(1).peekable();
    let mut config_path = dirs_home().join(".boveda").join("vaultd.toml");
    let mut init_pin: Option<String> = None;
    let mut quickstart: Option<String> = None;
    // Endurecimiento por defecto: el daemon sólo podrá leer la bóveda y
    // escribir en staging (Landlock, Linux). Se desactiva con `--no-landlock`
    // para kernels antiguos o entornos en contenedor que no lo soportan; si la
    // activación falla se avisa y el servicio continúa.
    let mut landlock = true;
    let args = &mut arg_iter;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                config_path = args.next().map(PathBuf::from).unwrap_or(config_path);
            }
            "--init" => {
                init_pin = args.next();
            }
            "--landlock" => {
                landlock = true;
            }
            "--no-landlock" => {
                landlock = false;
            }
            "--quickstart" => {
                // acepta `--quickstart PIN` o solo `--quickstart` (PIN aleatorio)
                quickstart = match args.peek() {
                    Some(next) if !next.starts_with('-') => args.next(),
                    _ => Some(String::new()),
                };
            }
            "--help" | "-h" => {
                println!("vaultd — daemon de la bóveda académica (una sola máquina Linux)");
                println!();
                println!("  --quickstart [PIN]   TODO-EN-UNO: crea bóveda + PIN + CA y arranca el servidor.");
                println!(
                    "                       Sin PIN genera uno aleatorio y lo muestra una vez."
                );
                println!("  --init PIN           solo configura el PIN de administrador y sale");
                println!("  --config RUTA        archivo de configuración (por defecto ~/.boveda/vaultd.toml)");
                println!("  --landlock           fuerza la restricción de acceso al sistema de archivos (Linux)");
                println!(
                    "  --no-landlock        no restringe el acceso al sistema de archivos (Linux)"
                );
                println!("                       por defecto la restricción SÍ se aplica si el kernel la soporta");
                println!();
                println!("Flujo en una sola máquina:");
                println!(
                    "  1) vaultd --quickstart MiPinSeguro        # levanta la bóveda y el servidor"
                );
                println!("  2) vaultctl discover                      # muestra la IP:puerto del canal mTLS");
                println!("  3) vaultctl pair <ip:puerto> <código> AND_LOCAL --ca ~/.boveda/data/pki/ca.crt.pem");
                println!("     (el código de un solo uso sale del panel: botón «Generar código»)");
                println!("  4) abre http://localhost:8443/ e inicia sesión con el PIN");
                std::process::exit(0);
            }
            other => {
                eprintln!("argumento desconocido: {other} (vea --help)");
                std::process::exit(2);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run(config_path, init_pin, quickstart, landlock) {
        tracing::error!("vaultd: {e}");
        std::process::exit(1);
    }
}

fn run(
    config_path: PathBuf,
    init_pin: Option<String>,
    quickstart: Option<String>,
    landlock: bool,
) -> Result<(), DaemonError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| DaemonError::Config(format!("runtime: {e}")))?;
    rt.block_on(async_run(config_path, init_pin, quickstart, landlock))
}

async fn async_run(
    config_path: PathBuf,
    init_pin: Option<String>,
    quickstart: Option<String>,
    landlock: bool,
) -> Result<(), DaemonError> {
    let config = Config::load_or_create(&config_path)?;
    let mut vault = Vault::open(config)?;

    // --quickstart: init (si falta) + arranque; pensado para la primera vez.
    if let Some(pin) = quickstart {
        let pin = if pin.is_empty() { random_pin() } else { pin };
        if vault.admin.lock().unwrap().db().admin_pin_hash().is_none() {
            vault.init_pin(&pin)?;
            println!();
            println!("  ╔════════════════════════════════════════════════╗");
            println!("  ║  PIN de administrador (guárdelo, no se repite): ║");
            println!("  ║              {pin}                           ║");
            println!("  ╚════════════════════════════════════════════════╝");
            println!();
        } else {
            tracing::info!("PIN ya configurado; --quickstart no lo cambia");
        }
    }

    if let Some(pin) = init_pin {
        vault.init_pin(&pin)?;
        tracing::info!("PIN de administrador configurado");
        return Ok(());
    }

    if vault.admin.lock().unwrap().db().admin_pin_hash().is_none() {
        return Err(DaemonError::Config(
            "sin PIN de administrador: ejecute «vaultd --init PIN» primero".into(),
        ));
    }

    // Barrido inicial: detecta apagones/corrupción ocurridos al estar apagado.
    match vault.sweep_now() {
        Ok(r) if r.problems.is_empty() => {
            tracing::info!("barrido inicial: {} documentos íntegros", r.checked);
        }
        Ok(r) => {
            tracing::warn!(
                "barrido inicial: {} problemas (perdidos={}, manipulados={})",
                r.problems.len(),
                r.missing,
                r.tampered
            );
        }
        Err(e) => tracing::warn!("barrido inicial falló: {e}"),
    }

    // Canal móvil (en una sola máquina: loopback).
    let (_mdns_guard, sync_addr) = vault.start_sync().await?;
    tracing::info!("canal de sincronización mTLS en {sync_addr}");

    // Endurecimiento del proceso (Linux): el servicio queda confinado a la
    // bóveda y a `<datos>`; fuera de ahí sólo puede leer los directorios de
    // sistema imprescindibles. Se avisa y se continúa si el kernel no lo
    // soporta: la bóveda sigue funcionando sin el sandbox.
    if landlock {
        // Las rutas deben existir ANTES de aplicar las reglas: Landlock no puede
        // conceder acceso a algo que todavía no está en el sistema de archivos.
        let _ = std::fs::create_dir_all(&vault.config.vault_root);
        let _ = std::fs::create_dir_all(&vault.config.data_dir);
        match vault_fs::apply_landlock(&vault.config.vault_root, &vault.config.data_dir) {
            Ok(()) => tracing::info!("landlock activado: sólo la bóveda y <datos> son escribibles"),
            Err(e) => {
                tracing::warn!("landlock no aplicado ({e}); el servicio continúa sin confinamiento")
            }
        }
    }

    // Exportar la CA de la bóveda donde vaultctl la encuentra (--ca).
    let ca_dst = vault.config.data_dir.join("ca.pem");
    let ca_src = vault.config.data_dir.join("pki/ca.crt.pem");
    if ca_src.exists() {
        std::fs::copy(&ca_src, &ca_dst)?;
    }

    // Panel local.
    let webui_addr = vault.start_webui()?;
    tracing::info!("panel de administración en http://{webui_addr}/");

    println!();
    println!("  Bóveda académica lista — TODO en esta máquina, sin servidor externo.");
    println!("  ─────────────────────────────────────────────────────────────────");
    println!("  Panel de administración : http://{webui_addr}/");
    println!("  Canal mTLS (para vaultctl): {sync_addr}");
    println!("  CA para emparejar       : {}", ca_dst.display());
    println!();
    println!("  Emparejar esta máquina como dispositivo:");
    println!("    1. Panel → «Generar código de emparejamiento»");
    println!(
        "    2. vaultctl pair {sync_addr} <CÓDIGO> AND_LOCAL --ca {}",
        ca_dst.display()
    );
    println!("    3. vaultctl upload {sync_addr} documento.pdf");
    println!();
    println!("  La aplicación gráfica puede abrirse en paralelo: detecta este servicio");
    println!("  y se abre en modo consulta (solo lectura) para no pisar los cambios.");
    println!();
    println!(
        "  Ctrl-C para apagar. La bóveda queda en {}",
        vault.config.vault_root.display()
    );
    println!();

    // Bucle periódico: destrucciones vencidas cada minuto y sweep a intervalo.
    let sweep_interval = {
        let secs = vault
            .admin
            .lock()
            .unwrap()
            .db()
            .settings()
            .sweep_interval_secs
            .max(60);
        std::time::Duration::from_secs(secs)
    };
    let mut last_sweep = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("señal de apagado recibida; cerrando");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                match vault.process_due_destructions() {
                    Ok(0) => {}
                    Ok(n) => tracing::info!("{n} destrucciones ejecutadas (gracia vencida)"),
                    Err(e) => tracing::warn!("destrucciones: {e}"),
                }
                if last_sweep.elapsed() >= sweep_interval {
                    match vault.sweep_now() {
                        Ok(r) if r.problems.is_empty() => {
                            tracing::info!("sweep: {} documentos íntegros", r.checked);
                        }
                        Ok(r) => tracing::warn!(
                            "sweep: {} problemas (perdidos={}, manipulados={})",
                            r.problems.len(), r.missing, r.tampered
                        ),
                        Err(e) => tracing::warn!("sweep: {e}"),
                    }
                    last_sweep = std::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(dir: &Path) -> Config {
        Config {
            vault_root: dir.join("vault"),
            data_dir: dir.join("data"),
            webui_listen: "127.0.0.1:0".into(),
            sync_listen: "127.0.0.1:0".into(),
            enable_sync: false, // sin mDNS en pruebas
            mdns_instance: "Test".into(),
            server_cn: "vault-test".into(),
        }
    }

    #[test]
    fn config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vaultd.toml");
        let cfg = Config::load_or_create(&p).unwrap();
        // El escenario soportado es UNA sola máquina: el canal mTLS escucha
        // solo en loopback, nunca en todas las interfaces.
        assert_eq!(cfg.sync_listen, "127.0.0.1:8642");
        let cfg2 = Config::load_or_create(&p).unwrap();
        assert_eq!(cfg.vault_root, cfg2.vault_root);
        // una config corrupta da error claro
        std::fs::write(&p, "esto no es toml =").unwrap();
        assert!(Config::load_or_create(&p).is_err());
    }

    #[test]
    fn config_defaults_are_loopback_only() {
        let cfg = Config::single_machine();
        for addr in [&cfg.webui_listen, &cfg.sync_listen] {
            let ip: std::net::IpAddr = addr
                .rsplit_once(':')
                .map(|(host, _)| host.parse().expect("host válido"))
                .expect("host:puerto");
            assert!(
                ip.is_loopback(),
                "{addr} debe escuchar solo en loopback (una sola máquina)"
            );
        }
        assert!(!cfg.enable_sync, "mDNS desactivado por defecto");
        assert!(cfg.vault_root.starts_with(dirs_home().join(".boveda")));
        assert!(cfg.data_dir.starts_with(dirs_home().join(".boveda")));
    }

    #[test]
    fn second_writer_is_rejected_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(temp_config(dir.path())).unwrap();
        // el servicio no debe arrancar en modo consulta silencioso
        // (`Vault` no implementa Debug a propósito: nunca debe volcar el
        // estado de la bóveda en un log)
        let err = match Vault::open(temp_config(dir.path())) {
            Ok(_) => panic!("un segundo escritor no debe ser aceptado"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("escritura"),
            "error inesperado: {err}"
        );
        drop(v);
        assert!(Vault::open(temp_config(dir.path())).is_ok());
    }

    #[test]
    fn vault_open_creates_structure_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut v = Vault::open(temp_config(dir.path())).unwrap();
            assert!(v.config.vault_root.join(".staging").exists());
            assert!(v.config.data_dir.join("db/vault.db.enc").exists());
            // keyfile 0600 en unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(v.config.data_dir.join("vault.key"))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            v.init_pin("123456").unwrap();
        }
        // reabrir con el MISMO keyfile conserva los datos (PIN)
        let v2 = Vault::open(temp_config(dir.path())).unwrap();
        assert!(v2.admin.lock().unwrap().db().admin_pin_hash().is_some());
    }

    #[test]
    fn full_flow_upload_then_admit() {
        // flujo completo del lado bóveda: ingest (lo que hace el callback del
        // servidor sync) + admisión por el servicio de administración.
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::open(temp_config(dir.path())).unwrap();

        let content = b"Tesis de prueba para el flujo completo del daemon";
        let hp = vault_crypto::HashPair::from_bytes(content);
        let staging = dir.path().join("vault/.staging");
        std::fs::create_dir_all(&staging).unwrap();
        let incoming = staging.join("tmp-1234.incoming");
        std::fs::write(&incoming, content).unwrap();

        let envelope = serde_json::json!({
            "header": {
                "device_id": "AND_TEST_1",
                "timestamp_utc": "2026-09-23T19:13:47Z",
                "protocol_version": "1.0"
            },
            "payload": {
                "file_name": "Tesis_Ingenieria_2026_Nicolas.pdf",
                "file_category": "Tesis",
                "file_size_bytes": content.len(),
                "sha256": hp.sha256,
                "department": "Coordinación de Ingeniería",
                "author": "Yoangel De Dios Nícolas Gómez Gómez",
                "title": "Tesis de Ingeniería",
                "academic_year": 2026
            }
        });
        let ack =
            ingest_to_staging(&v.admin, "AND_TEST_1", &envelope.to_string(), &incoming).unwrap();
        let ack: serde_json::Value = serde_json::from_str(&ack).unwrap();
        assert_eq!(ack["status"], "pending_admission");
        assert!(!incoming.exists(), "renombrado a staging definitivo");

        // admitir desde el servicio compartido
        let submission_id = ack["submission_id"].as_str().unwrap().to_string();
        let (vault_ack, rel_path) = {
            let mut svc = v.admin.lock().unwrap();
            let vault_ack = svc.admit(&submission_id, "tester").unwrap();
            assert_eq!(vault_ack.status, vault_core::SealStatus::Sealed);
            let sub = svc
                .db()
                .find_by_sha256(&hp.sha256)
                .expect("documento registrado")
                .clone();
            (vault_ack, sub.rel_path.clone())
        };
        let layout = VaultLayout::new(dir.path().join("vault"));
        assert!(layout.abs_path(&rel_path).exists());
        assert!(vault_ack.vault_id.is_some());
        // auditoría encadenada e íntegra
        assert!(v.admin.lock().unwrap().db().verify_audit_chain().is_ok());
    }

    /// E2E DE MÁQUINA ÚNICA: el mismo computador es bóveda (servidor) y
    /// dispositivo (cliente). Arranca el servidor mTLS real, empareja con
    /// código de un solo uso, sube un archivo, lo admite desde el panel y
    /// verifica el sellado físico + auditoría.
    #[test]
    fn single_machine_e2e_server_pair_upload_admit() {
        use vault_client::{pair as client_pair, upload_file, PairedDevice};

        let dir = tempfile::tempdir().unwrap();
        let cfg = temp_config(dir.path());
        let mut vault = Vault::open(cfg).unwrap();
        vault.init_pin("123456").unwrap();

        // 1) Arrancar el servidor de sincronización de verdad (tokio actual).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (sync_addr, _mdns) = rt.block_on(async {
            let (guard, addr) = vault.start_sync().await.unwrap();
            (addr, guard)
        });

        // 2) Generar código de emparejamiento (como el botón del panel).
        let code = vault.admin.lock().unwrap().new_pairing_code().unwrap();

        // 3) La MISMA máquina se empareja como dispositivo.
        let ca_pem = vault_crypto::pem_encode_cert(
            &vault_crypto::Identity::load(&dir.path().join("data/pki"), "ca")
                .unwrap()
                .cert_der,
        );
        let device: PairedDevice =
            client_pair(sync_addr, &ca_pem, &code, "AND_LOCAL").expect("pair");
        assert_eq!(device.device_id, "AND_LOCAL");
        assert!(device.cert_pem.contains("CERTIFICATE"));

        // el emparejamiento quedó persistido en la BD (sobrevive reinicios)
        assert!(vault
            .admin
            .lock()
            .unwrap()
            .db()
            .device_by_fingerprint(&device.fingerprint)
            .is_some());

        // 4) Subir un documento real con el cliente mTLS.
        let doc_dir = tempfile::tempdir().unwrap();
        let doc_path = doc_dir.path().join("Tesis_Ingenieria_2026_Nicolas.pdf");
        let doc_content = b"Contenido completo de la tesis - E2E una sola maquina";
        std::fs::write(&doc_path, doc_content).unwrap();
        let ack =
            upload_file(sync_addr, &device, &ca_pem, &doc_path, Some("Tesis")).expect("upload");
        assert_eq!(ack["status"], "pending_admission");
        let submission_id = ack["submission_id"].as_str().unwrap().to_string();

        // 5) El administrador admite desde el panel → sellado físico.
        let (ack_seal, rel_path, vault_id) = {
            let mut svc = vault.admin.lock().unwrap();
            let ack = svc.admit(&submission_id, "panel").unwrap();
            assert_eq!(ack.status, vault_core::SealStatus::Sealed);
            let doc = svc
                .db()
                .find_by_sha256(&vault_crypto::HashPair::from_bytes(doc_content).sha256)
                .expect("doc")
                .clone();
            (ack, doc.rel_path.clone(), doc.vault_id.clone())
        };
        assert!(ack_seal.vault_id.is_some());
        let sealed = VaultLayout::new(dir.path().join("vault")).abs_path(&rel_path);
        assert!(sealed.exists(), "documento sellado en disco");

        // 6) Barrido de integridad: todo OK y cadena de auditoría íntegra.
        let report = vault.sweep_now().unwrap();
        assert_eq!(report.tampered, 0);
        assert_eq!(report.missing, 0);
        assert!(report.ok >= 1);
        assert!(vault
            .admin
            .lock()
            .unwrap()
            .db()
            .verify_audit_chain()
            .is_ok());
        assert!(!vault_id.is_empty());
    }

    #[test]
    fn ingest_rejects_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // una única apertura: la BD solo admite un escritor a la vez
        let v = Vault::open(temp_config(dir.path())).unwrap();
        let staging = dir.path().join("vault/.staging");
        std::fs::create_dir_all(&staging).unwrap();
        let incoming = staging.join("fake.incoming");
        std::fs::write(&incoming, b"contenido real").unwrap();
        let envelope = serde_json::json!({
            "header": { "device_id": "d", "timestamp_utc": "t", "protocol_version": "1.0" },
            "payload": {
                "file_name": "x.pdf", "file_category": "Tesis",
                "file_size_bytes": 3, "sha256": format!("{:0>64}", "ab")
            }
        });
        let err = ingest_to_staging(&v.admin, "d", &envelope.to_string(), &incoming).unwrap_err();
        assert!(err.contains("hash"), "error: {err}");
        assert!(!incoming.exists(), "archivo rechazado eliminado");
    }
}
