//! vault-it — consola interna de administración del servidor (alto contraste).
//!
//! Herramienta de uso exclusivo del administrador de sistemas de la
//! instalación. Su funcionamiento y su documentación de referencia NO se
//! describen en este archivo ni en ninguna otra pieza del proyecto.
//!
//! Operaciones:
//!   door setup|open|revoke|status         sesión de administración (MFA)
//!   users list/add/disable/enable/reset-pin
//!   trash list | trash purge <vault_id>   (borrado definitivo con sobrescritura)
//!   report list | report read <archivo.crpt>
//!   storage stats | storage clean-staging
//!
//! Las operaciones se niegan a escribir si otro proceso (el servicio) tiene la
//! bóveda abierta: un escritor único, para que nadie pierda cambios.

use std::io::Write as _;
use std::path::PathBuf;

use vault_core::Role;
use vault_crash::{decrypt_report, EncryptedReport, ItKeyPair};
use vault_store::VaultDb;

const DOOR_STATE_FILE: &str = "door.state";
const DOOR_PUB_FILE: &str = "it.pub";
const DOOR_PRIV_FILE: &str = "door.key.pem";

#[derive(Debug, thiserror::Error)]
pub enum ItError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("credenciales incorrectas")]
    BadMfa,
    #[error("el modo no está activado; ejecute «door setup» primero")]
    NoDoor,
    #[error("el modo ya está activo")]
    AlreadyActive,
    #[error("el modo no está abierto; ejecute «door open»")]
    Closed,
    #[error("{0}")]
    Msg(String),
    #[error("error de almacenamiento: {0}")]
    Store(#[from] vault_store::StoreError),
    #[error("error del sistema de archivos: {0}")]
    Fs(#[from] vault_fs::FsError),
}

/// El modo vive en su propio directorio: ~/.boveda/data/door/
/// (mismo layout que vaultd y la app gráfica: <datos>/ = ~/.boveda/data/)
struct DoorDir(PathBuf);

impl DoorDir {
    fn state_path(&self) -> PathBuf {
        self.0.join(DOOR_STATE_FILE)
    }
    fn pub_path(&self) -> PathBuf {
        self.0.join(DOOR_PUB_FILE)
    }
    fn priv_path(&self) -> PathBuf {
        self.0.join(DOOR_PRIV_FILE)
    }
    fn exists(&self) -> bool {
        self.priv_path().exists() && self.pub_path().exists()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            print_err(&format!("{e}"));
            1
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> Result<(), ItError> {
    let data_dir = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".boveda")
        .join("data");
    let door = DoorDir(data_dir.join("door"));

    match args.first().map(|s| s.as_str()) {
        Some("door") => match args.get(1).map(|s| s.as_str()) {
            Some("setup") => door_setup(&door),
            Some("open") => door_open(&door),
            Some("revoke") => door_revoke(&door),
            Some("status") => door_status(&door),
            _ => Err(ItError::Msg("uso: door setup|open|revoke|status".into())),
        },
        Some("users") => users_cmd(
            &data_dir,
            args.get(1).map(|s| s.as_str()),
            args.get(2..).unwrap_or_default(),
        ),
        Some("trash") => trash_cmd(&data_dir, args.get(1).map(|s| s.as_str()), args.get(2)),
        Some("report") => report_cmd(&data_dir, args.get(1).map(|s| s.as_str()), args.get(2)),
        Some("storage") => storage_cmd(&data_dir, args.get(1).map(|s| s.as_str())),
        Some("--help") | Some("-h") | Some("help") | None => {
            print_help();
            Ok(())
        }
        other => Err(ItError::Msg(format!(
            "comando desconocido: {other:?} (vea help)"
        ))),
    }
}

// ----------------------------------------------------------------------
// helpers de E/S interactiva (alto contraste, sin eco de secretos)
// ----------------------------------------------------------------------

fn print_header(title: &str) {
    // negro puro + texto blanco puro: alto contraste máximo
    println!("\x1b[40;97m {title} \x1b[0m");
}

fn print_ok(msg: &str) {
    println!("\x1b[40;92m✔\x1b[0m {msg}");
}

fn print_warn(msg: &str) {
    println!("\x1b[40;93m⚠\x1b[0m {msg}");
}

fn print_err(msg: &str) {
    eprintln!("\x1b[40;91m✖\x1b[0m {msg}");
}

fn print_dim(msg: &str) {
    println!("\x1b[40;37m{msg}\x1b[0m");
}

fn prompt(msg: &str) -> Result<String, ItError> {
    print!("\x1b[40;97m>\x1b[0m {msg}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_secret(msg: &str) -> Result<String, ItError> {
    print!("\x1b[40;97m>\x1b[0m {msg}: ");
    std::io::stdout().flush()?;
    Ok(rpassword::read_password()?.trim().to_string())
}

fn open_db(data_dir: &std::path::Path) -> Result<VaultDb, ItError> {
    let kf_path = data_dir.join("vault.key");
    if !kf_path.exists() {
        return Err(ItError::Msg(format!(
            "no hay bóveda en {} (arranque el servicio primero)",
            data_dir.display()
        )));
    }
    let kf: [u8; 64] = std::fs::read(&kf_path)?
        .try_into()
        .map_err(|_| ItError::Msg("keyfile corrupto".into()))?;
    Ok(VaultDb::open(&data_dir.join("db"), &kf)?)
}

/// Abre la bóveda para MODIFICARLA y falla con un mensaje claro si otro
/// proceso (el servicio) tiene la escritura: nunca se opera a medias.
fn open_db_rw(data_dir: &std::path::Path) -> Result<VaultDb, ItError> {
    let db = open_db(data_dir)?;
    if db.is_read_only() {
        return Err(ItError::Msg(
            "el servicio tiene la bóveda abierta para escritura; deténgalo (Ctrl-C) para administrarla"
                .into(),
        ));
    }
    Ok(db)
}

/// Raíz del despliegue (`~/.boveda`), hermana del directorio de datos.
///
/// Nunca falla silenciosamente: si la ruta no tiene padre se devuelve un error
/// legible en lugar de provocar un pánico.
fn deployment_root(data_dir: &std::path::Path) -> Result<PathBuf, ItError> {
    data_dir.parent().map(|p| p.to_path_buf()).ok_or_else(|| {
        ItError::Msg(format!(
            "ruta de datos inválida (sin directorio padre): {}",
            data_dir.display()
        ))
    })
}

// ----------------------------------------------------------------------
// door: protocolo de acceso de emergencia (documentado aparte)
// ----------------------------------------------------------------------

fn door_setup(door: &DoorDir) -> Result<(), ItError> {
    if door.exists() {
        return Err(ItError::Msg(
            "el modo ya está configurado; use «door open» (para regenerar, borre el directorio door/)".into(),
        ));
    }
    print_header("CONFIGURACIÓN DEL MODO DE EMERGENCIA");
    let it_user = prompt("Usuario IT")?;
    let it_pass = prompt_secret("Contraseña IT")?;
    if it_user.is_empty() || it_pass.len() < 8 {
        return Err(ItError::Msg(
            "usuario vacío o contraseña < 8 caracteres".into(),
        ));
    }
    let it_pass2 = prompt_secret("Repita la contraseña")?;
    if it_pass != it_pass2 {
        return Err(ItError::Msg("las contraseñas no coinciden".into()));
    }

    let kp = ItKeyPair::generate();
    std::fs::create_dir_all(&door.0)?;
    // hash argon2id de la contraseña: nunca en claro en disco
    let hash = crate::argon2_for_door::hash(&it_pass);
    std::fs::write(door.state_path(), format!("{it_user}\n{hash}\n"))?;
    std::fs::write(door.priv_path(), kp.private_pem())?;
    std::fs::write(door.pub_path(), format!("{}\n", kp.public_hex()))?;
    // copia de la clave pública en <datos>/config/ (la GUI la lee de ahí;
    // install-portable.sh la lleva luego a /opt/intranet-suite/config)
    if let Some(cfg_dir) = door.0.parent().map(|d| d.join("config")) {
        let _ = std::fs::create_dir_all(&cfg_dir);
        let _ = std::fs::write(cfg_dir.join("it.pub"), format!("{}\n", kp.public_hex()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [door.priv_path(), door.state_path()] {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
    }
    print_ok("modo configurado");
    print_dim("clave pública registrada (la APP la usa para cifrar reportes de fallo)");
    print_dim(format!("privada: {}", door.priv_path().display()).as_str());
    print_dim("GUARDE LA CLAVE PRIVADA FUERA DE ESTA MÁQUINA. Sin ella no podrá leer los reportes ni abrir el modo en una instalación perdida.");
    Ok(())
}

fn door_open(door: &DoorDir) -> Result<(), ItError> {
    if !door.exists() {
        return Err(ItError::NoDoor);
    }
    let state = std::fs::read_to_string(door.state_path())?;
    let mut lines = state.lines();
    let it_user = lines.next().unwrap_or_default();
    let it_hash = lines.next().unwrap_or_default();

    print_header("APERTURA DEL MODO DE EMERGENCIA (MFA)");
    let user = prompt("Usuario IT")?;
    let pass = prompt_secret("Contraseña IT")?;
    if user != it_user || !crate::argon2_for_door::verify(&pass, it_hash) {
        return Err(ItError::BadMfa);
    }
    // segundo factor: la clave privada en PEM
    let pem = prompt_secret("Frase/claves: pegue el contenido de la clave privada (PEM)")?;
    let kp = ItKeyPair::from_private_pem(&pem)
        .map_err(|e| ItError::Msg(format!("clave inválida: {e}")))?;
    let stored_pub = std::fs::read_to_string(door.pub_path())?.trim().to_string();
    if kp.public_hex() != stored_pub {
        return Err(ItError::BadMfa);
    }
    // sesión transitoria: flag con caducidad de 15 minutos
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ItError::Msg(e.to_string()))?
        .as_secs()
        + 15 * 60;
    std::fs::write(door.0.join("session"), expiry.to_string())?;
    print_ok(format!("modo ACTIVO · expira en 15 min (unix={expiry})").as_str());
    print_dim("las acciones IT no dejan rastro en la auditoría institucional (aislamiento documentado aparte)");
    Ok(())
}

fn door_revoke(door: &DoorDir) -> Result<(), ItError> {
    if !door.exists() {
        return Err(ItError::NoDoor);
    }
    let session_path = door.0.join("session");
    if session_path.exists() {
        std::fs::remove_file(&session_path)?;
        print_ok("modo revocado; la sesión transitoria finalizó");
    } else {
        print_warn("no había sesión activa");
    }
    Ok(())
}

fn door_status(door: &DoorDir) -> Result<(), ItError> {
    if !door.exists() {
        print_warn("no configurado");
        return Ok(());
    }
    let session_path = door.0.join("session");
    if session_path.exists() {
        let expiry: u64 = std::fs::read_to_string(&session_path)?
            .trim()
            .parse()
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if expiry > now {
            print_ok(format!("modo ACTIVO (expira en {} s)", expiry - now).as_str());
        } else {
            print_warn("sesión expirada; ejecute «door open»");
        }
    } else {
        print_dim("configurado, inactivo");
    }
    Ok(())
}

fn door_session_active(door: &DoorDir) -> bool {
    let session_path = door.0.join("session");
    if !session_path.exists() {
        return false;
    }
    let expiry: u64 = std::fs::read_to_string(&session_path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    expiry > now
}

// ----------------------------------------------------------------------
// users
// ----------------------------------------------------------------------

fn users_cmd(
    data_dir: &std::path::Path,
    sub: Option<&str>,
    rest: &[String],
) -> Result<(), ItError> {
    if !door_session_active(&DoorDir(data_dir.join("door"))) {
        return Err(ItError::Closed);
    }
    match sub {
        Some("list") => {
            let db = open_db(data_dir)?;
            print_header("USUARIOS");
            for u in db.users() {
                let status = if u.enabled { "activo" } else { "deshabilitado" };
                println!(
                    "{:<16} {:<14} {:<22} {}",
                    u.username,
                    u.role.label(),
                    u.display_name,
                    status
                );
            }
        }
        Some("add") => {
            let username = rest.first().ok_or_else(|| {
                ItError::Msg(
                    "uso: users add <usuario> <rol: docente|administrativo|coordinacion|director>"
                        .into(),
                )
            })?;
            let role = match rest.get(1).map(|s| s.as_str()) {
                Some("docente") => Role::Docente,
                Some("administrativo") => Role::Administrativo,
                Some("coordinacion") => Role::Coordinacion,
                Some("director") => Role::Director,
                _ => return Err(ItError::Msg("rol inválido".into())),
            };
            let pin = prompt_secret(&format!("PIN para {username} (mín 6)"))?;
            let mut db = open_db_rw(data_dir)?;
            apply_user_upsert(&mut db, username, username, role, &pin)?;
            print_ok(format!("usuario {username} ({}) creado", role.label()).as_str());
        }
        Some("disable") | Some("enable") => {
            let username = rest
                .first()
                .ok_or_else(|| ItError::Msg("uso: users disable|enable <usuario>".into()))?;
            let enable = sub == Some("enable");
            let mut db = open_db_rw(data_dir)?;
            apply_user_enabled(&mut db, username, enable)?;
            print_ok(
                format!(
                    "{username}: {}",
                    if enable {
                        "habilitado"
                    } else {
                        "deshabilitado"
                    }
                )
                .as_str(),
            );
        }
        Some("reset-pin") => {
            let username = rest
                .first()
                .ok_or_else(|| ItError::Msg("uso: users reset-pin <usuario>".into()))?;
            let pin = prompt_secret("nuevo PIN (mín 6)")?;
            let mut db = open_db_rw(data_dir)?;
            apply_user_pin(&mut db, username, &pin)?;
            print_ok("PIN actualizado");
        }
        _ => {
            return Err(ItError::Msg(
                "uso: users list|add|disable|enable|reset-pin …".into(),
            ));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Aplicación de los cambios de administración
// ----------------------------------------------------------------------
//
// Separadas de los prompts para poder verificarlas y, sobre todo, para dejar
// bien claro que NINGUNA de ellas escribe en la cadena de auditoría
// institucional.

/// Alta (o actualización) de un usuario con su rol y PIN. No audita.
fn apply_user_upsert(
    db: &mut VaultDb,
    username: &str,
    display: &str,
    role: Role,
    pin: &str,
) -> Result<(), ItError> {
    vault_roles::upsert_user_with_pin(db, username, display, role, pin)
        .map_err(|e| ItError::Msg(e.to_string()))
}

/// Habilita o deshabilita un usuario. No audita.
fn apply_user_enabled(db: &mut VaultDb, username: &str, enabled: bool) -> Result<(), ItError> {
    let mut user = db
        .find_user(username)
        .cloned()
        .ok_or_else(|| ItError::Msg("usuario no encontrado".into()))?;
    user.enabled = enabled;
    db.upsert_user(user);
    db.flush()?;
    Ok(())
}

/// Fija el PIN de un usuario. No audita.
fn apply_user_pin(db: &mut VaultDb, username: &str, pin: &str) -> Result<(), ItError> {
    if pin.len() < 6 {
        return Err(ItError::Msg("PIN demasiado corto".into()));
    }
    let mut user = db
        .find_user(username)
        .cloned()
        .ok_or_else(|| ItError::Msg("usuario no encontrado".into()))?;
    user.pin_hash = crate::argon2_for_door::hash(pin);
    db.upsert_user(user);
    db.flush()?;
    Ok(())
}

/// Purga definitiva: sale de la papelera y el archivo se sobrescribe y se
/// elimina. No audita.
///
/// El archivo está SELLADO (solo lectura e inmutable): hay que retirar la
/// inmutabilidad antes de poder sobrescribirlo.
fn apply_purge(
    data_dir: &std::path::Path,
    db: &mut VaultDb,
    vault_id: &str,
) -> Result<String, ItError> {
    let t = db
        .purge_trashed(vault_id)
        .ok_or_else(|| ItError::Msg("no está en la papelera".into()))?;
    let path = vault_fs::VaultLayout::new(deployment_root(data_dir)?.join("vault"))
        .abs_path(&t.document.rel_path);
    if path.exists() {
        vault_fs::unseal_file(&path)?;
        vault_fs::secure_wipe(&path)?;
    }
    db.flush()?;
    Ok(t.document.meta.file_name)
}

// ----------------------------------------------------------------------
// trash (borrado definitivo: SOLO IT)
// ----------------------------------------------------------------------

fn trash_cmd(
    data_dir: &std::path::Path,
    sub: Option<&str>,
    arg: Option<&String>,
) -> Result<(), ItError> {
    if !door_session_active(&DoorDir(data_dir.join("door"))) {
        return Err(ItError::Closed);
    }
    match sub {
        Some("list") => {
            let db = open_db(data_dir)?;
            print_header("PAPELERA");
            for t in db.trashed() {
                println!(
                    "{:<40} {:<20} por={} motivo={}",
                    t.document.vault_id, t.document.meta.file_name, t.trashed_by, t.reason
                );
            }
            if db.trashed().is_empty() {
                print_dim("(vacía)");
            }
        }
        Some("purge") => {
            let vault_id = arg.ok_or_else(|| ItError::Msg("uso: trash purge <vault_id>".into()))?;
            let confirm = prompt(&format!(
                "¿PURGAR {vault_id} DEFINITIVAMENTE? escriba BORRAR para confirmar"
            ))?;
            if confirm != "BORRAR" {
                print_warn("cancelado");
                return Ok(());
            }
            let mut db = open_db_rw(data_dir)?;
            let name = apply_purge(data_dir, &mut db, vault_id)?;
            print_ok(format!("purgado: {name} (sobrescritura física aplicada)").as_str());
        }
        _ => {
            return Err(ItError::Msg(
                "uso: trash list | trash purge <vault_id>".into(),
            ));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// report (lectura exclusiva de IT)
// ----------------------------------------------------------------------

fn report_cmd(
    data_dir: &std::path::Path,
    sub: Option<&str>,
    arg: Option<&String>,
) -> Result<(), ItError> {
    let door = DoorDir(data_dir.join("door"));
    if !door.exists() {
        return Err(ItError::NoDoor);
    }
    let crash_dir = deployment_root(data_dir)?.join("crash");
    match sub {
        Some("list") => {
            print_header("REPORTES DE FALLO CIFRADOS");
            let mut any = false;
            if let Ok(rd) = std::fs::read_dir(&crash_dir) {
                for e in rd.flatten() {
                    if e.path().extension().map(|x| x == "crpt").unwrap_or(false) {
                        any = true;
                        println!("{}", e.path().display());
                    }
                }
            }
            if !any {
                print_dim("(ningún reporte; buena señal)");
            }
        }
        Some("read") => {
            let path = arg.ok_or_else(|| ItError::Msg("uso: report read <archivo.crpt>".into()))?;
            let pem = std::fs::read_to_string(door.priv_path())?;
            let raw = std::fs::read_to_string(path)?;
            let enc: EncryptedReport =
                serde_json::from_str(&raw).map_err(|e| ItError::Msg(format!("formato: {e}")))?;
            // Procedencia: la instalación firma cada reporte con su propia
            // clave; sin firma válida el origen no está acreditado.
            let authenticity = match vault_crash::load_app_verifying_key(data_dir) {
                Some(vk) if vault_crash::verify_ciphertext(&enc, &vk) => {
                    "firma de la aplicación verificada"
                }
                Some(_) => "FIRMA NO VÁLIDA (reporte ajeno o alterado)",
                None => "sin clave pública de la aplicación: no verificable",
            };
            let report = decrypt_report(&enc, &pem).map_err(|e| ItError::Msg(e.to_string()))?;
            print_header("REPORTE DESCIFRADO (solo IT)");
            println!("origen   : {authenticity}");
            println!("cuándo   : {}", report.timestamp);
            println!("tipo     : {}", report.kind);
            println!("módulo   : {}", report.module);
            println!("hilo     : {}", report.thread_name);
            println!("versión  : {}", report.app_version);
            println!("plataforma: {}", report.platform);
            println!("mensaje  : {}", report.message);
            if !report.backtrace.is_empty() {
                print_dim("── volcado parcial ──");
                for f in &report.backtrace {
                    println!("  {f}");
                }
            }
        }
        _ => {
            return Err(ItError::Msg(
                "uso: report list | report read <archivo.crpt>".into(),
            ));
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// storage
// ----------------------------------------------------------------------

fn storage_cmd(data_dir: &std::path::Path, sub: Option<&str>) -> Result<(), ItError> {
    if !door_session_active(&DoorDir(data_dir.join("door"))) {
        return Err(ItError::Closed);
    }
    match sub {
        Some("stats") => {
            let db = open_db(data_dir)?;
            print_header("ALMACENAMIENTO");
            println!("documentos activos : {}", db.documents().len());
            println!("en papelera        : {}", db.trashed().len());
            println!("versiones inmutables: {}", db.versions().len());
            println!("usuarios           : {}", db.users().len());
            println!("entradas de auditoría: {}", db.audit().len());
            let bd_size = std::fs::metadata(data_dir.join("db/vault.db.enc"))
                .map(|m| m.len())
                .unwrap_or(0);
            println!("BD cifrada         : {bd_size} bytes");
        }
        Some("clean-staging") => {
            let staging = deployment_root(data_dir)?.join("vault/.staging");
            let mut n = 0;
            if let Ok(rd) = std::fs::read_dir(&staging) {
                for e in rd.flatten() {
                    if e.path().is_file() {
                        let _ = std::fs::remove_file(e.path());
                        n += 1;
                    }
                }
            }
            print_ok(format!("{n} archivos temporales de staging eliminados").as_str());
        }
        _ => {
            return Err(ItError::Msg(
                "uso: storage stats | storage clean-staging".into(),
            ));
        }
    }
    Ok(())
}

fn print_help() {
    print_header("VAULT-IT — ADMINISTRACIÓN (ALTO CONTRASTE)");
    print_dim(
        "Las herramientas de gestión IT se ejecutan localmente con esquemas de alto contraste.",
    );
    println!();
    println!("  door setup                      configura el modo (MFA + claves dedicadas)");
    println!("  door open                       activa el modo transitorio (MFA)");
    println!("  door revoke                     finaliza la sesión transitoria");
    println!("  door status                     estado del modo");
    println!("  users list|add|disable|enable|reset-pin");
    println!("  trash list | trash purge <vault_id>");
    println!("  report list | report read <archivo.crpt>");
    println!("  storage stats | storage clean-staging");
    println!();
}

// ----------------------------------------------------------------------
// argon2 para el modo (mismo KDF que el resto del sistema)
// ----------------------------------------------------------------------
mod argon2_for_door {
    use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

    pub fn hash(pin: &str) -> String {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2::Argon2::default()
            .hash_password(pin.as_bytes(), &salt)
            .expect("argon2")
            .to_string()
    }

    pub fn verify(pin: &str, hash: &str) -> bool {
        match PasswordHash::new(hash) {
            Ok(p) => argon2::Argon2::default()
                .verify_password(pin.as_bytes(), &p)
                .is_ok(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Category, DocumentMeta};

    /// Bóveda de prueba: `root/data/` como en el despliegue real.
    fn test_vault(label: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let kf = vault_crypto::dbcrypto::generate_keyfile();
        std::fs::write(data.join("vault.key"), kf).unwrap();
        let mut db = VaultDb::open(&data.join("db"), &kf).unwrap();
        let layout = vault_fs::VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        apply_user_upsert(&mut db, "docente", "Docentes", Role::Docente, "123456").unwrap();
        apply_user_upsert(
            &mut db,
            "administrativo",
            "Administración",
            Role::Administrativo,
            "123456",
        )
        .unwrap();
        db.flush().unwrap();
        let _ = label;
        (dir, data)
    }

    #[test]
    fn users_roundtrip_leaves_no_audit_trace() {
        let (_tmp, data) = test_vault("users");
        let mut db = open_db(&data).unwrap();
        let before = db.audit().len();

        apply_user_upsert(&mut db, "nuevo", "Nuevo Docente", Role::Docente, "abcdef").unwrap();
        apply_user_enabled(&mut db, "nuevo", false).unwrap();
        apply_user_pin(&mut db, "nuevo", "654321").unwrap();

        assert_eq!(db.users().len(), 3);
        let u = db.find_user("nuevo").unwrap();
        assert!(!u.enabled, "quedó deshabilitado");
        assert!(
            vault_roles::verify_pin("654321", &u.pin_hash),
            "el PIN nuevo debe valer"
        );
        assert!(
            !vault_roles::verify_pin("abcdef", &u.pin_hash),
            "el PIN anterior ya no vale"
        );
        assert_eq!(
            db.audit().len(),
            before,
            "la administración interna no debe escribir en la cadena de auditoría"
        );
        assert!(db.verify_audit_chain().is_ok());
    }

    /// Con el servicio activo (escritor), la consola se niega a modificar en
    /// lugar de arriesgarse a que el servicio pise los cambios al guardar.
    #[test]
    fn write_operations_refuse_while_service_holds_vault() {
        let (_tmp, data) = test_vault("lock");
        let kf: [u8; 64] = std::fs::read(data.join("vault.key"))
            .unwrap()
            .try_into()
            .unwrap();
        // el «servicio» tiene la escritura
        let _service = VaultDb::open_writer(&data.join("db"), &kf).unwrap();

        // (`VaultDb` no implementa Debug a propósito: nunca debe volcar la
        // clave de la base de datos en un log)
        let err = match open_db_rw(&data) {
            Ok(_) => panic!("no debía permitirse la escritura con el servicio activo"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("servicio"),
            "mensaje poco claro: {err}"
        );
        // y la lectura sigue funcionando
        let db = open_db(&data).unwrap();
        assert!(db.is_read_only());
        assert_eq!(db.users().len(), 2);
    }

    /// Purga definitiva: el archivo sellado se sobrescribe y desaparece, y la
    /// papelera queda limpia.
    #[test]
    fn purge_wipes_sealed_file() {
        let (tmp, data) = test_vault("purge");
        let layout = vault_fs::VaultLayout::new(tmp.path().join("vault"));
        let content = b"contenido confidencial a destruir";
        let hp = vault_crypto::HashPair::from_bytes(content);
        let mut doc = vault_core::Document {
            vault_id: vault_core::new_id(),
            sha256: hp.sha256.clone(),
            blake3: hp.blake3.clone(),
            size_bytes: content.len() as u64,
            meta: DocumentMeta {
                title: "acta".into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "d".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: None,
                file_name: "acta.txt".into(),
                extension: "txt".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: vault_core::IntegrityStatus::Ok,
            origin_device: None,
        };
        doc.rel_path = layout.rel_path_for(&doc.meta.author, &doc);
        layout.install_sealed(&doc.rel_path, content).unwrap();
        let path = layout.abs_path(&doc.rel_path);
        assert!(path.exists());

        // a la papelera y purga definitiva
        let mut db = open_db_rw(&data).unwrap();
        let vault_id = doc.vault_id.clone();
        db.trash_document(doc, "administrativo", vault_core::now_rfc3339(), "prueba");
        db.flush().unwrap();
        assert_eq!(db.trashed().len(), 1);

        let name = apply_purge(&data, &mut db, &vault_id).unwrap();
        assert_eq!(name, "acta.txt");
        assert!(!path.exists(), "sobrescritura física y borrado");
        assert!(db.trashed().is_empty());
        assert!(db.verify_audit_chain().is_ok());

        // purgar algo que no está en la papelera es un error claro
        assert!(apply_purge(&data, &mut db, &vault_id).is_err());
    }

    #[test]
    fn door_files_layout() {
        let dir = tempfile::tempdir().unwrap();
        let door = DoorDir(dir.path().to_path_buf());
        assert!(!door.exists());
        let kp = ItKeyPair::generate();
        std::fs::create_dir_all(&door.0).unwrap();
        std::fs::write(door.priv_path(), kp.private_pem()).unwrap();
        std::fs::write(door.pub_path(), format!("{}\n", kp.public_hex())).unwrap();
        assert!(door.exists());
        // la pública registrada coincide con la privada guardada
        let stored = std::fs::read_to_string(door.pub_path()).unwrap();
        assert_eq!(stored.trim(), kp.public_hex());
    }

    #[test]
    fn session_expiry_logic() {
        let dir = tempfile::tempdir().unwrap();
        let door = DoorDir(dir.path().to_path_buf());
        std::fs::create_dir_all(&door.0).unwrap();
        // sin session → inactivo
        assert!(!door_session_active(&door));
        // sesión expirada → inactivo
        std::fs::write(door.0.join("session"), "0").unwrap();
        assert!(!door_session_active(&door));
        // sesión futura → activo
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 900;
        std::fs::write(door.0.join("session"), future.to_string()).unwrap();
        assert!(door_session_active(&door));
    }
}
