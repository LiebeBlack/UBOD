//! vault-fs: sellado físico de documentos — la capa de inmutabilidad del SO.
//!
//! Linux (primario): chmod 0440/0550 + chattr +i (bit inmutable) + preparado
//! para fs-verity. El daemon aplica Landlock para restringir su propio acceso.
//! Windows: atributo FILE_ATTRIBUTE_READONLY + hook para ACLs deny
//! (WRITE/APPEND/DELETE) sobre la bóveda; el wipe usa sobrescritura múltiple.

use std::path::{Path, PathBuf};
use vault_core::{Category, Document};

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("mecanismo de inmutabilidad no disponible: {0}")]
    Immutable(String),
}

/// Layout de la bóveda: raíz + carpetas por usuario y categoría.
pub struct VaultLayout {
    pub root: PathBuf,
}

impl VaultLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        VaultLayout { root: root.into() }
    }

    /// Ruta relativa de un documento dentro de la bóveda.
    pub fn rel_path_for(&self, user: &str, doc: &Document) -> String {
        let safe_user = sanitize_component(user);
        let safe_name = sanitize_component(&doc.meta.file_name);
        format!(
            "{safe_user}/{cat}/{safe_name}",
            cat = doc.meta.category.dir_name()
        )
    }

    /// Ruta absoluta para una ruta relativa.
    pub fn abs_path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Directorio de staging (única zona escribible).
    pub fn staging(&self) -> PathBuf {
        self.root.join(".staging")
    }

    /// Directorio de tombstones (registros de destrucción supervisada).
    pub fn tombstones(&self) -> PathBuf {
        self.root.join(".tombstones")
    }

    /// Instala un documento nuevo a partir de su contenido: crea las carpetas
    /// necesarias y lo sella (inmutable).
    ///
    /// Es una de las dos entradas físicas a la bóveda —la otra es
    /// [`VaultLayout::install_staged`]— para que un documento importado desde
    /// la aplicación y uno recibido del móvil acaben idénticos en disco.
    pub fn install_sealed(&self, rel: &str, content: &[u8]) -> Result<PathBuf, FsError> {
        let dest = self.prepare_parent(rel)?;
        if dest.exists() {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("ya existe un documento en {rel}"),
            )));
        }
        std::fs::write(&dest, content)?;
        set_owner_only(&dest)?;
        seal_file(&dest)?;
        Ok(dest)
    }

    /// Instala un documento moviendo el fichero ya recibido en staging a su
    /// ubicación definitiva, sellándolo después.
    pub fn install_staged(&self, rel: &str, staged: &Path) -> Result<PathBuf, FsError> {
        let dest = self.prepare_parent(rel)?;
        if dest.exists() {
            return Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("ya existe un documento en {rel}"),
            )));
        }
        match std::fs::rename(staged, &dest) {
            Ok(()) => {}
            // Otro sistema de archivos (staging fuera del árbol): copia + borrado.
            // 18 = EXDEV (Unix), 17 = ERROR_NOT_SAME_DEVICE (Windows).
            Err(e) if matches!(e.raw_os_error(), Some(18) | Some(17)) => {
                std::fs::copy(staged, &dest)?;
                let _ = std::fs::remove_file(staged);
            }
            Err(e) => return Err(FsError::Io(e)),
        }
        set_owner_only(&dest)?;
        seal_file(&dest)?;
        Ok(dest)
    }

    /// Prepara el directorio destino y devuelve la ruta absoluta.
    fn prepare_parent(&self, rel: &str) -> Result<PathBuf, FsError> {
        let dest = self.abs_path(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
            ensure_dir_writable(parent)?;
        }
        Ok(dest)
    }

    /// Crea la estructura inicial de la bóveda.
    pub fn init(&self, users: &[String]) -> Result<(), FsError> {
        std::fs::create_dir_all(self.staging())?;
        std::fs::create_dir_all(self.tombstones())?;
        for u in users {
            for cat in Category::ALL {
                let dir = self.root.join(sanitize_component(u)).join(cat.dir_name());
                std::fs::create_dir_all(&dir)?;
                protect_directory(&dir)?;
            }
        }
        Ok(())
    }
}

/// Sanitiza un componente de ruta: sin separadores, sin "..", imprimible.
pub fn sanitize_component(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '(' | ')') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim().replace(' ', "_");
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "_".to_string()
    } else {
        cleaned
    }
}

/// Sellado: permisos de solo lectura + bit inmutable (Linux) o readonly (Windows).
pub fn seal_file(path: &Path) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o440);
        std::fs::set_permissions(path, perms)?;
        // chattr +i: bit inmutable (ni root escribe/borra sin quitarlo)
        chattr_immutable(path, true)?;
    }
    #[cfg(windows)]
    {
        set_readonly_attr(path, true)?;
        apply_deny_acl(path)?;
    }
    Ok(())
}

/// Retira la inmutabilidad (solo para destrucción supervisada).
pub fn unseal_file(path: &Path) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        chattr_immutable(path, false)?;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        remove_deny_acl(path)?;
        set_readonly_attr(path, false)?;
    }
    Ok(())
}

/// Protección de directorio de la bóveda.
///
/// El dueño (el propio servicio/usuario de la bóveda) conserva escritura
/// porque tiene que instalar documentos sellados dentro; el grupo y el resto
/// del sistema NO pueden escribir ni listar. Un `0o550` bloquearía al propio
/// dueño y haría imposible custodiar nada.
pub fn protect_directory(dir: &Path) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
    }
    #[cfg(windows)]
    {
        let _ = dir;
    }
    Ok(())
}

/// Garantiza que el dueño pueda escribir en `dir`.
///
/// Cura instalaciones creadas por versiones anteriores (carpetas en `0o550`),
/// sin abrir el acceso al grupo ni al resto del sistema.
#[cfg(unix)]
pub fn ensure_dir_writable(dir: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    if mode & 0o700 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o700))?;
    }
    Ok(())
}

#[cfg(windows)]
pub fn ensure_dir_writable(_dir: &Path) -> Result<(), FsError> {
    Ok(())
}

/// Permisos de propietario para un documento recién instalado (antes de sellar).
#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), FsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn set_owner_only(_path: &Path) -> Result<(), FsError> {
    Ok(())
}

#[cfg(unix)]
fn chattr_immutable(path: &Path, on: bool) -> Result<(), FsError> {
    use std::os::unix::io::AsRawFd;
    const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;
    // FS_IOC_SETFLAGS = _IOW('f', 2, long)
    const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
    let f = std::fs::OpenOptions::new().read(true).open(path)?;
    let flags: libc::c_long = if on { FS_IMMUTABLE_FL } else { 0 };
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_SETFLAGS, &flags) };
    if rc != 0 && on {
        tracing::warn!(path = %path.display(), "chattr +i no soportado aquí; protección parcial");
    }
    Ok(())
}

#[cfg(windows)]
fn set_readonly_attr(path: &Path, on: bool) -> Result<(), FsError> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let attrs = GetFileAttributesW(wide.as_ptr());
        if attrs == u32::MAX {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }
        let new_attrs = if on {
            attrs | FILE_ATTRIBUTE_READONLY
        } else {
            attrs & !FILE_ATTRIBUTE_READONLY
        };
        if SetFileAttributesW(wide.as_ptr(), new_attrs) == 0 {
            return Err(FsError::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn apply_deny_acl(_path: &Path) -> Result<(), FsError> {
    // El servicio corre como única cuenta con acceso de escritura; las ACLs
    // deny explícitas (FILE_WRITE_DATA/FILE_APPEND_DATA/DELETE) se aplican en
    // el instalador y desde el módulo de servicio.
    Ok(())
}

#[cfg(windows)]
fn remove_deny_acl(_path: &Path) -> Result<(), FsError> {
    Ok(())
}

/// Wipe seguro: 3 pasadas (0x00, 0xFF, aleatorio) y eliminación.
pub fn secure_wipe(path: &Path) -> Result<(), FsError> {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    let size = f.metadata()?.len();
    for round in 0..3u8 {
        f.seek(SeekFrom::Start(0))?;
        let chunk = 64 * 1024;
        let mut buf = vec![0u8; chunk];
        match round % 3 {
            0 => buf.fill(0x00),
            1 => buf.fill(0xFF),
            _ => {
                getrandom::getrandom(&mut buf).map_err(|e| std::io::Error::other(e.to_string()))?;
            }
        }
        let mut left = size;
        while left > 0 {
            let n = buf.len().min(left as usize);
            f.write_all(&buf[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    drop(f);
    std::fs::remove_file(path)?;
    Ok(())
}

/// Traduce el estado de un ruleset ya aplicado a un resultado con traza.
///
/// Se avisa y se continúa si el kernel sólo aplica parte de la política: un
/// sandbox parcial sigue sumando defensa en profundidad. No aplicarlo en
/// absoluto sí es un error, y cada llamante decide cómo tratarlo.
#[cfg(unix)]
fn landlock_status(status: landlock::RestrictionStatus, what: &str) -> Result<(), String> {
    match status.ruleset {
        landlock::RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock ({what}): totalmente aplicado");
            Ok(())
        }
        landlock::RulesetStatus::PartiallyEnforced => {
            tracing::warn!("Landlock ({what}): parcialmente aplicado (kernel antiguo)");
            Ok(())
        }
        landlock::RulesetStatus::NotEnforced => Err(format!("landlock no pudo activarse ({what})")),
    }
}

/// Rutas del sistema que un proceso confinado necesita poder LEER para seguir
/// funcionando: bibliotecas, zona horaria, `/proc`, `/sys` y `/run`.
///
/// El HOME del usuario NO está aquí a propósito: es justo lo que el
/// confinamiento debe dejar fuera del alcance del proceso.
#[cfg(unix)]
const SYSTEM_READ_ROOTS: &[&str] = &[
    "/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/run",
];

/// Rutas del sistema con escritura incidental: `/dev/null` (salida
/// redireccionada) y los temporales del sistema (OCR, ficheros de trabajo).
#[cfg(unix)]
const SYSTEM_WRITE_ROOTS: &[&str] = &["/dev", "/tmp"];

/// Landlock (Linux): confina el SERVICIO a la bóveda y a su directorio de datos.
///
/// Fuera de esas dos rutas el proceso sólo puede leer los directorios de sistema
/// imprescindibles ([`SYSTEM_READ_ROOTS`]); en particular no alcanza el HOME del
/// usuario, así que una vulnerabilidad en el analizador de un PDF o de un DOCX
/// no llega al resto del sistema de archivos.
///
/// Requisitos y matices:
/// - Las rutas **deben existir** antes de llamar: Landlock no puede conceder
///   acceso a algo que todavía no está en el sistema de archivos.
/// - Se pide el ABI 4 (Linux 6.7) porque cubre los derechos que importan
///   (`Truncate`, `Refer`) sin arrastrar los más recientes, que forzarían un
///   sandbox parcial permanente en kernels actuales. Con `BestEffort` la crate
///   enmascara lo que el kernel en marcha no soporte y lo reporta como parcial.
/// - No es fatal: si el kernel no soporta Landlock devuelve `Err` y es el
///   llamante quien decide (el servicio avisa y continúa).
#[cfg(unix)]
pub fn apply_landlock(vault_root: &Path, data_dir: &Path) -> Result<(), String> {
    let writable: Vec<&Path> = SYSTEM_WRITE_ROOTS
        .iter()
        .map(Path::new)
        .chain([vault_root, data_dir])
        .collect();
    let read_only: Vec<&Path> = SYSTEM_READ_ROOTS.iter().map(Path::new).collect();
    tracing::info!(
        boveda = %vault_root.display(),
        datos = %data_dir.display(),
        "Landlock: el servicio sólo podrá escribir en la bóveda y en <datos>"
    );
    landlock_restrict(&read_only, &writable, false)
}

/// En sistemas sin Landlock no hay nada que confinar: el aislamiento físico de
/// la bóveda queda a cargo de los permisos y atributos de archivo.
#[cfg(not(unix))]
pub fn apply_landlock(_vault_root: &Path, _data_dir: &Path) -> Result<(), String> {
    Ok(())
}

/// Landlock (Linux) para procesos interactivos: confina **sólo la ESCRITURA** a
/// `roots` (más `/dev` y `/tmp`) y deja la lectura intacta.
///
/// Es la política adecuada para la aplicación gráfica y las consolas de
/// administración: importar un documento exige poder LEER de cualquier carpeta
/// del usuario (Escritorio, Descargas, una unidad externa), pero el proceso no
/// debe poder escribir nada fuera de las rutas indicadas. Los derechos de
/// lectura no se tramitan, así que quedan como estaban.
#[cfg(unix)]
pub fn apply_landlock_write_only(roots: &[&Path]) -> Result<(), String> {
    let writable: Vec<&Path> = SYSTEM_WRITE_ROOTS
        .iter()
        .map(Path::new)
        .chain(roots.iter().copied())
        .collect();
    landlock_restrict(&[], &writable, true)
}

#[cfg(not(unix))]
pub fn apply_landlock_write_only(_roots: &[&Path]) -> Result<(), String> {
    Ok(())
}

/// Aplica un ruleset de Landlock.
///
/// Con `write_only` en falso se tramitan los derechos completos de `read_only`
/// (sólo lectura) y de `writable` (lectura y escritura); con `write_only` en
/// verdadero se tramitan únicamente los derechos de escritura, de modo que la
/// lectura queda sin restringir.
#[cfg(unix)]
fn landlock_restrict(
    read_only: &[&Path],
    writable: &[&Path],
    write_only: bool,
) -> Result<(), String> {
    use landlock::{
        path_beneath_rules, Access, AccessFs, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
        ABI,
    };
    let abi = ABI::V4;
    // En modo escritura sólo se tramita (y se concede) `from_write`: añadir a la
    // regla un derecho no tramitado sería incoherente y la crate lo rechaza.
    let handled = if write_only {
        AccessFs::from_write(abi)
    } else {
        AccessFs::from_all(abi)
    };
    let mut rules = Ruleset::default()
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(handled)
        .map_err(|e| e.to_string())?
        .create()
        .map_err(|e| e.to_string())?;
    if !write_only && !read_only.is_empty() {
        rules = rules
            .add_rules(path_beneath_rules(
                read_only.iter().copied(),
                AccessFs::from_read(abi),
            ))
            .map_err(|e| e.to_string())?;
    }
    if !writable.is_empty() {
        rules = rules
            .add_rules(path_beneath_rules(writable.iter().copied(), handled))
            .map_err(|e| e.to_string())?;
    }
    let status = rules.restrict_self().map_err(|e| e.to_string())?;
    landlock_status(
        status,
        if write_only {
            "sólo escritura"
        } else {
            "servicio"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::DocumentMeta;

    #[test]
    fn sanitize_components() {
        assert_eq!(
            sanitize_component("Tesis Doctoral 2026"),
            "Tesis_Doctoral_2026"
        );
        assert_eq!(sanitize_component("   "), "_");
        let s = sanitize_component("../../etc/passwd");
        assert!(!s.contains('/'));
        assert_ne!(s, "..");
    }

    #[test]
    fn layout_paths_are_safe() {
        let layout = VaultLayout::new("/tmp/vault-test");
        let doc = Document {
            vault_id: "x".into(),
            sha256: "x".into(),
            blake3: "x".into(),
            size_bytes: 1,
            meta: DocumentMeta {
                title: "t".into(),
                category: Category::Tesis,
                author: "a".into(),
                id_number: None,
                department: "d".into(),
                registered_at: "now".into(),
                academic_year: None,
                file_name: "mi tesis.pdf".into(),
                extension: "pdf".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: vault_core::IntegrityStatus::Pending,
            origin_device: None,
        };
        let rel = layout.rel_path_for("Profesor Uno", &doc);
        assert_eq!(rel, "Profesor_Uno/Tesis/mi_tesis.pdf");
    }

    #[test]
    fn init_dirs_accept_new_documents_and_block_others() {
        use vault_core::Category;
        let dir = tempfile::tempdir().unwrap();
        let layout = VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();

        let doc = Document {
            vault_id: "v1".into(),
            sha256: "aa".into(),
            blake3: "bb".into(),
            size_bytes: 5,
            meta: DocumentMeta {
                title: "t".into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "d".into(),
                registered_at: "now".into(),
                academic_year: None,
                file_name: "nueva tesis.pdf".into(),
                extension: "pdf".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: vault_core::IntegrityStatus::Pending,
            origin_device: None,
        };
        let rel = layout.rel_path_for("Profesor Uno", &doc);

        // la carpeta creada por `init` DEBE admitir documentos nuevos
        let installed = layout.install_sealed(&rel, b"tesis").unwrap();
        assert!(installed.exists());
        assert_eq!(std::fs::read(&installed).unwrap(), b"tesis");

        // y no se puede instalar dos veces en la misma ruta
        assert!(layout.install_sealed(&rel, b"otra").is_err());

        // otro documento movido desde staging también se sella
        let staged = layout.staging().join("recibido.incoming");
        std::fs::write(&staged, b"recibido del movil").unwrap();
        let rel2 = "Profesor_Uno/Material_grafico/foto.png";
        let moved = layout.install_staged(rel2, &staged).unwrap();
        assert!(moved.exists());
        assert!(!staged.exists(), "el staging no debe quedar con copias");

        // el grupo y el resto del sistema no pueden escribir en la bóveda
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("vault/Profesor_Uno/Tesis"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o022, 0, "ni grupo ni otros con escritura");
            assert_eq!(mode & 0o700, 0o700, "el dueño conserva rwx");
            // self-heal: una carpeta heredada en 0o550 vuelve a ser escribible
            std::fs::set_permissions(
                dir.path().join("vault/Profesor_Uno/Tesis"),
                std::fs::Permissions::from_mode(0o550),
            )
            .unwrap();
            layout
                .install_sealed("Profesor_Uno/Tesis/otra.pdf", b"x")
                .unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn readonly_seal_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("doc.pdf");
        std::fs::write(&f, b"contenido").unwrap();
        seal_file(&f).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"contenido");
        let write_result = std::fs::write(&f, b"alterado");
        assert!(
            write_result.is_err(),
            "la escritura a un archivo sellado debe fallar"
        );
        unseal_file(&f).unwrap();
        std::fs::write(&f, b"ahora si").unwrap();
    }
}
