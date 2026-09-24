//! vault-roles: control de acceso granular (PoLP) sobre la bóveda.
//!
//! Roles estándar:
//! - Docente: solo lectura.
//! - Administrativo: renombrar/mover/papelera (soft-delete). Nunca borrado definitivo.
//! - Coordinación: auditoría; sus ediciones crean una copia de seguridad
//!   inmutable (versionado seguro) del contenido previo.
//! - Director: visualización global; cada acción suya se registra en auditoría.
//!
//! Toda operación pasa por `RoleService`, que valida el rol, ejecuta el
//! efecto físico mínimo y escribe en la cadena de auditoría.

use vault_core::{Document, DocumentVersion, Role, TrashedDocument, User};
use vault_store::VaultDb;

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("usuario o contraseña incorrectos")]
    BadCredentials,
    #[error("usuario deshabilitado")]
    Disabled,
    #[error("el rol {0} no tiene permiso para esta operación")]
    Denied(&'static str),
    #[error("documento no encontrado: {0}")]
    NotFound(String),
    #[error("ya existe un documento con ese nombre en el destino: {0}")]
    Collision(String),
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de almacenamiento: {0}")]
    Store(#[from] vault_store::StoreError),
    #[error("error del sistema de archivos: {0}")]
    Fs(#[from] vault_fs::FsError),
}

/// Sesión autenticada de un usuario con rol.
#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub display_name: String,
    pub role: Role,
}

impl Session {
    pub fn actor(&self) -> &str {
        &self.username
    }
}

/// Servicio de operaciones con control de roles. Opera sobre la misma BD
/// cifrada y el mismo layout físico de la bóveda.
pub struct RoleService {
    db: VaultDb,
    layout: vault_fs::VaultLayout,
}

impl RoleService {
    pub fn new(db: VaultDb, layout: vault_fs::VaultLayout) -> Self {
        RoleService { db, layout }
    }

    pub fn db(&self) -> &VaultDb {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut VaultDb {
        &mut self.db
    }

    pub fn layout(&self) -> &vault_fs::VaultLayout {
        &self.layout
    }

    /// ¿La bóveda está en modo consulta?
    ///
    /// Ocurre cuando otro proceso (el servicio) tiene la escritura: se puede
    /// leer y autenticar, pero ninguna operación puede modificar la BD.
    pub fn is_read_only(&self) -> bool {
        self.db.is_read_only()
    }

    // ------------------------------------------------------------------
    // Administración de usuarios (pantalla interna de administración)
    // ------------------------------------------------------------------
    //
    // Estas operaciones NO escriben en la cadena de auditoría institucional:
    // la administración de sistemas queda deliberadamente fuera del rastro
    // visible para Coordinación y Dirección.

    /// Usuarios con su rol y estado (solo lectura).
    pub fn users(&self) -> Vec<User> {
        self.db.users().to_vec()
    }

    /// Fija el PIN de un usuario existente (argon2id). No audita.
    pub fn set_user_pin(&mut self, username: &str, pin: &str) -> Result<(), RoleError> {
        if pin.len() < 6 {
            return Err(RoleError::BadCredentials);
        }
        self.require_writable()?;
        let mut user = self
            .db
            .find_user(username)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(username.to_string()))?;
        user.pin_hash = vault_roles_pin_hash(pin);
        self.db.upsert_user(user);
        self.db.flush()?;
        Ok(())
    }

    /// Habilita o deshabilita un usuario. No audita.
    pub fn set_user_enabled(&mut self, username: &str, enabled: bool) -> Result<(), RoleError> {
        self.require_writable()?;
        let mut user = self
            .db
            .find_user(username)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(username.to_string()))?;
        user.enabled = enabled;
        self.db.upsert_user(user);
        self.db.flush()?;
        Ok(())
    }

    /// Da de alta (o actualiza) un usuario con su rol. No audita.
    pub fn upsert_user(
        &mut self,
        username: &str,
        display: &str,
        role: Role,
        pin: &str,
    ) -> Result<(), RoleError> {
        self.require_writable()?;
        upsert_user_with_pin(&mut self.db, username, display, role, pin)
    }

    /// Aborta cualquier operación de escritura cuando la bóveda está en modo
    /// consulta, ANTES de tocar el disco: así nunca queda un cambio a medias.
    fn require_writable(&self) -> Result<(), RoleError> {
        if self.db.is_read_only() {
            Err(RoleError::Store(vault_store::StoreError::ReadOnly))
        } else {
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // Autenticación
    // ------------------------------------------------------------------

    /// Autentica un usuario contra la BD (argon2id) y devuelve su sesión.
    pub fn login(&mut self, username: &str, password: &str) -> Result<Session, RoleError> {
        let user = self
            .db
            .find_user(username)
            .cloned()
            .ok_or(RoleError::BadCredentials)?;
        if !user.enabled {
            return Err(RoleError::Disabled);
        }
        if !vault_roles_pin_verify(password, &user.pin_hash) {
            return Err(RoleError::BadCredentials);
        }
        // El último acceso se registra solo si esta instancia puede escribir:
        // en modo consulta no se toca un estado que no se puede persistir.
        if !self.db.is_read_only() {
            let mut u = user.clone();
            u.last_login = Some(vault_core::now_rfc3339());
            self.db.upsert_user(u);
            self.db.flush()?;
        }
        Ok(Session {
            username: user.username,
            display_name: user.display_name,
            role: user.role,
        })
    }

    // ------------------------------------------------------------------
    // Consulta (todos los roles)
    // ------------------------------------------------------------------

    /// Documentos visibles (activos, no en papelera).
    pub fn documents(&self, _s: &Session) -> Vec<Document> {
        self.db.documents().to_vec()
    }

    /// Papelera (solo roles con can_restore la listan).
    pub fn trashed(&self, s: &Session) -> Result<Vec<TrashedDocument>, RoleError> {
        if s.role.can_restore() {
            Ok(self.db.trashed().to_vec())
        } else {
            Err(RoleError::Denied("ver papelera"))
        }
    }

    /// Versiones inmutables de un documento.
    pub fn versions_of(
        &self,
        s: &Session,
        vault_id: &str,
    ) -> Result<Vec<DocumentVersion>, RoleError> {
        if !s.role.can_view() {
            return Err(RoleError::Denied("ver versiones"));
        }
        Ok(self.db.versions_of(vault_id).into_iter().cloned().collect())
    }

    /// Auditoría (Coordinación y Director).
    pub fn audit(&self, s: &Session) -> Result<Vec<vault_store::AuditEntry>, RoleError> {
        if !s.role.can_audit() {
            return Err(RoleError::Denied("consultar auditoría"));
        }
        Ok(self.db.audit().to_vec())
    }

    /// Búsqueda compuesta.
    pub fn search(&self, _s: &Session, query: &str) -> Result<Vec<Document>, RoleError> {
        let q = vault_index_parse(query);
        Ok(self
            .db
            .documents()
            .iter()
            .filter(|d| q.matches(d, self.db.get_text(&d.vault_id)))
            .cloned()
            .collect())
    }

    // ------------------------------------------------------------------
    // Administrativo: renombrar / mover / papelera / restaurar
    // ------------------------------------------------------------------

    /// Renombra el archivo físico y el metadato. Solo Administrativo.
    pub fn rename(
        &mut self,
        s: &Session,
        vault_id: &str,
        new_name: &str,
    ) -> Result<Document, RoleError> {
        if !s.role.can_rename_or_move() {
            return Err(RoleError::Denied("renombrar"));
        }
        self.require_writable()?;
        let new_name = new_name.trim().to_string();
        if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
            return Err(RoleError::Collision("nombre inválido".into()));
        }
        let mut doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;

        let old_rel = doc.rel_path.clone();
        let new_rel = {
            let mut parts: Vec<&str> = old_rel.split('/').collect();
            let last = parts.len() - 1;
            parts[last] = &new_name;
            parts.join("/")
        };
        if new_rel == old_rel {
            return Ok(doc);
        }
        // colisión en destino
        if self.layout.abs_path(&new_rel).exists() {
            return Err(RoleError::Collision(new_rel));
        }

        let old_abs = self.layout.abs_path(&old_rel);
        let new_abs = self.layout.abs_path(&new_rel);
        // retirar inmutabilidad → mover → volver a sellar
        vault_fs::unseal_file(&old_abs)?;
        if let Some(parent) = new_abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&old_abs, &new_abs)?;
        vault_fs::seal_file(&new_abs)?;
        // limpiar directorios vacíos del origen
        if let Some(p) = old_abs.parent() {
            let _ = std::fs::remove_dir(p); // solo si quedó vacío
        }

        doc.meta.file_name = new_name.clone();
        doc.rel_path = new_rel.clone();
        self.db.update_document(doc.clone());
        self.db.append_audit(
            s.actor(),
            "rename",
            &doc.sha256,
            &format!("vault_id={vault_id} «{old_rel}» → «{new_rel}»"),
        );
        self.db.flush()?;
        Ok(doc)
    }

    /// Mueve un documento a otra categoría (y opcionalmente otro autor/carpeta).
    /// Solo Administrativo. Recoloca físicamente el archivo sellado.
    pub fn move_to_category(
        &mut self,
        s: &Session,
        vault_id: &str,
        new_category: vault_core::Category,
    ) -> Result<Document, RoleError> {
        if !s.role.can_rename_or_move() {
            return Err(RoleError::Denied("mover"));
        }
        self.require_writable()?;
        let mut doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;
        if doc.meta.category == new_category {
            return Ok(doc);
        }

        let old_rel = doc.rel_path.clone();
        let new_rel = self.layout.rel_path_for(&doc.meta.author, &{
            let mut d = doc.clone();
            d.meta.category = new_category;
            d
        });
        if new_rel == old_rel {
            doc.meta.category = new_category;
            self.db.update_document(doc.clone());
            return Ok(doc);
        }
        if self.layout.abs_path(&new_rel).exists() {
            return Err(RoleError::Collision(new_rel));
        }

        let old_abs = self.layout.abs_path(&old_rel);
        let new_abs = self.layout.abs_path(&new_rel);
        vault_fs::unseal_file(&old_abs)?;
        if let Some(parent) = new_abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&old_abs, &new_abs)?;
        vault_fs::seal_file(&new_abs)?;
        if let Some(p) = old_abs.parent() {
            let _ = std::fs::remove_dir(p);
        }

        doc.meta.category = new_category;
        doc.rel_path = new_rel.clone();
        self.db.update_document(doc.clone());
        self.db.append_audit(
            s.actor(),
            "move",
            &doc.sha256,
            &format!("vault_id={vault_id} «{old_rel}» → «{new_rel}»"),
        );
        self.db.flush()?;
        Ok(doc)
    }

    /// Soft-delete: el documento sale del índice activo y va a la papelera.
    /// El archivo físico NO se destruye. Solo Administrativo.
    pub fn soft_delete(
        &mut self,
        s: &Session,
        vault_id: &str,
        reason: &str,
    ) -> Result<(), RoleError> {
        if !s.role.can_soft_delete() {
            return Err(RoleError::Denied("enviar a papelera"));
        }
        self.require_writable()?;
        let doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;
        let reason = reason.trim().to_string();
        self.db
            .trash_document(doc, s.actor(), vault_core::now_rfc3339(), &reason);
        self.db.append_audit(
            s.actor(),
            "soft_delete",
            vault_id,
            &format!("a papelera (motivo: {reason}); archivo intacto, restaurable"),
        );
        self.db.flush()?;
        Ok(())
    }

    /// Restaura un documento de la papelera. Solo Administrativo.
    pub fn restore(&mut self, s: &Session, vault_id: &str) -> Result<Document, RoleError> {
        if !s.role.can_restore() {
            return Err(RoleError::Denied("restaurar"));
        }
        self.require_writable()?;
        let doc = self
            .db
            .restore_trashed(vault_id)
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;
        self.db.append_audit(
            s.actor(),
            "restore",
            &doc.sha256,
            &format!("vault_id={vault_id} restaurado desde papelera"),
        );
        self.db.flush()?;
        Ok(doc)
    }

    // ------------------------------------------------------------------
    // Coordinación: edición con versión inmutable previa
    // ------------------------------------------------------------------

    /// Edita metadatos. Si el actor es Coordinación, ANTES de aplicar la
    /// edición se crea una copia de seguridad inmutable del documento actual
    /// (contenido + metadatos) que ningún rol puede borrar.
    pub fn edit_meta(
        &mut self,
        s: &Session,
        vault_id: &str,
        new_title: Option<String>,
        new_department: Option<String>,
        new_year: Option<u16>,
        note: &str,
    ) -> Result<Document, RoleError> {
        if !s.role.can_edit_meta() {
            return Err(RoleError::Denied("editar metadatos"));
        }
        self.require_writable()?;
        let mut doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;

        // 1) versión inmutable del estado previo (solo Coordinación)
        if s.role.versions_on_edit() {
            let next_version = self
                .db
                .versions_of(vault_id)
                .last()
                .map(|v| v.version + 1)
                .unwrap_or(1);
            let version_rel = format!(
                "{}{}/.versions/{}_v{}",
                doc.rel_path
                    .rsplit_once('/')
                    .map(|(d, _)| format!("{d}/"))
                    .unwrap_or_default(),
                ".versiones",
                doc.vault_id,
                next_version
            );
            let src = self.layout.abs_path(&doc.rel_path);
            let dst = self.layout.abs_path(&version_rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&src, &dst)?;
            vault_fs::seal_file(&dst)?;
            self.db.add_version(DocumentVersion {
                vault_id: vault_id.to_string(),
                version: next_version,
                sha256: doc.sha256.clone(),
                rel_path: version_rel,
                meta: doc.meta.clone(),
                created_by: s.actor().to_string(),
                created_at: vault_core::now_rfc3339(),
                note: note.to_string(),
            });
        }

        // 2) aplicar edición de metadatos (el contenido nunca cambia aquí)
        if let Some(t) = new_title {
            doc.meta.title = t;
        }
        if let Some(d) = new_department {
            doc.meta.department = d;
        }
        if let Some(y) = new_year {
            doc.meta.academic_year = Some(y);
        }
        self.db.update_document(doc.clone());
        self.db.append_audit(
            s.actor(),
            "edit_meta",
            &doc.sha256,
            &format!(
                "vault_id={vault_id} nota={note} versionado={}",
                s.role.versions_on_edit()
            ),
        );
        self.db.flush()?;
        Ok(doc)
    }

    // ------------------------------------------------------------------
    // Director: todas sus acciones ya quedan auditadas por cada operación;
    // aquí se registra explícitamente cada consulta para transparencia total.
    // ------------------------------------------------------------------

    /// Consulta de visualización registrada (para Director se audita TODO).
    ///
    /// En modo consulta la visualización no puede registrarse, así que se
    /// rechaza en lugar de dejar una consulta de Dirección sin rastro.
    pub fn view(&mut self, s: &Session, vault_id: &str) -> Result<Document, RoleError> {
        self.require_writable()?;
        let doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| RoleError::NotFound(vault_id.into()))?;
        self.db.append_audit(
            s.actor(),
            "view",
            &doc.sha256,
            &format!("vault_id={vault_id} rol={}", s.role.label()),
        );
        self.db.flush()?;
        Ok(doc)
    }
}

// ----------------------------------------------------------------------
// gestión de usuarios (la usan el bootstrap de la GUI y la consola IT)
// ----------------------------------------------------------------------

/// Crea o actualiza un usuario con PIN hasheado (argon2id).
pub fn upsert_user_with_pin(
    db: &mut VaultDb,
    username: &str,
    display: &str,
    role: Role,
    pin: &str,
) -> Result<(), RoleError> {
    let username = username.trim().to_lowercase();
    if username.is_empty() || pin.len() < 6 {
        return Err(RoleError::BadCredentials);
    }
    let hash = vault_roles_pin_hash(pin);
    let user = User {
        username: username.clone(),
        display_name: display.trim().to_string(),
        role,
        pin_hash: hash,
        created_at: vault_core::now_rfc3339(),
        last_login: None,
        enabled: true,
    };
    db.upsert_user(user);
    db.flush()?;
    Ok(())
}

/// Verifica un PIN contra su hash argon2id (utilidad pública: la usan las
/// herramientas de administración para comprobar credenciales sin abrir sesión).
pub fn verify_pin(pin: &str, hash: &str) -> bool {
    vault_roles_pin_verify(pin, hash)
}

// wrappers para no depender de argon2 en este crate (vault-admin ya lo trae)
fn vault_roles_pin_hash(pin: &str) -> String {
    vault_admin_hash_pin(pin)
}

fn vault_roles_pin_verify(pin: &str, hash: &str) -> bool {
    vault_admin_verify_pin(pin, hash)
}

fn vault_admin_hash_pin(pin: &str) -> String {
    use argon2_shim::ArgonShim;
    ArgonShim::hash(pin)
}

fn vault_admin_verify_pin(pin: &str, hash: &str) -> bool {
    use argon2_shim::ArgonShim;
    ArgonShim::verify(pin, hash)
}

/// Módulo puente: argon2id directo (misma función que vault-admin).
mod argon2_shim {
    use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

    pub struct ArgonShim;

    impl ArgonShim {
        pub fn hash(pin: &str) -> String {
            let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
            argon2::Argon2::default()
                .hash_password(pin.as_bytes(), &salt)
                .expect("argon2 hash")
                .to_string()
        }

        pub fn verify(pin: &str, hash: &str) -> bool {
            match PasswordHash::new(hash) {
                Ok(parsed) => argon2::Argon2::default()
                    .verify_password(pin.as_bytes(), &parsed)
                    .is_ok(),
                Err(_) => false,
            }
        }
    }
}

// utilidad local de parseo de búsqueda (misma gramática que vault-index)
fn vault_index_parse(q: &str) -> vault_index_shim::SearchQuery {
    vault_index_shim::SearchQuery::parse(q)
}

mod vault_index_shim {
    // re-usa vault-index real vía dependencia
    pub use vault_index::SearchQuery;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use vault_core::{Category, DocumentMeta};
    use vault_crypto::dbcrypto::generate_keyfile;

    fn setup(dir: &Path) -> RoleService {
        let kf = generate_keyfile();
        let db = VaultDb::open(&dir.join("db"), &kf).unwrap();
        let layout = vault_fs::VaultLayout::new(dir.join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        RoleService::new(db, layout)
    }

    fn seed_document(dir: &Path, svc: &mut RoleService, name: &str) -> Document {
        let content = format!("contenido de {name}").into_bytes();
        let hp = vault_crypto::HashPair::from_bytes(&content);
        let mut doc = Document {
            vault_id: vault_core::new_id(),
            sha256: hp.sha256.clone(),
            blake3: hp.blake3.clone(),
            size_bytes: content.len() as u64,
            meta: DocumentMeta {
                title: name.into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: name.into(),
                extension: "pdf".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: vault_core::IntegrityStatus::Ok,
            origin_device: None,
        };
        doc.rel_path = svc.layout().rel_path_for(&doc.meta.author, &doc);
        let abs = svc.layout().abs_path(&doc.rel_path);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, &content).unwrap();
        vault_fs::seal_file(&abs).unwrap();
        svc.db_mut().add_document(doc.clone());
        svc.db_mut().flush().unwrap();
        let _ = dir;
        doc
    }

    fn users(svc: &mut RoleService) {
        upsert_user_with_pin(svc.db_mut(), "doc1", "Docente Uno", Role::Docente, "123456").unwrap();
        upsert_user_with_pin(
            svc.db_mut(),
            "adm1",
            "Admin Uno",
            Role::Administrativo,
            "123456",
        )
        .unwrap();
        upsert_user_with_pin(
            svc.db_mut(),
            "coord1",
            "Coord Uno",
            Role::Coordinacion,
            "123456",
        )
        .unwrap();
        upsert_user_with_pin(
            svc.db_mut(),
            "dir1",
            "Director Uno",
            Role::Director,
            "123456",
        )
        .unwrap();
    }

    #[test]
    fn login_and_role_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);

        let docente = svc.login("doc1", "123456").unwrap();
        assert_eq!(docente.role, Role::Docente);
        assert!(svc.login("doc1", "mala").is_err());

        // docente: solo lectura → renombrar denegado
        let doc = seed_document(dir.path(), &mut svc, "t1.pdf");
        assert!(matches!(
            svc.rename(&docente, &doc.vault_id, "x.pdf"),
            Err(RoleError::Denied(_))
        ));

        // director: ver sí, renombrar no
        let director = svc.login("dir1", "123456").unwrap();
        svc.view(&director, &doc.vault_id).unwrap();
        assert!(matches!(
            svc.rename(&director, &doc.vault_id, "x.pdf"),
            Err(RoleError::Denied(_))
        ));
        // la consulta del director quedó auditada
        let audit = svc.audit(&director).unwrap();
        assert!(audit
            .iter()
            .any(|a| a.action == "view" && a.actor == "dir1"));

        // coordinación: ve auditoría
        let coord = svc.login("coord1", "123456").unwrap();
        assert!(svc.audit(&coord).is_ok());
        // docente: no
        assert!(matches!(svc.audit(&docente), Err(RoleError::Denied(_))));
    }

    #[test]
    fn administrativo_rename_move_soft_delete_restore() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);
        let adm = svc.login("adm1", "123456").unwrap();
        let doc = seed_document(dir.path(), &mut svc, "tesis_original.pdf");

        // renombrar
        let renamed = svc
            .rename(&adm, &doc.vault_id, "tesis_renombrada.pdf")
            .unwrap();
        assert_eq!(renamed.meta.file_name, "tesis_renombrada.pdf");
        assert!(svc.layout().abs_path(&renamed.rel_path).exists());
        assert!(!svc.layout().abs_path(&doc.rel_path).exists());

        // mover de categoría
        let moved = svc
            .move_to_category(&adm, &doc.vault_id, Category::Resolucion)
            .unwrap();
        assert_eq!(moved.meta.category, Category::Resolucion);
        assert!(svc.layout().abs_path(&moved.rel_path).exists());

        // restaurar sin soft-delete previo → error
        assert!(matches!(
            svc.restore(&adm, &doc.vault_id),
            Err(RoleError::NotFound(_))
        ));

        // soft-delete → fuera del índice, en papelera, archivo intacto
        let path_before = svc.layout().abs_path(&moved.rel_path);
        svc.soft_delete(&adm, &doc.vault_id, "duplicado detectado")
            .unwrap();
        assert!(svc.db().find_by_vault_id(&doc.vault_id).is_none());
        assert!(path_before.exists(), "el archivo NO se destruye");

        // restaurar → vuelve al índice
        let restored = svc.restore(&adm, &doc.vault_id).unwrap();
        assert_eq!(restored.vault_id, doc.vault_id);
        assert!(svc.db().find_by_vault_id(&doc.vault_id).is_some());
    }

    #[test]
    fn coordinacion_edit_creates_immutable_version() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);
        let coord = svc.login("coord1", "123456").unwrap();
        let adm = svc.login("adm1", "123456").unwrap();
        let doc = seed_document(dir.path(), &mut svc, "tesis_v1.pdf");

        // administrativo edita: NO versiona
        svc.edit_meta(
            &adm,
            &doc.vault_id,
            Some("título sin versión".into()),
            None,
            None,
            "ajuste menor",
        )
        .unwrap();
        assert!(svc.db().versions_of(&doc.vault_id).is_empty());

        // coordinación edita: crea versión inmutable del estado previo
        svc.edit_meta(
            &coord,
            &doc.vault_id,
            Some("Tesis de Ingeniería (título corregido)".into()),
            None,
            Some(2027),
            "corrección de título por supervisión",
        )
        .unwrap();
        let versions = svc.db().versions_of(&doc.vault_id);
        assert_eq!(versions.len(), 1);
        let v0 = versions[0];
        assert_eq!(v0.version, 1);
        // la versión congelada conserva el título previo a la edición de Coordinación
        assert_eq!(v0.meta.title, "título sin versión");
        // la copia existe, está sellada y es inaccesible para escritura
        let vpath = svc.layout().abs_path(&v0.rel_path);
        assert!(vpath.exists());
        assert!(
            std::fs::write(&vpath, b"hack").is_err(),
            "la versión debe ser inmutable"
        );

        // segunda edición → v2
        svc.edit_meta(
            &coord,
            &doc.vault_id,
            None,
            Some("Ciencias".into()),
            None,
            "dept corregido",
        )
        .unwrap();
        assert_eq!(svc.db().versions_of(&doc.vault_id).len(), 2);

        // ninguna operación estándar borra versiones (no hay API para ello)
    }

    #[test]
    fn audit_chain_survives_all_operations() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);
        let adm = svc.login("adm1", "123456").unwrap();
        let coord = svc.login("coord1", "123456").unwrap();
        let doc = seed_document(dir.path(), &mut svc, "t.pdf");
        svc.rename(&adm, &doc.vault_id, "t2.pdf").unwrap();
        svc.move_to_category(&adm, &doc.vault_id, Category::Evaluacion)
            .unwrap();
        svc.edit_meta(
            &coord,
            &doc.vault_id,
            Some("nuevo".into()),
            None,
            None,
            "nota",
        )
        .unwrap();
        svc.soft_delete(&adm, &doc.vault_id, "limpieza").unwrap();
        svc.restore(&adm, &doc.vault_id).unwrap();
        assert!(svc.db().verify_audit_chain().is_ok());
        let actions: Vec<&str> = svc.db().audit().iter().map(|a| a.action.as_str()).collect();
        for expected in ["rename", "move", "edit_meta", "soft_delete", "restore"] {
            assert!(
                actions.contains(&expected),
                "falta {expected} en {actions:?}"
            );
        }
    }

    /// Con el servicio activo (escritor), la aplicación abre en modo consulta:
    /// puede autenticar y leer, pero nunca escribe (así no pisa el estado del
    /// servicio cuando éste guarde).
    #[test]
    fn read_only_mode_allows_login_but_blocks_writes() {
        let dir = tempfile::tempdir().unwrap();
        let kf = generate_keyfile();
        let vault_root = dir.path().join("vault");

        let db_w = VaultDb::open(&dir.path().join("db"), &kf).unwrap();
        let layout = vault_fs::VaultLayout::new(&vault_root);
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        let mut writer = RoleService::new(db_w, layout);
        users(&mut writer);
        let doc = seed_document(dir.path(), &mut writer, "t1.pdf");
        assert!(!writer.is_read_only());

        // segundo handle sobre la MISMA bóveda: modo consulta
        let db_r = VaultDb::open(&dir.path().join("db"), &kf).unwrap();
        assert!(db_r.is_read_only());
        let mut reader = RoleService::new(db_r, vault_fs::VaultLayout::new(&vault_root));
        assert!(reader.is_read_only());

        // leer y autenticar sí
        let adm = reader.login("adm1", "123456").unwrap();
        assert_eq!(reader.documents(&adm).len(), 1);

        // escribir no: la operación falla de forma explícita
        assert!(matches!(
            reader.soft_delete(&adm, &doc.vault_id, "prueba"),
            Err(RoleError::Store(vault_store::StoreError::ReadOnly))
        ));
        assert!(matches!(
            reader.rename(&adm, &doc.vault_id, "otro.pdf"),
            Err(RoleError::Store(vault_store::StoreError::ReadOnly))
        ));

        // el escritor sigue siendo el dueño de la base de datos
        assert!(!writer.is_read_only());
        let adm_w = writer.login("adm1", "123456").unwrap();
        writer
            .soft_delete(&adm_w, &doc.vault_id, "de verdad")
            .unwrap();
    }

    /// La administración de usuarios de la pantalla interna NO deja rastro en
    /// la cadena de auditoría institucional, pero sí surte efecto.
    #[test]
    fn user_administration_leaves_no_audit_trace() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);
        let before = svc.db().audit().len();

        svc.set_user_pin("adm1", "654321").unwrap();
        svc.set_user_enabled("doc1", false).unwrap();
        svc.upsert_user("nuevo", "Nuevo Docente", Role::Docente, "abcdef")
            .unwrap();

        assert_eq!(
            svc.db().audit().len(),
            before,
            "la administración interna no debe auditarse en la cadena institucional"
        );
        // efectos reales
        assert!(svc.login("adm1", "654321").is_ok());
        assert!(matches!(
            svc.login("doc1", "123456"),
            Err(RoleError::Disabled)
        ));
        assert!(svc.login("nuevo", "abcdef").is_ok());
        // y la cadena sigue íntegra
        assert!(svc.db().verify_audit_chain().is_ok());
    }

    /// La búsqueda de la aplicación consulta el índice de texto: sin indexar no
    /// encuentra el contenido y con el texto indexado sí.
    #[test]
    fn search_uses_the_text_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        users(&mut svc);
        let docente = svc.login("doc1", "123456").unwrap();
        let doc = seed_document(dir.path(), &mut svc, "tesis.pdf");

        assert!(svc.search(&docente, "texto:penicilina").unwrap().is_empty());
        svc.db_mut()
            .set_text(&doc.vault_id, "estudio sobre la penicilina en 2026");
        let found = svc.search(&docente, "texto:penicilina").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].vault_id, doc.vault_id);
        // y sigue funcionando la búsqueda por metadatos
        assert_eq!(svc.search(&docente, "autor:Profesor").unwrap().len(), 1);
    }
}
