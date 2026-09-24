//! vault-store: base de datos cifrada de la bóveda (sustituto puro-Rust de SQLCipher).
//!
//! Formato: snapshot JSON cifrado con XChaCha20-Poly1305 (bloques de 4 KiB, AAD
//! por índice) + cadena de auditoría hash-linked donde cada entrada incluye el
//! hash de la anterior: borrar o alterar cualquier entrada rompe toda la cadena.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vault_core::{Document, DocumentVersion, IntegrityStatus, Submission, TrashedDocument, User};
use vault_crypto::dbcrypto::DbCrypto;

pub const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("error de almacenamiento: {0}")]
    Io(#[from] std::io::Error),
    #[error("error criptográfico: {0}")]
    Crypto(#[from] vault_crypto::DbCryptoError),
    #[error("error de serialización: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("recurso no encontrado: {0}")]
    NotFound(String),
    /// La BD se abrió en modo consulta porque otro proceso (el servicio) la
    /// tiene abierta para escritura: se puede LEER pero nunca escribir, para
    /// que el estado en memoria del escritor no se pierda silenciosamente.
    #[error("bóveda en modo consulta: el servicio está activo y tiene la escritura; no se puede modificar la base de datos")]
    ReadOnly,
    /// Se pedía escritura exclusiva y otro proceso la tiene.
    #[error("la bóveda ya está abierta para escritura por otro proceso ({0})")]
    Locked(String),
}

/// Evento de auditoría con encadenamiento criptográfico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: String,
    /// SHA-256 de la representación canónica de la entrada anterior.
    pub prev_hash: String,
}

impl AuditEntry {
    /// Hash de esta entrada (para encadenar la siguiente).
    pub fn content_hash(&self) -> String {
        use sha2::Digest;
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.seq,
            self.timestamp,
            self.actor,
            self.action,
            self.subject,
            self.detail,
            self.prev_hash
        );
        hex::encode(sha2::Sha256::digest(canonical.as_bytes()))
    }
}

/// Estado completo persistido de la bóveda.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DbState {
    documents: Vec<Document>,
    submissions: Vec<Submission>,
    audit: Vec<AuditEntry>,
    devices: Vec<DeviceRecord>,
    admin_pin_hash: Option<String>,
    settings: Settings,
    /// Usuarios institucionales con roles (PoLP).
    #[serde(default)]
    users: Vec<User>,
    /// Papelera: documentos con soft-delete (restaurables).
    #[serde(default)]
    trashed: Vec<TrashedDocument>,
    /// Versiones inmutables (creadas por Coordinación).
    #[serde(default)]
    versions: Vec<DocumentVersion>,
    /// Índice de texto completo: vault_id -> texto extraído (PDF/OCR).
    #[serde(default)]
    text_index: std::collections::HashMap<String, String>,
}

/// Configuración persistente gestionada desde el panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_tsa_url")]
    pub tsa_url: Option<String>,
    /// Categorías que exigen aprobación humana antes del sellado.
    #[serde(default)]
    pub admission_required_categories: Vec<String>,
    /// Ventana de gracia de destrucción supervisada (segundos, 0 = inmediata).
    #[serde(default)]
    pub destruction_grace_secs: u64,
    #[serde(default = "default_sweep_interval")]
    pub sweep_interval_secs: u64,
    /// Claves adicionales (p.ej. destruction_pin_hash).
    #[serde(default)]
    pub extra: std::collections::HashMap<String, String>,
}

fn default_tsa_url() -> Option<String> {
    None
}
fn default_sweep_interval() -> u64 {
    6 * 3600
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tsa_url: default_tsa_url(),
            admission_required_categories: Vec::new(),
            destruction_grace_secs: 0,
            sweep_interval_secs: default_sweep_interval(),
            extra: std::collections::HashMap::new(),
        }
    }
}

/// Dispositivo móvil emparejado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    /// SHA-256 del certificado de cliente (fingerprint).
    pub cert_fingerprint: String,
    pub paired_at: String,
    pub enabled: bool,
}

/// Base de datos cifrada con acceso exclusivo y guardado atómico.
///
/// Escritor único: al abrir se toma un bloqueo de fichero (`db/.lock`) que
/// impide que dos procesos mantengan a la vez estado en memoria sobre el
/// mismo `vault.db.enc` (el servicio y la aplicación gráfica, por ejemplo),
/// evitando que el último en guardar borre los cambios del otro.
pub struct VaultDb {
    path: PathBuf,
    crypto: DbCrypto,
    state: DbState,
    /// `true` cuando otro proceso tiene la escritura (no se puede guardar).
    read_only: bool,
    /// Bloqueo mantenido (y liberado al soltar) mientras este handle sea el
    /// escritor: es un guardián, nunca se lee.
    _lock: Option<std::fs::File>,
}

impl VaultDb {
    /// Abre (o crea) la base de datos en `dir/vault.db.enc` con el keyfile dado.
    ///
    /// Intenta ser el escritor; si otro proceso ya la tiene abierta para
    /// escritura, la apertura **no falla**: devuelve la bóveda en modo
    /// consulta (`is_read_only()`) para que la interfaz avise en pantalla.
    pub fn open(dir: &Path, keyfile: &[u8; 64]) -> Result<Self, StoreError> {
        Self::open_with_lock(dir, keyfile, false)
    }

    /// Igual que [`VaultDb::open`] pero exige la escritura exclusiva: si otro
    /// proceso la tiene, devuelve [`StoreError::Locked`] en lugar de degradar
    /// a modo consulta. Lo usa el servicio, que nunca debe mentir sobre su
    /// capacidad de guardar.
    pub fn open_writer(dir: &Path, keyfile: &[u8; 64]) -> Result<Self, StoreError> {
        Self::open_with_lock(dir, keyfile, true)
    }

    fn open_with_lock(
        dir: &Path,
        keyfile: &[u8; 64],
        require_write: bool,
    ) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("vault.db.enc");
        let lock_path = dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        let read_only = match lock_file.try_lock() {
            Ok(()) => false,
            Err(std::fs::TryLockError::WouldBlock) => {
                if require_write {
                    return Err(StoreError::Locked(lock_path.display().to_string()));
                }
                true
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(StoreError::Io(e)),
        };
        let crypto = DbCrypto::new(keyfile);
        let state = if path.exists() {
            let blob = std::fs::read(&path)?;
            let plain = crypto.decrypt_blob(&blob)?;
            serde_json::from_slice(&plain)?
        } else {
            DbState::default()
        };
        Ok(VaultDb {
            path,
            crypto,
            state,
            read_only,
            _lock: if read_only { None } else { Some(lock_file) },
        })
    }

    /// ¿Está la bóveda en modo consulta por tener otro proceso la escritura?
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Persiste el estado cifrado de forma atómica (tmp + rename).
    ///
    /// En modo consulta no escribe nada y devuelve [`StoreError::ReadOnly`].
    pub fn flush(&self) -> Result<(), StoreError> {
        if self.read_only {
            return Err(StoreError::ReadOnly);
        }
        let plain = serde_json::to_vec(&self.state)?;
        let blob = self.crypto.encrypt_blob(&plain)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    // ---------- Documentos ----------

    pub fn add_document(&mut self, doc: Document) {
        self.state.documents.push(doc);
    }

    pub fn documents(&self) -> &[Document] {
        &self.state.documents
    }

    pub fn find_by_sha256(&self, sha256: &str) -> Option<&Document> {
        self.state.documents.iter().find(|d| d.sha256 == sha256)
    }

    pub fn find_by_vault_id(&self, vault_id: &str) -> Option<&Document> {
        self.state.documents.iter().find(|d| d.vault_id == vault_id)
    }

    pub fn update_integrity(&mut self, vault_id: &str, status: IntegrityStatus) {
        for d in self.state.documents.iter_mut() {
            if d.vault_id == vault_id {
                d.integrity = status;
            }
        }
    }

    /// Reemplaza un documento (renombrar/mover/editar metadatos).
    pub fn update_document(&mut self, doc: Document) {
        for d in self.state.documents.iter_mut() {
            if d.vault_id == doc.vault_id {
                *d = doc;
                return;
            }
        }
    }

    // ---------- Usuarios (roles PoLP) ----------

    pub fn users(&self) -> &[User] {
        &self.state.users
    }

    pub fn find_user(&self, username: &str) -> Option<&User> {
        self.state
            .users
            .iter()
            .find(|u| u.username.eq_ignore_ascii_case(username))
    }

    pub fn upsert_user(&mut self, user: User) {
        match self
            .state
            .users
            .iter_mut()
            .find(|u| u.username == user.username)
        {
            Some(existing) => *existing = user,
            None => self.state.users.push(user),
        }
    }

    pub fn remove_user(&mut self, username: &str) -> Option<User> {
        let idx = self
            .state
            .users
            .iter()
            .position(|u| u.username.eq_ignore_ascii_case(username))?;
        Some(self.state.users.remove(idx))
    }

    // ---------- Papelera (soft-delete) ----------

    pub fn trashed(&self) -> &[TrashedDocument] {
        &self.state.trashed
    }

    /// Saca el documento del índice activo y lo conserva en la papelera.
    pub fn trash_document(&mut self, doc: Document, by: &str, at: String, reason: &str) {
        self.remove_document(&doc.vault_id);
        self.state.trashed.push(TrashedDocument {
            document: doc,
            trashed_by: by.to_string(),
            trashed_at: at,
            reason: reason.to_string(),
        });
    }

    /// Restaura un documento de la papelera al índice activo.
    pub fn restore_trashed(&mut self, vault_id: &str) -> Option<Document> {
        let idx = self
            .state
            .trashed
            .iter()
            .position(|t| t.document.vault_id == vault_id)?;
        let t = self.state.trashed.remove(idx);
        self.state.documents.push(t.document.clone());
        Some(t.document)
    }

    /// Borra una entrada de la papelera (solo modo IT).
    pub fn purge_trashed(&mut self, vault_id: &str) -> Option<TrashedDocument> {
        let idx = self
            .state
            .trashed
            .iter()
            .position(|t| t.document.vault_id == vault_id)?;
        Some(self.state.trashed.remove(idx))
    }

    // ---------- Versiones inmutables ----------

    pub fn versions(&self) -> &[DocumentVersion] {
        &self.state.versions
    }

    pub fn versions_of(&self, vault_id: &str) -> Vec<&DocumentVersion> {
        let mut vs: Vec<_> = self
            .state
            .versions
            .iter()
            .filter(|v| v.vault_id == vault_id)
            .collect();
        vs.sort_by_key(|v| v.version);
        vs
    }

    pub fn add_version(&mut self, version: DocumentVersion) {
        self.state.versions.push(version);
    }

    /// Elimina el documento del índice (tras destrucción supervisada).
    pub fn remove_document(&mut self, vault_id: &str) -> Option<Document> {
        let idx = self
            .state
            .documents
            .iter()
            .position(|d| d.vault_id == vault_id)?;
        Some(self.state.documents.remove(idx))
    }

    // ---------- Entregas ----------

    pub fn submissions(&self) -> &[Submission] {
        &self.state.submissions
    }

    pub fn pending_submissions(&self) -> Vec<Submission> {
        self.state
            .submissions
            .iter()
            .filter(|s| s.state == vault_core::AdmissionState::Pending)
            .cloned()
            .collect()
    }

    pub fn add_submission(&mut self, sub: Submission) {
        self.state.submissions.push(sub);
    }

    pub fn find_submission(&self, submission_id: &str) -> Option<&Submission> {
        self.state
            .submissions
            .iter()
            .find(|s| s.submission_id == submission_id)
    }

    pub fn update_submission_state(
        &mut self,
        submission_id: &str,
        state: vault_core::AdmissionState,
    ) -> Result<(), StoreError> {
        self.state
            .submissions
            .iter_mut()
            .find(|s| s.submission_id == submission_id)
            .map(|s| s.state = state)
            .ok_or_else(|| StoreError::NotFound(submission_id.to_string()))
    }

    // ---------- Dispositivos ----------

    pub fn devices(&self) -> &[DeviceRecord] {
        &self.state.devices
    }

    pub fn upsert_device(&mut self, dev: DeviceRecord) {
        match self
            .state
            .devices
            .iter_mut()
            .find(|d| d.device_id == dev.device_id)
        {
            Some(existing) => *existing = dev,
            None => self.state.devices.push(dev),
        }
    }

    pub fn device_by_fingerprint(&self, fp: &str) -> Option<&DeviceRecord> {
        self.state.devices.iter().find(|d| d.cert_fingerprint == fp)
    }

    // ---------- PIN ----------

    pub fn admin_pin_hash(&self) -> Option<&str> {
        self.state.admin_pin_hash.as_deref()
    }

    pub fn set_admin_pin_hash(&mut self, hash: String) {
        self.state.admin_pin_hash = Some(hash);
    }

    // ---------- Índice de texto ----------

    pub fn set_text(&mut self, vault_id: &str, text: &str) {
        self.state
            .text_index
            .insert(vault_id.to_string(), text.to_string());
    }

    pub fn get_text(&self, vault_id: &str) -> Option<&str> {
        self.state.text_index.get(vault_id).map(|s| s.as_str())
    }

    // ---------- Configuración ----------

    pub fn settings(&self) -> &Settings {
        &self.state.settings
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.state.settings
    }

    // ---------- Auditoría ----------

    /// Añade una entrada a la cadena de auditoría y devuelve su hash.
    pub fn append_audit(
        &mut self,
        actor: &str,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> String {
        let prev_hash = self
            .state
            .audit
            .last()
            .map(|e| e.content_hash())
            .unwrap_or_else(|| AUDIT_GENESIS.to_string());
        let entry = AuditEntry {
            seq: self.state.audit.len() as u64,
            timestamp: vault_core::now_rfc3339(),
            actor: actor.to_string(),
            action: action.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
            prev_hash,
        };
        let h = entry.content_hash();
        self.state.audit.push(entry);
        h
    }

    pub fn audit(&self) -> &[AuditEntry] {
        &self.state.audit
    }

    /// Verifica la integridad de toda la cadena de auditoría.
    pub fn verify_audit_chain(&self) -> Result<(), String> {
        let mut prev = AUDIT_GENESIS.to_string();
        for e in &self.state.audit {
            if e.prev_hash != prev {
                return Err(format!("entrada {} enlaza con hash incorrecto", e.seq));
            }
            prev = e.content_hash();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Category, DocumentMeta, IntegrityStatus};

    fn doc(sha: &str) -> Document {
        Document {
            vault_id: vault_core::new_id(),
            sha256: sha.to_string(),
            blake3: "aa".repeat(32),
            size_bytes: 1234,
            meta: DocumentMeta {
                title: "Tesis de prueba".into(),
                category: Category::Tesis,
                author: "Prof. Prueba".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: "tesis.pdf".into(),
                extension: "pdf".into(),
            },
            rel_path: "Profesor/Tesis/tesis.pdf".into(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: IntegrityStatus::Ok,
            origin_device: Some("AND_TEST".into()),
        }
    }

    #[test]
    fn open_flush_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kf = vault_crypto::dbcrypto::generate_keyfile();
        {
            let mut db = VaultDb::open(dir.path(), &kf).unwrap();
            db.add_document(doc(&"ab".repeat(32)));
            db.append_audit("tester", "ingest", "tesis.pdf", "vía de prueba");
            db.flush().unwrap();
        }
        let db = VaultDb::open(dir.path(), &kf).unwrap();
        assert_eq!(db.documents().len(), 1);
        assert!(db.find_by_sha256(&"ab".repeat(32)).is_some());
        assert_eq!(db.audit().len(), 1);
        assert!(db.verify_audit_chain().is_ok());
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let kf1 = vault_crypto::dbcrypto::generate_keyfile();
        let kf2 = vault_crypto::dbcrypto::generate_keyfile();
        {
            let mut db = VaultDb::open(dir.path(), &kf1).unwrap();
            db.add_document(doc(&"cd".repeat(32)));
            db.flush().unwrap();
        }
        assert!(VaultDb::open(dir.path(), &kf2).is_err());
    }

    #[test]
    fn single_writer_lock_and_read_only_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let kf = vault_crypto::dbcrypto::generate_keyfile();

        // primer handle: escritor
        let mut writer = VaultDb::open(dir.path(), &kf).unwrap();
        assert!(!writer.is_read_only());

        // segundo handle: no puede escribir, pero SÍ leer (modo consulta)
        let mut reader = VaultDb::open(dir.path(), &kf).unwrap();
        assert!(reader.is_read_only());
        reader.add_document(doc(&"ee".repeat(32)));
        assert!(matches!(reader.flush(), Err(StoreError::ReadOnly)));

        // quien exige escritura falla con un error explícito
        assert!(matches!(
            VaultDb::open_writer(dir.path(), &kf),
            Err(StoreError::Locked(_))
        ));

        // el escritor guarda con normalidad
        writer.add_document(doc(&"ff".repeat(32)));
        writer.flush().unwrap();

        // al soltar el escritor, el siguiente puede serlo
        drop(writer);
        let takeover = VaultDb::open(dir.path(), &kf).unwrap();
        assert!(!takeover.is_read_only());
        assert_eq!(takeover.documents().len(), 1);
        assert!(takeover.flush().is_ok());
    }

    #[test]
    fn text_index_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kf = vault_crypto::dbcrypto::generate_keyfile();
        let id = vault_core::new_id();
        {
            let mut db = VaultDb::open(dir.path(), &kf).unwrap();
            db.set_text(&id, "contenido extraído de la tesis");
            db.flush().unwrap();
        }
        let db = VaultDb::open(dir.path(), &kf).unwrap();
        assert_eq!(
            db.get_text(&id),
            Some("contenido extraído de la tesis"),
            "el índice de texto debe sobrevivir al guardado"
        );
    }

    #[test]
    fn audit_chain_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let kf = vault_crypto::dbcrypto::generate_keyfile();
        {
            let mut db = VaultDb::open(dir.path(), &kf).unwrap();
            db.append_audit("a", "op1", "x", "");
            db.append_audit("a", "op2", "y", "");
            db.flush().unwrap();
        }
        // manipular el blob: descifrar, alterar detail, recifrar
        let blob = std::fs::read(dir.path().join("vault.db.enc")).unwrap();
        let crypto = DbCrypto::new(&kf);
        let mut state: DbState =
            serde_json::from_slice(&crypto.decrypt_blob(&blob).unwrap()).unwrap();
        state.audit[0].detail = "manipulado".into();
        let forged = crypto
            .encrypt_blob(&serde_json::to_vec(&state).unwrap())
            .unwrap();
        std::fs::write(dir.path().join("vault.db.enc"), forged).unwrap();

        let db = VaultDb::open(dir.path(), &kf).unwrap();
        assert!(db.verify_audit_chain().is_err());
    }
}
