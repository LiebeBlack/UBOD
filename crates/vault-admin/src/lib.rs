//! vault-admin: lógica del panel de administración.
//!
//! - PIN de administrador y PIN de destrucción (argon2id, doble control).
//! - Bloqueo progresivo por intentos fallidos.
//! - Cola de admisión: admitir (sellado inmutable) o rechazar entregas.
//! - Destrucción supervisada: tombstone + wipe + auditoría encadenada.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use std::collections::HashMap;
use std::path::PathBuf;
use vault_core::{AdmissionState, Document, SealAck, SealStatus, Submission};
use vault_crypto::LocalTsa;
use vault_fs::{secure_wipe, unseal_file, VaultLayout};
use vault_store::{DeviceRecord, StoreError, VaultDb};

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("PIN incorrecto")]
    WrongPin,
    #[error("demasiados intentos fallidos; espere {secs}s")]
    LockedOut { secs: u64 },
    #[error("no existe un PIN configurado")]
    NoPin,
    #[error("PIN de destrucción requerido (doble control)")]
    DestructionPinRequired,
    #[error("entrega no encontrada: {0}")]
    SubmissionNotFound(String),
    #[error("documento no encontrado: {0}")]
    DocumentNotFound(String),
    #[error("conflicto de nombre en el destino: {0}")]
    Collision(String),
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de almacenamiento: {0}")]
    Store(#[from] StoreError),
    #[error("error del sellador de tiempo: {0}")]
    Tsa(#[from] vault_crypto::TsaError),
    #[error("error del sistema de archivos: {0}")]
    Fs(#[from] vault_fs::FsError),
}

// ----------------------------------------------------------------------
// Sellado unificado de documentos
// ----------------------------------------------------------------------

/// De dónde sale el contenido a sellar.
pub enum SealSource<'a> {
    /// Contenido ya en memoria (importación desde la aplicación gráfica).
    Bytes(&'a [u8]),
    /// Fichero ya recibido en staging, que se moverá a su destino (canal móvil).
    StagedFile(&'a std::path::Path),
}

/// Todo lo que describe un documento a sellar (agrupa los parámetros para que
/// el camino único de sellado siga siendo legible).
pub struct SealRequest<'a> {
    /// Origen del contenido.
    pub source: SealSource<'a>,
    /// Metadatos definitivos del documento.
    pub meta: vault_core::DocumentMeta,
    /// Dispositivo que lo entregó (None si es una importación local).
    pub origin_device: Option<String>,
    /// Quién ejecuta la operación (queda en la auditoría).
    pub actor: &'a str,
    /// Acción que se registra en la auditoría ("admit", "import"…).
    pub audit_action: &'a str,
}

/// Resultado de un intento de sellado.
#[derive(Debug)]
pub enum SealOutcome {
    /// Documento custodiado: ya está en disco, indexado y auditado.
    Sealed(Box<Document>),
    /// El contenido (SHA-256) ya existía: no se toca la bóveda.
    Duplicate {
        existing_vault_id: String,
        sha256: String,
        blake3: String,
    },
}

/// Sella un documento: instalación física → sello de tiempo RFC 3161 →
/// índice de texto → registro en la BD y en la cadena de auditoría.
///
/// Es el ÚNICO camino de sellado del sistema: lo usan la admisión de entregas
/// (`AdminService::admit`) y la importación local de la aplicación gráfica, de
/// modo que ambos producen exactamente el mismo documento custodiado.
///
/// No persiste: el llamante decide cuándo hacer `db.flush()` (la admisión
/// necesita guardar además el estado de la entrega en la misma operación).
pub fn seal_document(
    db: &mut VaultDb,
    layout: &VaultLayout,
    tsa: Option<&LocalTsa>,
    req: SealRequest<'_>,
) -> Result<SealOutcome, AdminError> {
    let SealRequest {
        source,
        meta,
        origin_device,
        actor,
        audit_action,
    } = req;
    let (hp, size_bytes) = match source {
        SealSource::Bytes(content) => (
            vault_crypto::HashPair::from_bytes(content),
            content.len() as u64,
        ),
        SealSource::StagedFile(path) => (
            vault_crypto::HashPair::from_file(path)?,
            std::fs::metadata(path)?.len(),
        ),
    };

    // Deduplicación por contenido: el mismo archivo nunca entra dos veces.
    if let Some(existing) = db.find_by_sha256(&hp.sha256) {
        return Ok(SealOutcome::Duplicate {
            existing_vault_id: existing.vault_id.clone(),
            sha256: hp.sha256,
            blake3: hp.blake3,
        });
    }

    let mut doc = Document {
        vault_id: vault_core::new_id(),
        sha256: hp.sha256.clone(),
        blake3: hp.blake3.clone(),
        size_bytes,
        meta: meta.clone(),
        rel_path: String::new(),
        rfc3161_token: None,
        rfc3161_time: None,
        integrity: vault_core::IntegrityStatus::Pending,
        origin_device,
    };
    doc.rel_path = layout.rel_path_for(&meta.author, &doc);
    if layout.abs_path(&doc.rel_path).exists() {
        return Err(AdminError::Collision(doc.rel_path));
    }

    // 1) instalación física (misma ruta para contenido en memoria y staging)
    match source {
        SealSource::Bytes(content) => {
            layout.install_sealed(&doc.rel_path, content)?;
        }
        SealSource::StagedFile(path) => {
            layout.install_staged(&doc.rel_path, path)?;
        }
    }

    // 2) sello de tiempo RFC 3161 (si la TSA no está disponible se sella sin él)
    if let Some(tsa) = tsa {
        match tsa.stamp_document(&doc.sha256) {
            Ok((token_b64, when)) => {
                doc.rfc3161_token = Some(token_b64);
                doc.rfc3161_time = Some(when);
            }
            Err(e) => tracing::warn!("TSA no disponible: {e}; se sella sin token remoto"),
        }
    }

    // 3) índice de texto: sin esto la búsqueda por contenido nunca encuentra nada
    doc.integrity = vault_core::IntegrityStatus::Ok;
    vault_index::index_document(db, layout, &doc);

    // 4) registro + auditoría
    db.add_document(doc.clone());
    db.append_audit(
        actor,
        audit_action,
        &doc.sha256,
        &format!("vault_id={} ruta={}", doc.vault_id, doc.rel_path),
    );
    Ok(SealOutcome::Sealed(Box::new(doc)))
}

/// Carga el ruleset institucional de `<datos>/config/rules.toml`.
///
/// El archivo externo permite a la institución ajustar la clasificación sin
/// recompilar. Si no existe, se usan las reglas embebidas; si existe pero es
/// ilegible, se avisa y se continúa con las embebidas (nunca se cae el
/// servicio por un archivo de configuración mal escrito).
pub fn load_ruleset(data_dir: &std::path::Path) -> vault_index::Ruleset {
    let path = data_dir.join("config/rules.toml");
    match vault_index::Ruleset::load(&path) {
        Ok(rs) => {
            tracing::info!(path = %path.display(), reglas = rs.rule.len(), "ruleset institucional cargado");
            rs
        }
        Err(e) => {
            if path.exists() {
                tracing::warn!(
                    path = %path.display(),
                    "ruleset externo ilegible ({e}); se usan las reglas embebidas"
                );
            }
            vault_index::Ruleset::default_ruleset()
        }
    }
}

/// Estado de bloqueo por intentos fallidos (rate-limit exponencial).
#[derive(Default)]
struct LockoutState {
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl LockoutState {
    /// Segundos restantes de bloqueo (0 = desbloqueado).
    fn remaining_secs(&self) -> u64 {
        match self.locked_until {
            Some(until) => {
                let now = std::time::Instant::now();
                if now < until {
                    (until - now).as_secs() + 1
                } else {
                    0
                }
            }
            None => 0,
        }
    }
}

const BASE_LOCK_SECS: u64 = 5;
const MAX_FAILURES_BEFORE_LOCK: u32 = 3;

fn next_lockout(st: &LockoutState) -> u64 {
    BASE_LOCK_SECS * 2u64.saturating_pow(st.failures.saturating_sub(MAX_FAILURES_BEFORE_LOCK))
}

/// Gestor de administración: PINs, admisión y destrucción supervisada.
pub struct AdminService {
    db: VaultDb,
    layout: VaultLayout,
    tsa: LocalTsa,
    /// Ruleset institucional: decide la clasificación en la admisión.
    ruleset: vault_index::Ruleset,
    pin_lockout: LockoutState,
    destruction_lockout: LockoutState,
    /// Sesiones activas: token -> expiración (epoch).
    sessions: HashMap<String, u64>,
    /// Destrucciones pendientes en ventana de gracia: vault_id -> ejecutar_después (epoch).
    pending_destructions: HashMap<String, u64>,
    session_ttl_secs: u64,
}

impl AdminService {
    pub fn new(db: VaultDb, layout: VaultLayout, tsa: LocalTsa) -> Self {
        AdminService {
            db,
            layout,
            tsa,
            ruleset: vault_index::Ruleset::default_ruleset(),
            pin_lockout: LockoutState::default(),
            destruction_lockout: LockoutState::default(),
            sessions: HashMap::new(),
            pending_destructions: HashMap::new(),
            session_ttl_secs: 15 * 60,
        }
    }

    /// Instala el ruleset institucional (el que decide la clasificación en la
    /// admisión). Se encadena sobre [`AdminService::new`].
    pub fn with_ruleset(mut self, ruleset: vault_index::Ruleset) -> Self {
        self.ruleset = ruleset;
        self
    }

    /// Reglas de clasificación vigentes en el servidor.
    pub fn ruleset(&self) -> &vault_index::Ruleset {
        &self.ruleset
    }

    /// Reemplaza el ruleset en caliente (p. ej. tras editar `rules.toml`).
    pub fn set_ruleset(&mut self, ruleset: vault_index::Ruleset) {
        self.ruleset = ruleset;
    }

    /// Segundos restantes del bloqueo del PIN de administrador (0 = sin bloqueo).
    pub fn admin_lockout_secs(&self) -> u64 {
        self.pin_lockout.remaining_secs()
    }

    /// Segundos restantes del bloqueo del PIN de destrucción (0 = sin bloqueo).
    pub fn destruction_lockout_secs(&self) -> u64 {
        self.destruction_lockout.remaining_secs()
    }

    /// Configura (o restablece) el PIN de destrucción (segundo factor humano).
    pub fn set_destruction_pin(
        &mut self,
        admin_session: &str,
        new_pin: &str,
    ) -> Result<(), AdminError> {
        self.validate_session(admin_session)?;
        if !is_strong_enough(new_pin) {
            return Err(AdminError::WrongPin);
        }
        let hash = hash_pin(new_pin)?;
        self.db.settings_mut().set("destruction_pin_hash", hash);
        self.db.append_audit(
            "admin",
            "set_destruction_pin",
            "admin",
            "PIN de destrucción configurado",
        );
        self.db.flush()?;
        Ok(())
    }

    /// Indica si el PIN de destrucción ya está configurado.
    pub fn has_destruction_pin(&self) -> bool {
        self.db.settings().get("destruction_pin_hash").is_some()
    }

    pub fn db_mut(&mut self) -> &mut VaultDb {
        &mut self.db
    }

    pub fn db(&self) -> &VaultDb {
        &self.db
    }

    pub fn layout(&self) -> &VaultLayout {
        &self.layout
    }

    /// Raíz física de la bóveda (para barridos externos, tombstones…).
    pub fn vault_root(&self) -> std::path::PathBuf {
        self.layout.root.clone()
    }

    // ---------- PIN ----------

    /// Configura (o restablece) el PIN de administrador. Solo funciona si no hay PIN previo
    /// o se proporciona el PIN actual.
    pub fn set_admin_pin(
        &mut self,
        current: Option<&str>,
        new_pin: &str,
    ) -> Result<(), AdminError> {
        if !is_strong_enough(new_pin) {
            return Err(AdminError::WrongPin);
        }
        if let Some(existing) = self.db.admin_pin_hash() {
            // requiere PIN actual
            let cur = current.ok_or(AdminError::WrongPin)?;
            self.check_lockout()?;
            if !verify_pin(cur, existing) {
                self.register_failure()?;
                return Err(AdminError::WrongPin);
            }
        }
        let hash = hash_pin(new_pin)?;
        self.db.set_admin_pin_hash(hash);
        self.db
            .append_audit("admin", "set_pin", "admin", "PIN configurado/restablecido");
        self.db.flush()?;
        Ok(())
    }

    /// Verifica el PIN y devuelve un token de sesión.
    pub fn login(&mut self, pin: &str) -> Result<String, AdminError> {
        let hash = self
            .db
            .admin_pin_hash()
            .ok_or(AdminError::NoPin)?
            .to_string();
        self.check_lockout()?;
        if !verify_pin(pin, &hash) {
            self.register_failure()?;
            self.db
                .append_audit("admin", "login_failed", "admin", "PIN incorrecto");
            self.db.flush()?;
            return Err(AdminError::WrongPin);
        }
        self.pin_lockout.failures = 0;
        let token = new_session_token();
        let now = now_epoch();
        self.sessions
            .insert(token.clone(), now + self.session_ttl_secs);
        self.db
            .append_audit("admin", "login_ok", "admin", "sesión iniciada");
        self.db.flush()?;
        Ok(token)
    }

    /// Valida un token de sesión (y lo renueva).
    pub fn validate_session(&mut self, token: &str) -> Result<(), AdminError> {
        let now = now_epoch();
        match self.sessions.get(token) {
            Some(&exp) if exp > now => {
                self.sessions
                    .insert(token.to_string(), now + self.session_ttl_secs);
                Ok(())
            }
            _ => Err(AdminError::NoPin),
        }
    }

    /// Cierra una sesión activa.
    pub fn logout(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    fn check_lockout(&self) -> Result<(), AdminError> {
        if let Some(until) = self.pin_lockout.locked_until {
            let now = std::time::Instant::now();
            if now < until {
                return Err(AdminError::LockedOut {
                    secs: (until - now).as_secs() + 1,
                });
            }
        }
        Ok(())
    }

    fn register_failure(&mut self) -> Result<(), AdminError> {
        self.pin_lockout.failures += 1;
        if self.pin_lockout.failures > MAX_FAILURES_BEFORE_LOCK {
            let secs = next_lockout(&self.pin_lockout);
            self.pin_lockout.locked_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(secs));
        }
        Ok(())
    }

    // ---------- Cola de admisión ----------

    /// Entregas pendientes de decisión.
    pub fn pending_submissions(&self) -> Vec<Submission> {
        self.db.pending_submissions()
    }

    /// Admite una entrega: sella el archivo en la bóveda (inmutable) + RFC 3161.
    pub fn admit(&mut self, submission_id: &str, actor: &str) -> Result<SealAck, AdminError> {
        let sub = self
            .db
            .find_submission(submission_id)
            .cloned()
            .ok_or_else(|| AdminError::SubmissionNotFound(submission_id.into()))?;
        if sub.state != AdmissionState::Pending {
            return Err(AdminError::SubmissionNotFound(format!(
                "{submission_id} (ya decidida)"
            )));
        }

        // 1. localizar el archivo en staging
        let staging_path = self.layout.staging().join(&sub.staging_path);
        let bytes_hash_ok = {
            let hp = vault_crypto::HashPair::from_file(&staging_path).map_err(AdminError::Io)?;
            hp.sha256 == sub.sha256 && hp.blake3 == sub.blake3
        };
        if !bytes_hash_ok {
            self.db.append_audit(
                actor,
                "admit_failed",
                &sub.sha256,
                "hash divergente en staging",
            );
            self.db.flush()?;
            return Err(AdminError::Io(std::io::Error::other(
                "el archivo en staging no coincide con el hash recibido",
            )));
        }

        // 2. clasificación del lado del servidor: el ruleset institucional
        //    (config/rules.toml) manda sobre lo que declare el dispositivo
        //    emisor, que no puede elegir la carpeta destino de la bóveda.
        let mut meta = sub.meta.clone();
        if let Some(decidida) = self.ruleset.classify(&meta.file_name) {
            if decidida != meta.category {
                tracing::info!(
                    archivo = %meta.file_name,
                    declarada = ?meta.category,
                    aplicada = ?decidida,
                    "categoría reclasificada por el ruleset del servidor"
                );
                self.db.append_audit(
                    actor,
                    "admit_reclassify",
                    &sub.sha256,
                    &format!(
                        "{:?} -> {:?} (ruleset institucional)",
                        meta.category, decidida
                    ),
                );
                meta.category = decidida;
            }
        }

        // 3. sellado unificado: instala, sella con TSA, indexa y audita.
        //    La deduplicación por contenido vive dentro del sellado.
        match seal_document(
            &mut self.db,
            &self.layout,
            Some(&self.tsa),
            SealRequest {
                source: SealSource::StagedFile(&staging_path),
                meta,
                origin_device: Some(sub.device_id.clone()),
                actor,
                audit_action: "admit",
            },
        )? {
            SealOutcome::Duplicate { sha256, blake3, .. } => {
                self.db
                    .update_submission_state(submission_id, AdmissionState::Rejected)?;
                let _ = std::fs::remove_file(&staging_path);
                self.db
                    .append_audit(actor, "admit_dup", &sha256, "duplicado descartado");
                self.db.flush()?;
                Ok(SealAck {
                    status: SealStatus::Sealed,
                    vault_id: None,
                    sha256,
                    blake3,
                    rfc3161_time: None,
                    message: Some("duplicado: ya existía en la bóveda".into()),
                })
            }
            SealOutcome::Sealed(doc) => {
                self.db
                    .update_submission_state(submission_id, AdmissionState::Admitted)?;
                self.db.flush()?;
                Ok(SealAck {
                    status: SealStatus::Sealed,
                    vault_id: Some(doc.vault_id.clone()),
                    sha256: doc.sha256.clone(),
                    blake3: doc.blake3.clone(),
                    rfc3161_time: doc.rfc3161_time.clone(),
                    message: Some("sellado e inmutable".into()),
                })
            }
        }
    }

    /// Rechaza una entrega: nunca toca la bóveda, se devuelve al origen.
    pub fn reject(
        &mut self,
        submission_id: &str,
        reason: &str,
        actor: &str,
    ) -> Result<(), AdminError> {
        let sub = self
            .db
            .find_submission(submission_id)
            .cloned()
            .ok_or_else(|| AdminError::SubmissionNotFound(submission_id.into()))?;
        if sub.state != AdmissionState::Pending {
            return Err(AdminError::SubmissionNotFound(format!(
                "{submission_id} (ya decidida)"
            )));
        }
        let staging_path = self.layout.staging().join(&sub.staging_path);
        let _ = std::fs::remove_file(&staging_path);
        self.db
            .update_submission_state(submission_id, AdmissionState::Rejected)?;
        self.db.append_audit(actor, "reject", &sub.sha256, reason);
        self.db.flush()?;
        Ok(())
    }

    // ---------- Destrucción supervisada ----------

    /// Programa la destrucción de un documento. Requiere PIN de administrador
    /// Y PIN de destrucción (doble control). Con gracia configurable.
    pub fn destroy(
        &mut self,
        vault_id: &str,
        admin_pin: &str,
        destruction_pin: &str,
        justification: &str,
        actor: &str,
    ) -> Result<(), AdminError> {
        // doble control: ambos PIN deben verificarse
        self.verify_admin_pin(admin_pin)?;
        self.verify_destruction_pin(destruction_pin)?;

        let doc = self
            .db
            .find_by_vault_id(vault_id)
            .cloned()
            .ok_or_else(|| AdminError::DocumentNotFound(vault_id.into()))?;

        let grace = self.db.settings().destruction_grace_secs;
        if grace > 0 {
            let exec_at = now_epoch() + grace;
            self.pending_destructions
                .insert(vault_id.to_string(), exec_at);
            self.db.append_audit(
                actor,
                "destroy_scheduled",
                &doc.sha256,
                &format!(
                    "vault_id={vault_id} ejecutar_en={} motivo={justification}",
                    exec_at
                ),
            );
            self.db.flush()?;
            return Ok(());
        }

        self.execute_destruction(&doc, justification, actor)
    }

    /// Ejecuta destrucciones cuya ventana de gracia expiró.
    pub fn process_due_destructions(&mut self, actor: &str) -> Result<usize, AdminError> {
        let now = now_epoch();
        let due: Vec<(String, Document)> = self
            .pending_destructions
            .iter()
            .filter(|(_, &t)| t <= now)
            .filter_map(|(id, _)| {
                self.db
                    .find_by_vault_id(id)
                    .cloned()
                    .map(|d| (id.clone(), d))
            })
            .collect();
        let n = due.len();
        for (id, doc) in due {
            self.pending_destructions.remove(&id);
            self.execute_destruction(&doc, "ventana de gracia expirada", actor)?;
        }
        Ok(n)
    }

    fn execute_destruction(
        &mut self,
        doc: &Document,
        justification: &str,
        actor: &str,
    ) -> Result<(), AdminError> {
        let path = self.layout.abs_path(&doc.rel_path);

        // 1. quitar inmutabilidad (chattr -i / readonly off)
        if path.exists() {
            unseal_file(&path)?;
            // 2. wipe seguro (sobrescritura múltiple) + remove
            secure_wipe(&path)?;
        }

        // 3. tombstone en disco con toda la trazabilidad
        let tombstone = format!(
            "DESTRUIDO\nvault_id={}\nsha256={}\nblake3={}\nruta={}\nmotivo={}\ncuando={}\nactor={}\n",
            doc.vault_id, doc.sha256, doc.blake3, doc.rel_path, justification, vault_core::now_rfc3339(), actor
        );
        let tb_dir = self.layout.tombstones();
        std::fs::create_dir_all(&tb_dir)?;
        let tb_path: PathBuf = tb_dir.join(format!("tombstone-{}.txt", doc.vault_id));
        std::fs::write(&tb_path, tombstone)?;
        vault_fs::seal_file(&tb_path)?;

        // 4. quitar del índice + auditoría encadenada
        self.db.remove_document(&doc.vault_id);
        self.db.append_audit(
            actor,
            "destroy_executed",
            &doc.sha256,
            &format!(
                "vault_id={} motivo={justification} tombstone={}",
                doc.vault_id,
                tb_path.display()
            ),
        );
        self.db.flush()?;
        Ok(())
    }

    // ---------- Verificaciones de PIN internas ----------

    fn verify_admin_pin(&mut self, pin: &str) -> Result<(), AdminError> {
        let hash = self
            .db
            .admin_pin_hash()
            .ok_or(AdminError::NoPin)?
            .to_string();
        self.check_lockout()?;
        if !verify_pin(pin, &hash) {
            self.register_failure()?;
            return Err(AdminError::WrongPin);
        }
        self.pin_lockout.failures = 0;
        Ok(())
    }

    /// El PIN de destrucción se verifica contra un hash en settings (segundo factor humano).
    fn verify_destruction_pin(&mut self, pin: &str) -> Result<(), AdminError> {
        match self.db.settings().get("destruction_pin_hash") {
            Some(h) if verify_pin(pin, &h) => Ok(()),
            _ => Err(AdminError::DestructionPinRequired),
        }
    }

    // ---------- Dispositivos ----------

    /// Genera un código de emparejamiento de un solo uso (10 min).
    /// La autenticación del actor es responsabilidad de la capa que llama
    /// (panel web con sesión, CLI local…).
    pub fn new_pairing_code(&mut self) -> Result<String, AdminError> {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b)
            .map_err(|e| AdminError::Io(std::io::Error::other(e.to_string())))?;
        let code: String = b.iter().map(|x| format!("{x:02X}")).collect();
        self.db.append_audit(
            "admin",
            "pairing_code",
            "admin",
            "código de emparejamiento emitido",
        );
        self.db.flush()?;
        Ok(code)
    }

    /// Empareja un dispositivo manualmente (fingerprint conocido, sin código).
    pub fn pair_device(
        &mut self,
        device_id: &str,
        cert_fingerprint: &str,
        actor: &str,
    ) -> Result<(), AdminError> {
        self.db.upsert_device(DeviceRecord {
            device_id: device_id.to_string(),
            cert_fingerprint: cert_fingerprint.to_string(),
            paired_at: vault_core::now_rfc3339(),
            enabled: true,
        });
        self.db
            .append_audit(actor, "pair_device", device_id, "dispositivo emparejado");
        self.db.flush()?;
        Ok(())
    }

    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.db.devices().to_vec()
    }
}

fn is_strong_enough(pin: &str) -> bool {
    pin.len() >= 6 && pin.chars().any(|c| c.is_ascii_digit())
}

/// hash argon2id con sal aleatoria.
pub fn hash_pin(pin: &str) -> Result<String, AdminError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon = argon2::Argon2::default();
    Ok(argon
        .hash_password(pin.as_bytes(), &salt)
        .map_err(|_| AdminError::WrongPin)?
        .to_string())
}

pub fn verify_pin(pin: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(pin.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

fn new_session_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("os randomness");
    hex_encode(&b)
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
fn base64_decode(s: &str) -> Vec<u8> {
    // decodificador mínimo para las pruebas (el sellado real lo hace
    // vault-crypto::LocalTsa::stamp_document)
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .expect("token en base64")
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// extensión de settings para guardar el hash del PIN de destrucción.
trait SettingsExt {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&mut self, key: &str, value: String);
}

impl SettingsExt for vault_store::Settings {
    fn get(&self, key: &str) -> Option<String> {
        self.extra.get(key).cloned()
    }
    fn set(&mut self, key: &str, value: String) {
        self.extra.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use vault_core::{Category, DocumentMeta};
    use vault_crypto::dbcrypto::generate_keyfile;

    fn setup(dir: &Path) -> AdminService {
        let kf = generate_keyfile();
        let db = VaultDb::open(&dir.join("db"), &kf).unwrap();
        let layout = VaultLayout::new(dir.join("vault"));
        layout.init(&["Profesor".to_string()]).unwrap();
        let tsa = LocalTsa::new().unwrap();
        AdminService::new(db, layout, tsa)
    }

    fn make_submission(dir: &Path) -> (Submission, std::path::PathBuf) {
        let content = b"PDF-FAKE contenido de tesis doctoral 2026";
        let hp = vault_crypto::HashPair::from_bytes(content);
        let staging = dir.join("vault/.staging");
        std::fs::create_dir_all(&staging).unwrap();
        let rel = format!("{}.bin", &hp.sha256[..12]);
        let p = staging.join(&rel);
        std::fs::write(&p, content).unwrap();
        let sub = Submission {
            submission_id: vault_core::new_id(),
            device_id: "AND_TEST_1".into(),
            meta: DocumentMeta {
                title: "Tesis Ing".into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: "tesis-ing.pdf".into(),
                extension: "pdf".into(),
            },
            sha256: hp.sha256,
            blake3: hp.blake3,
            size_bytes: content.len() as u64,
            staging_path: rel,
            received_at: vault_core::now_rfc3339(),
            state: AdmissionState::Pending,
        };
        (sub, p)
    }

    #[test]
    fn pin_lifecycle_and_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        assert!(matches!(svc.login("123456"), Err(AdminError::NoPin)));
        svc.set_admin_pin(None, "123456").unwrap();
        assert!(matches!(svc.login("000000"), Err(AdminError::WrongPin)));
        let tok = svc.login("123456").unwrap();
        svc.validate_session(&tok).unwrap();
        // restablecer sin PIN actual falla
        assert!(svc.set_admin_pin(None, "654321").is_err());
        // restablecer con PIN actual funciona
        svc.set_admin_pin(Some("123456"), "654321").unwrap();
        assert!(svc.login("654321").is_ok());
    }

    #[test]
    fn admit_seals_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        svc.set_admin_pin(None, "123456").unwrap();
        let (sub, staging_file) = make_submission(dir.path());
        svc.db_mut().add_submission(sub.clone());
        svc.db_mut().flush().unwrap();

        let ack = svc.admit(&sub.submission_id, "tester").unwrap();
        assert_eq!(ack.status, SealStatus::Sealed);
        assert!(ack.vault_id.is_some());

        // el archivo sellado existe y está protegido
        let doc = svc.db().find_by_sha256(&sub.sha256).unwrap().clone();
        let sealed = svc.layout().abs_path(&doc.rel_path);
        assert!(sealed.exists());
        assert!(
            std::fs::write(&sealed, b"hack").is_err(),
            "sellado debe impedir escritura"
        );

        // deduplicación
        std::fs::write(&staging_file, b"PDF-FAKE contenido de tesis doctoral 2026").unwrap();
        let sub2 = Submission {
            submission_id: vault_core::new_id(),
            ..sub.clone()
        };
        svc.db_mut().add_submission(sub2.clone());
        let ack2 = svc.admit(&sub2.submission_id, "tester").unwrap();
        assert!(ack2.message.unwrap().contains("duplicado"));
    }

    #[test]
    fn destroy_requires_double_pin() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        svc.set_admin_pin(None, "123456").unwrap();
        svc.db_mut()
            .settings_mut()
            .set("destruction_pin_hash", hash_pin("999999").unwrap());

        let (sub, _) = make_submission(dir.path());
        svc.db_mut().add_submission(sub.clone());
        let ack = svc.admit(&sub.submission_id, "tester").unwrap();
        let vault_id = ack.vault_id.unwrap();
        let doc = svc.db().find_by_vault_id(&vault_id).unwrap().clone();
        let path = svc.layout().abs_path(&doc.rel_path);
        assert!(path.exists());

        // solo PIN admin: falla
        assert!(matches!(
            svc.destroy(&vault_id, "123456", "", "prueba", "tester"),
            Err(AdminError::DestructionPinRequired)
        ));
        // PIN destrucción mal: falla
        assert!(matches!(
            svc.destroy(&vault_id, "123456", "111111", "prueba", "tester"),
            Err(AdminError::DestructionPinRequired)
        ));
        // doble PIN correcto: destruye con tombstone
        svc.destroy(
            &vault_id,
            "123456",
            "999999",
            "solicitud del titular",
            "tester",
        )
        .unwrap();
        assert!(!path.exists(), "el archivo debe desaparecer físicamente");
        assert!(svc.db().find_by_vault_id(&vault_id).is_none());
        // tombstone sellado existe
        let tbs: Vec<_> = std::fs::read_dir(svc.layout().tombstones())
            .unwrap()
            .collect();
        assert_eq!(tbs.len(), 1);
        // la cadena de auditoría sigue íntegra y registra la destrucción
        assert!(svc.db().verify_audit_chain().is_ok());
        let actions: Vec<&str> = svc.db().audit().iter().map(|a| a.action.as_str()).collect();
        assert!(actions.contains(&"destroy_executed"));
    }

    fn text_meta(file_name: &str) -> DocumentMeta {
        DocumentMeta {
            title: "Notas".into(),
            category: Category::Tesis,
            author: "Profesor Uno".into(),
            id_number: None,
            department: "Ingeniería".into(),
            registered_at: vault_core::now_rfc3339(),
            academic_year: Some(2026),
            file_name: file_name.into(),
            extension: file_name.rsplit('.').next().unwrap_or("").to_string(),
        }
    }

    /// El sellado es el camino único: sella con TSA, deja el contenido en el
    /// índice de texto (la búsqueda por contenido debe encontrar el documento)
    /// y audita la operación.
    #[test]
    fn seal_document_stamps_indexes_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = VaultDb::open(&dir.path().join("db"), &generate_keyfile()).unwrap();
        let layout = VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        let tsa = LocalTsa::new().unwrap();

        let content = b"contenido indexable de la tesis de ingenieria";
        let outcome = seal_document(
            &mut db,
            &layout,
            Some(&tsa),
            SealRequest {
                source: SealSource::Bytes(content),
                meta: text_meta("notas.txt"),
                origin_device: Some("AND_LOCAL".into()),
                actor: "tester",
                audit_action: "import",
            },
        )
        .unwrap();
        let doc = match outcome {
            SealOutcome::Sealed(d) => *d,
            SealOutcome::Duplicate { .. } => panic!("no debía ser duplicado"),
        };

        // 1) está en disco y sellado
        assert!(layout.abs_path(&doc.rel_path).exists());
        assert_eq!(doc.origin_device.as_deref(), Some("AND_LOCAL"));
        assert_eq!(doc.integrity, vault_core::IntegrityStatus::Ok);

        // 2) sello RFC 3161 real (token base64 no vacío + fecha)
        let token = doc.rfc3161_token.clone().expect("token TSA");
        assert!(!base64_decode(&token).is_empty());
        assert!(doc.rfc3161_time.as_deref().unwrap_or("").ends_with('Z'));

        // 3) índice de texto: la búsqueda por contenido encuentra el documento
        let text = db.get_text(&doc.vault_id).unwrap_or_default();
        assert!(
            text.contains("indexable"),
            "índice de texto vacío: {text:?}"
        );
        let q = vault_index::SearchQuery::parse("texto:indexable");
        let found = vault_index::search(&db, &q);
        assert_eq!(found.len(), 1, "búsqueda por contenido debe encontrarlo");

        // 4) auditoría encadenada con la acción indicada
        assert!(db.verify_audit_chain().is_ok());
        assert!(db.audit().iter().any(|a| a.action == "import"));

        // 5) el mismo contenido no entra dos veces
        let again = seal_document(
            &mut db,
            &layout,
            Some(&tsa),
            SealRequest {
                source: SealSource::Bytes(content),
                meta: text_meta("otro-nombre.txt"),
                origin_device: None,
                actor: "tester",
                audit_action: "import",
            },
        )
        .unwrap();
        match again {
            SealOutcome::Duplicate {
                existing_vault_id, ..
            } => assert_eq!(existing_vault_id, doc.vault_id),
            SealOutcome::Sealed(_) => panic!("el duplicado no debe sellarse"),
        }
        assert_eq!(db.documents().len(), 1);
    }

    /// Dos documentos distintos con el mismo nombre en la misma carpeta no
    /// pueden pisarse: el segundo se rechaza con un error claro.
    #[test]
    fn seal_document_rejects_name_collision() {
        let dir = tempfile::tempdir().unwrap();
        let layout = VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        let mut db = VaultDb::open(&dir.path().join("db"), &generate_keyfile()).unwrap();

        seal_document(
            &mut db,
            &layout,
            None,
            SealRequest {
                source: SealSource::Bytes(b"primera version"),
                meta: text_meta("informe.txt"),
                origin_device: None,
                actor: "tester",
                audit_action: "import",
            },
        )
        .unwrap();

        let err = seal_document(
            &mut db,
            &layout,
            None,
            SealRequest {
                source: SealSource::Bytes(b"contenido diferente"),
                meta: text_meta("informe.txt"),
                origin_device: None,
                actor: "tester",
                audit_action: "import",
            },
        )
        .unwrap_err();
        assert!(matches!(err, AdminError::Collision(_)), "error: {err}");
        assert_eq!(db.documents().len(), 1);
    }

    #[test]
    fn reject_never_touches_vault() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path());
        let (sub, staging_file) = make_submission(dir.path());
        svc.db_mut().add_submission(sub.clone());
        svc.reject(&sub.submission_id, "documento ilegible", "tester")
            .unwrap();
        assert!(!staging_file.exists());
        assert!(svc.db().documents().is_empty());
        assert!(svc.pending_submissions().is_empty());
    }

    /// El ruleset institucional (`config/rules.toml`) manda sobre la categoría
    /// que declara el dispositivo emisor: nadie elige desde fuera en qué carpeta
    /// de la bóveda acaba un documento.
    #[test]
    fn server_ruleset_overrides_the_declared_category() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("rules.toml"),
            "[[rule]]\ncategory = \"Evaluacion\"\nfilename_contains = [\"tesis-ing\"]\n",
        )
        .unwrap();

        let mut svc = setup(dir.path()).with_ruleset(load_ruleset(dir.path()));
        svc.set_admin_pin(None, "123456").unwrap();

        // El emisor declara «Tesis»; la institución clasifica «Evaluacion».
        let (sub, _staging) = make_submission(dir.path());
        assert_eq!(sub.meta.category, Category::Tesis);
        svc.db_mut().add_submission(sub.clone());

        let ack = svc.admit(&sub.submission_id, "tester").unwrap();
        assert_eq!(ack.status, SealStatus::Sealed);
        let doc = svc.db().find_by_sha256(&sub.sha256).unwrap().clone();
        assert_eq!(
            doc.meta.category,
            Category::Evaluacion,
            "el ruleset del servidor debe imponerse al emisor"
        );
        assert!(
            doc.rel_path.contains("Evaluacion"),
            "el documento se archiva según la clasificación institucional: {}",
            doc.rel_path
        );
        // La reclasificación queda registrada y la cadena sigue íntegra.
        assert!(
            svc.db()
                .audit()
                .iter()
                .any(|e| e.action == "admit_reclassify"),
            "la reclasificación debe auditarse"
        );
        assert!(svc.db().verify_audit_chain().is_ok());
        // Y la categoría declarada ya no coincide con la que hay en la bóveda.
        assert_ne!(doc.meta.category, sub.meta.category);
    }

    /// Sin `config/rules.toml` entran las reglas embebidas, que también corrigen
    /// una categoría declarada de forma incorrecta.
    #[test]
    fn embedded_ruleset_is_the_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut svc = setup(dir.path()).with_ruleset(load_ruleset(dir.path()));
        svc.set_admin_pin(None, "123456").unwrap();

        let (mut sub, _staging) = make_submission(dir.path());
        sub.meta.category = Category::MaterialGrafico; // el emisor declara otra cosa
        svc.db_mut().add_submission(sub.clone());
        svc.admit(&sub.submission_id, "tester").unwrap();

        let doc = svc.db().find_by_sha256(&sub.sha256).unwrap();
        assert_eq!(
            doc.meta.category,
            Category::Tesis,
            "la regla embebida por nombre (tesis*) debe aplicarse"
        );
    }
}
