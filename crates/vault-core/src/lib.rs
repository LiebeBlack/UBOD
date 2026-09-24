//! vault-core: tipos fundamentales del Sistema Integral de Bóveda.
//!
//! Define el esquema de metadatos académicos, las categorías documentales,
//! los estados de admisión y el envelope JSON del protocolo de transferencia
//! Android ⇄ Bóveda.

use serde::{Deserialize, Serialize};

/// Categorías académicas soportadas por el esquema de clasificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Tesis (licenciatura, maestría, doctorado).
    Tesis,
    /// Expediente personal de profesor.
    ExpedienteProfesor,
    /// Resoluciones administrativas y académicas.
    Resolucion,
    /// Evaluaciones y calificaciones.
    Evaluacion,
    /// Fotografía documental (minutas, pizarras, actas fotografiadas).
    FotografiaDocumental,
    /// Material gráfico y didáctico.
    MaterialGrafico,
}

impl Category {
    /// Nombre de carpeta física dentro de la bóveda.
    pub fn dir_name(self) -> &'static str {
        match self {
            Category::Tesis => "Tesis",
            Category::ExpedienteProfesor => "Expediente_Profesor",
            Category::Resolucion => "Resolucion",
            Category::Evaluacion => "Evaluacion",
            Category::FotografiaDocumental => "Fotografia_Documental",
            Category::MaterialGrafico => "Material_Grafico",
        }
    }

    /// Parse desde el nombre de carpeta o el nombre de protocolo.
    pub fn from_dir_name(s: &str) -> Option<Category> {
        match s {
            "Tesis" | "tesis" => Some(Category::Tesis),
            "Expediente_Profesor" | "expediente_profesor" => Some(Category::ExpedienteProfesor),
            "Resolucion" | "resolucion" => Some(Category::Resolucion),
            "Evaluacion" | "evaluacion" => Some(Category::Evaluacion),
            "FotografiaDocumental" | "Fotografia_Documental" | "fotografia_documental" => {
                Some(Category::FotografiaDocumental)
            }
            "MaterialGrafico" | "Material_Grafico" | "material_grafico" => {
                Some(Category::MaterialGrafico)
            }
            _ => None,
        }
    }

    pub const ALL: [Category; 6] = [
        Category::Tesis,
        Category::ExpedienteProfesor,
        Category::Resolucion,
        Category::Evaluacion,
        Category::FotografiaDocumental,
        Category::MaterialGrafico,
    ];
}

/// Estado de verificación de integridad de un documento sellado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Verificado en el último barrido.
    Ok,
    /// Aún no verificado (recién sellado, primer barrido pendiente).
    Pending,
    /// Divergencia de hash: manipulación o bit rot.
    Tampered,
}

/// Roles del entorno educativo/administrativo (principio de menor privilegio).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Solo lectura.
    Docente,
    /// Gestión documental de bajo nivel: renombrar/mover/papelera. Sin borrado definitivo.
    Administrativo,
    /// Auditoría y supervisión; sus ediciones crean versión inmutable e inborrable.
    Coordinacion,
    /// Visualización global; todas sus acciones quedan registradas.
    Director,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Role::Docente,
        Role::Administrativo,
        Role::Coordinacion,
        Role::Director,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Role::Docente => "Docente",
            Role::Administrativo => "Administrativo",
            Role::Coordinacion => "Coordinación",
            Role::Director => "Director",
        }
    }

    /// Puede ver documentos (todos los roles pueden).
    pub fn can_view(self) -> bool {
        true
    }

    /// Puede renombrar o mover documentos (solo Administrativo).
    pub fn can_rename_or_move(self) -> bool {
        matches!(self, Role::Administrativo)
    }

    /// Puede enviar a papelera (soft-delete). Nunca hay borrado definitivo
    /// desde los roles estándar: eso es exclusivo del modo IT.
    pub fn can_soft_delete(self) -> bool {
        matches!(self, Role::Administrativo)
    }

    /// Puede restaurar desde papelera.
    pub fn can_restore(self) -> bool {
        matches!(self, Role::Administrativo)
    }

    /// Puede editar metadatos; si es Coordinación, la edición versiona inmutable.
    pub fn can_edit_meta(self) -> bool {
        matches!(self, Role::Administrativo | Role::Coordinacion)
    }

    /// Las ediciones de este rol generan copia de seguridad inmutable.
    pub fn versions_on_edit(self) -> bool {
        matches!(self, Role::Coordinacion)
    }

    /// Puede consultar la auditoría.
    pub fn can_audit(self) -> bool {
        matches!(self, Role::Coordinacion | Role::Director)
    }

    /// Puede incorporar documentos nuevos a la bóveda (importación local).
    /// Docente solo consulta; Dirección supervisa y consulta.
    pub fn can_import(self) -> bool {
        self.can_rename_or_move() || self.can_edit_meta()
    }
}

/// Metadatos académicos asociados a un documento custodiado.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentMeta {
    /// Título del documento.
    pub title: String,
    /// Categoría de clasificación.
    pub category: Category,
    /// Autor o profesor responsable.
    pub author: String,
    /// Cédula / ID del autor (opcional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_number: Option<String>,
    /// Departamento o coordinación emisora.
    #[serde(default)]
    pub department: String,
    /// Fecha de registro (RFC 3339 UTC).
    pub registered_at: String,
    /// Año académico extraído o declarado.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub academic_year: Option<u16>,
    /// Nombre de archivo original.
    pub file_name: String,
    /// Extensión en minúsculas sin punto (pdf, jpg, png, docx…).
    pub extension: String,
}

/// Usuario del sistema con rol institucional.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    /// Nombre de usuario (único, minúsculas).
    pub username: String,
    /// Nombre completo para mostrar.
    pub display_name: String,
    /// Rol asignado (PoLP).
    pub role: Role,
    /// Argon2id del PIN/contraseña (misma función que el PIN de admin).
    pub pin_hash: String,
    /// Alta (RFC 3339).
    pub created_at: String,
    /// Último acceso correcto (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,
    /// Usuario habilitado.
    pub enabled: bool,
}

/// Registro completo de un documento dentro de la bóveda.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Document {
    /// Identificador único (ULID-like: timestamp + aleatorio).
    pub vault_id: String,
    /// SHA-256 en hex minúscula.
    pub sha256: String,
    /// BLAKE3 en hex minúscula.
    pub blake3: String,
    /// Tamaño en bytes.
    pub size_bytes: u64,
    /// Metadatos académicos.
    pub meta: DocumentMeta,
    /// Ruta relativa dentro de la bóveda (siempre forward-slash).
    pub rel_path: String,
    /// Sello de tiempo RFC 3161 (der CMS, base64) si fue obtenido.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161_token: Option<String>,
    /// Hora del sello (RFC 3339 UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161_time: Option<String>,
    /// Estado de integridad.
    pub integrity: IntegrityStatus,
    /// Device_id que originó el documento (si vino de un móvil).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_device: Option<String>,
}

/// Documento en papelera (soft-delete): conserva todo para restaurar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrashedDocument {
    pub document: Document,
    /// Quién lo envió a papelera.
    pub trashed_by: String,
    /// Cuándo (RFC 3339).
    pub trashed_at: String,
    /// Motivo declarado.
    pub reason: String,
}

/// Versión inmutable de un documento (creada por Coordinación al editar).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentVersion {
    pub vault_id: String,
    /// Número de versión (1..n) por documento.
    pub version: u32,
    /// Hash de esta versión del contenido.
    pub sha256: String,
    /// Ruta relativa dentro de la bóveda donde vive la copia inmutable.
    pub rel_path: String,
    /// Metadatos congelados al versionar.
    pub meta: DocumentMeta,
    /// Quién generó la versión.
    pub created_by: String,
    /// Cuándo (RFC 3339).
    pub created_at: String,
    /// Nota de la edición.
    pub note: String,
}

/// Estado de admisión de una entrega entrante.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionState {
    /// Esperando decisión del administrador en la cola de admisión.
    Pending,
    /// Admitido y sellado (inmutable).
    Admitted,
    /// Rechazado: devuelto al origen, nunca tocó la bóveda.
    Rejected,
}

/// Una entrega recibida por el canal de sincronización.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Submission {
    /// Identificador de la entrega.
    pub submission_id: String,
    /// Device_id del emisor.
    pub device_id: String,
    /// Metadatos declarados por el emisor.
    pub meta: DocumentMeta,
    /// SHA-256 calculado por el servidor sobre los bytes recibidos.
    pub sha256: String,
    /// BLAKE3 calculado por el servidor.
    pub blake3: String,
    /// Tamaño recibido.
    pub size_bytes: u64,
    /// Ruta al archivo en staging (relativa al staging root).
    pub staging_path: String,
    /// Hora de recepción RFC 3339.
    pub received_at: String,
    /// Estado de admisión.
    pub state: AdmissionState,
}

/// Envelope JSON del protocolo de transferencia (versión 1.0).
/// La cabecera viaja por el canal mTLS antes del stream binario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferHeader {
    /// Identificador del dispositivo emisor.
    pub device_id: String,
    /// Hora UTC en formato RFC 3339, p.ej. "2026-09-23T19:13:47Z".
    pub timestamp_utc: String,
    /// Versión del protocolo.
    pub protocol_version: String,
}

/// Payload declarativo del envelope (según especificación del proyecto).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferPayload {
    pub file_name: String,
    pub file_category: String,
    pub file_size_bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub department: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub id_number: Option<String>,
    #[serde(default)]
    pub academic_year: Option<u16>,
}

/// Envelope completo: header + payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferEnvelope {
    pub header: TransferHeader,
    pub payload: TransferPayload,
}

impl TransferEnvelope {
    pub const PROTOCOL_VERSION: &'static str = "1.0";
}

/// ACK sellado que la bóveda devuelve tras la ingesta/admisión.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealAck {
    pub status: SealStatus,
    pub vault_id: Option<String>,
    pub sha256: String,
    pub blake3: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealStatus {
    /// Sellado e inmutable.
    Sealed,
    /// En cola de admisión (la categoría exige aprobación humana).
    PendingAdmission,
    /// Rechazado por el administrador.
    Rejected,
    /// Error de validación (hash no coincide, categoría desconocida…).
    Error,
}

/// Genera un identificador único ordenable (48 hex chars): ms epoch + 80 bits aleatorios.
pub fn new_id() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut rnd = [0u8; 10];
    getrandom::getrandom(&mut rnd).expect("os randomness");
    let mut out = String::with_capacity(48);
    out.push_str(&format!("{:012x}", ms));
    out.push_str(&hex::encode(rnd));
    out
}

/// Hora actual RFC 3339 UTC (segundos).
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339(secs)
}

/// Formatea un epoch segundo como RFC 3339 UTC.
pub fn format_rfc3339(epoch_secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_epoch(epoch_secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convierte epoch seconds a fecha civil UTC (algoritmo de Howard Hinnant).
pub fn civil_from_epoch(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;
    (y, m, d, h, mi, s)
}

/// Validación mínima de un hash hex SHA-256.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_roundtrip() {
        for c in Category::ALL {
            let name = c.dir_name();
            assert_eq!(Category::from_dir_name(name), Some(c));
        }
    }

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2026-09-23T19:13:47Z del enunciado
        assert_eq!(format_rfc3339(1_790_190_827), "2026-09-23T19:13:47Z");
    }

    #[test]
    fn ids_are_unique_and_ordered() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32); // 12 hex (ms) + 20 hex (80 bits aleatorios)
    }

    #[test]
    fn envelope_serializes_per_spec() {
        let env = TransferEnvelope {
            header: TransferHeader {
                device_id: "AND_PROFE_0291".into(),
                timestamp_utc: "2026-09-23T19:13:47Z".into(),
                protocol_version: "1.0".into(),
            },
            payload: TransferPayload {
                file_name: "Tesis_Ingenieria_2026_Nicolas.pdf".into(),
                file_category: "Tesis".into(),
                file_size_bytes: 14_589_200,
                sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                department: "Coordinación de Ingeniería".into(),
                author: "Yoangel De Dios Nícolas Gómez Gómez".into(),
                title: "Tesis de Ingeniería".into(),
                id_number: None,
                academic_year: Some(2026),
            },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"device_id\":\"AND_PROFE_0291\""));
        assert!(json.contains("\"protocol_version\":\"1.0\""));
        let back: TransferEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }
}
