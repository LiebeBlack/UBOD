//! vault-index: motor de organización, clasificación y búsqueda.
//!
//! - Clasificador declarativo (TOML) por extensión y patrones de nombre.
//! - Extracción de texto de PDFs (lopdf) y OCR best-effort (tesseract si existe).
//! - Búsqueda compuesta estilo "categoria:Tesis AND departamento:\"Ingeniería\" AND año:2026".

use serde::{Deserialize, Serialize};
use std::path::Path;
use vault_core::{Category, Document, IntegrityStatus};
use vault_store::VaultDb;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de TOML: {0}")]
    Toml(String),
}

// ---------------------------------------------------------------------------
// Clasificador
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub category: String,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub filename_contains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl Ruleset {
    /// Reglas por defecto embebidas (orden significativo: primera coincidencia gana).
    pub fn default_ruleset() -> Ruleset {
        let toml_str = r#"
[[rule]]
category = "Tesis"
extensions = ["pdf", "docx", "doc", "odt"]
filename_contains = ["tesis", "thesis"]

[[rule]]
category = "Expediente_Profesor"
filename_contains = ["expediente", "curriculum", "cv_", "hoja_de_vida"]

[[rule]]
category = "Resolucion"
extensions = ["pdf"]
filename_contains = ["resolucion", "resolución", "acuerdo", "dictamen"]

[[rule]]
category = "Evaluacion"
filename_contains = ["evaluacion", "evaluación", "calificacion", "calificaciones", "rubrica", "rúbrica", "acta_de_examen"]

[[rule]]
category = "Fotografia_Documental"
extensions = ["jpg", "jpeg", "png", "heic", "webp"]
filename_contains = ["foto", "minuta", "pizarra"]

[[rule]]
category = "Material_Grafico"
extensions = ["svg", "pptx", "drawio", "pdf"]
filename_contains = ["diagrama", "presentacion", "presentación", "poster"]
"#;
        toml::from_str(toml_str).expect("reglas embebidas válidas")
    }

    pub fn load(path: &Path) -> Result<Ruleset, IndexError> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| IndexError::Toml(e.to_string()))
    }

    /// Clasifica un archivo por nombre/extensión. Los patrones de nombre son
    /// más específicos que las extensiones, así que se evalúan primero.
    pub fn classify(&self, file_name: &str) -> Option<Category> {
        let lower = file_name.to_lowercase();
        let ext = lower.rsplit('.').next().unwrap_or("").to_string();
        // 1ª pasada: patrones de nombre
        for r in &self.rule {
            if r.filename_contains
                .iter()
                .any(|p| lower.contains(&p.to_lowercase()))
            {
                if let Some(c) = Category::from_dir_name(&r.category) {
                    return Some(c);
                }
            }
        }
        // 2ª pasada: extensiones
        for r in &self.rule {
            if r.extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext)) {
                if let Some(c) = Category::from_dir_name(&r.category) {
                    return Some(c);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Extracción de texto
// ---------------------------------------------------------------------------

/// Extrae texto indexable de un archivo (primeras `max_pages` páginas de PDF).
/// Para imágenes intenta OCR con tesseract si está instalado (mejor esfuerzo).
pub fn extract_text(path: &Path, max_pages: usize) -> String {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" => extract_pdf_text(path, max_pages).unwrap_or_default(),
        "jpg" | "jpeg" | "png" | "webp" | "heic" => ocr_best_effort(path),
        "txt" | "md" | "csv" | "toml" | "json" => std::fs::read_to_string(path).unwrap_or_default(),
        _ => String::new(),
    }
}

fn extract_pdf_text(path: &Path, max_pages: usize) -> Option<String> {
    let doc = lopdf::Document::load(path).ok()?;
    let pages: Vec<u32> = doc.get_pages().keys().take(max_pages).copied().collect();
    if pages.is_empty() {
        return None;
    }
    doc.extract_text(&pages).ok()
}

fn ocr_best_effort(path: &Path) -> String {
    // OCR lite: delega en tesseract si existe; si no, texto vacío.
    let out_base = std::env::temp_dir().join(format!("vaultocr-{}", vault_core::new_id()));
    let status = std::process::Command::new("tesseract")
        .arg(path)
        .arg(&out_base)
        .arg("-l")
        .arg("spa+eng")
        .arg("--quiet")
        .output();
    match status {
        Ok(o) if o.status.success() => {
            std::fs::read_to_string(out_base.with_extension("txt")).unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// Indexa un documento: extrae texto y lo guarda en la BD.
pub fn index_document(db: &mut VaultDb, layout: &vault_fs::VaultLayout, doc: &Document) {
    let path = layout.abs_path(&doc.rel_path);
    let text = extract_text(&path, 10);
    db.set_text(&doc.vault_id, &text);
}

// ---------------------------------------------------------------------------
// Búsqueda compuesta
// ---------------------------------------------------------------------------

/// Consulta estructurada: términos separados por AND.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub terms: Vec<SearchTerm>,
}

#[derive(Debug, Clone)]
pub enum SearchTerm {
    Category(Category),
    Author(String),
    Department(String),
    Year(u16),
    Extension(String),
    Integrity(IntegrityStatus),
    /// Texto libre sobre título/autor/departamento/texto extraído.
    Text(String),
    FileName(String),
}

impl SearchQuery {
    /// Parsea consultas: `categoria:Tesis AND año:2026 AND departamento:"Ingeniería" AND integridad:ok`.
    pub fn parse(q: &str) -> SearchQuery {
        let mut terms = Vec::new();
        for raw in split_and(q) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let (key, value) = match raw.split_once(':') {
                Some((k, v)) => (k.trim().to_lowercase(), unquote(v.trim())),
                None => (String::new(), unquote(raw)),
            };
            let term = match key.as_str() {
                "categoria" | "category" | "categoría" => {
                    Category::from_dir_name(&value).map(SearchTerm::Category)
                }
                "autor" | "author" => Some(SearchTerm::Author(value.to_lowercase())),
                "departamento" | "department" => Some(SearchTerm::Department(value.to_lowercase())),
                "anio" | "año" | "year" => value.parse::<u16>().ok().map(SearchTerm::Year),
                "extension" | "ext" => Some(SearchTerm::Extension(value.to_lowercase())),
                "integridad" | "integrity" => match value.to_lowercase().as_str() {
                    "ok" | "verificada" | "verified" => {
                        Some(SearchTerm::Integrity(IntegrityStatus::Ok))
                    }
                    "tampered" | "manipulado" => {
                        Some(SearchTerm::Integrity(IntegrityStatus::Tampered))
                    }
                    "pending" | "pendiente" => {
                        Some(SearchTerm::Integrity(IntegrityStatus::Pending))
                    }
                    _ => None,
                },
                "titulo" | "título" | "title" => Some(SearchTerm::Text(value.to_lowercase())),
                "nombre" | "filename" | "archivo" => {
                    Some(SearchTerm::FileName(value.to_lowercase()))
                }
                "" | "texto" | "text" | "q" => Some(SearchTerm::Text(value.to_lowercase())),
                _ => None,
            };
            if let Some(t) = term {
                terms.push(t);
            }
        }
        SearchQuery { terms }
    }

    pub fn matches(&self, doc: &Document, text: Option<&str>) -> bool {
        self.terms.iter().all(|t| match t {
            SearchTerm::Category(c) => doc.meta.category == *c,
            SearchTerm::Author(a) => doc.meta.author.to_lowercase().contains(a),
            SearchTerm::Department(d) => doc.meta.department.to_lowercase().contains(d),
            SearchTerm::Year(y) => doc.meta.academic_year == Some(*y),
            SearchTerm::Extension(e) => doc.meta.extension.eq_ignore_ascii_case(e),
            SearchTerm::Integrity(s) => doc.integrity == *s,
            SearchTerm::FileName(f) => doc.meta.file_name.to_lowercase().contains(f),
            SearchTerm::Text(q) => {
                doc.meta.title.to_lowercase().contains(q)
                    || doc.meta.author.to_lowercase().contains(q)
                    || doc.meta.department.to_lowercase().contains(q)
                    || doc.meta.file_name.to_lowercase().contains(q)
                    || text.map(|t| t.to_lowercase().contains(q)).unwrap_or(false)
            }
        })
    }
}

/// Ejecuta una búsqueda sobre la base de datos.
pub fn search(db: &VaultDb, query: &SearchQuery) -> Vec<Document> {
    db.documents()
        .iter()
        .filter(|d| query.matches(d, db.get_text(&d.vault_id)))
        .cloned()
        .collect()
}

fn split_and(q: &str) -> Vec<String> {
    // 1) segmentar por espacios respetando comillas
    let mut segments: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in q.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    segments.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        segments.push(cur);
    }

    // 2) los conectores "AND"/"Y" aislados inician una nueva parte
    let mut parts: Vec<String> = Vec::new();
    let mut acc = String::new();
    for seg in segments {
        let l = seg.to_lowercase();
        if l == "and" || l == "y" {
            if !acc.trim().is_empty() {
                parts.push(acc.trim().to_string());
            }
            acc.clear();
        } else {
            if !acc.is_empty() {
                acc.push(' ');
            }
            acc.push_str(&seg);
        }
    }
    if !acc.trim().is_empty() {
        parts.push(acc.trim().to_string());
    }
    parts
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::DocumentMeta;

    #[test]
    fn classify_by_rules() {
        let rs = Ruleset::default_ruleset();
        assert_eq!(
            rs.classify("Tesis_Ingenieria_2026_Nicolas.pdf"),
            Some(Category::Tesis)
        );
        assert_eq!(
            rs.classify("foto_pizarra_clase.jpg"),
            Some(Category::FotografiaDocumental)
        );
        assert_eq!(
            rs.classify("expediente_ana.pdf"),
            Some(Category::ExpedienteProfesor)
        );
        assert_eq!(
            rs.classify("Resolucion_101_2026.pdf"),
            Some(Category::Resolucion)
        );
        assert_eq!(
            rs.classify("calificaciones_finales.xlsx"),
            Some(Category::Evaluacion)
        );
    }

    #[test]
    fn query_parse_and_match() {
        let doc = Document {
            vault_id: "v1".into(),
            sha256: "h".into(),
            blake3: "b".into(),
            size_bytes: 1,
            meta: DocumentMeta {
                title: "Análisis estructural".into(),
                category: Category::Tesis,
                author: "Yoangel De Dios Nícolas Gómez Gómez".into(),
                id_number: None,
                department: "Coordinación de Ingeniería".into(),
                registered_at: String::new(),
                academic_year: Some(2026),
                file_name: "Tesis_Ingenieria_2026_Nicolas.pdf".into(),
                extension: "pdf".into(),
            },
            rel_path: "p/Tesis/f.pdf".into(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: IntegrityStatus::Ok,
            origin_device: None,
        };
        let q = SearchQuery::parse(
            "categoria:Tesis AND departamento:\"Ingeniería\" AND año:2026 AND extension:pdf AND integridad:ok",
        );
        assert_eq!(q.terms.len(), 5);
        assert!(q.matches(&doc, None));

        let q2 = SearchQuery::parse("categoria:Evaluacion");
        assert!(!q2.matches(&doc, None));

        let q3 = SearchQuery::parse("texto:\"análisis estructural\" AND año:2026");
        assert!(q3.matches(&doc, None));
    }

    /// Las reglas se pueden ajustar en un TOML externo (config/rules.toml) sin
    /// recompilar; si no existe, quien llama usa las embebidas.
    #[test]
    fn external_ruleset_overrides_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rules.toml");
        std::fs::write(
            &p,
            r#"
[[rule]]
category = "Tesis"
filename_contains = ["proyecto_final"]
"#,
        )
        .unwrap();
        let rs = Ruleset::load(&p).unwrap();
        assert_eq!(
            rs.classify("Proyecto_Final_2026.pdf"),
            Some(Category::Tesis)
        );
        // las reglas embebidas ya no aplican: no hay comodín por extensión
        assert_eq!(rs.classify("foto_pizarra.jpg"), None);
        // y un archivo ausente es un error controlado (no un pánico)
        assert!(Ruleset::load(&dir.path().join("no-existe.toml")).is_err());
    }

    /// El índice de texto conecta la extracción con la búsqueda: un PDF
    /// custodiado se encuentra por su contenido, no solo por sus metadatos.
    #[test]
    fn index_document_makes_content_searchable() {
        use vault_core::{Category, Document};
        let dir = tempfile::tempdir().unwrap();
        let kf = [7u8; 64];
        let layout = vault_fs::VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        let mut db = VaultDb::open(&dir.path().join("db"), &kf).unwrap();

        let mut doc = Document {
            vault_id: vault_core::new_id(),
            sha256: "aa".repeat(32),
            blake3: "bb".repeat(32),
            size_bytes: 0,
            meta: DocumentMeta {
                title: "acta".into(),
                category: Category::Tesis,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: "acta.pdf".into(),
                extension: "pdf".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: IntegrityStatus::Ok,
            origin_device: None,
        };
        doc.rel_path = layout.rel_path_for(&doc.meta.author, &doc);
        layout
            .install_sealed(&doc.rel_path, &minimal_pdf(b"penicilina resistente 2026"))
            .unwrap();
        db.add_document(doc.clone());

        // sin indexar, el contenido no se encuentra
        let q = SearchQuery::parse("texto:penicilina");
        assert!(search(&db, &q).is_empty());

        // al indexar, se extrae el texto del PDF y la búsqueda lo encuentra
        index_document(&mut db, &layout, &doc);
        assert!(db
            .get_text(&doc.vault_id)
            .unwrap_or_default()
            .to_lowercase()
            .contains("penicilina"));
        let found = search(&db, &q);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].vault_id, doc.vault_id);
    }

    #[test]
    fn pdf_text_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let pdf_path = dir.path().join("test.pdf");
        std::fs::write(
            &pdf_path,
            minimal_pdf(b"Tesis de Ingenieria Industrial 2026"),
        )
        .unwrap();
        let text = extract_pdf_text(&pdf_path, 5).expect("extraer texto");
        assert!(
            text.to_lowercase().contains("tesis de ingenieria"),
            "texto: {text}"
        );
    }

    /// Construye un PDF mínimo válido (1 página, 1 línea de texto) con xref correcto.
    fn minimal_pdf(text: &[u8]) -> Vec<u8> {
        let content = format!(
            "BT /F1 12 Tf 72 720 Td ({}) Tj ET",
            String::from_utf8_lossy(text).replace(['(', ')', '\\'], "")
        );
        let stream = format!(
            "<< /Length {} >>\nstream\n{}\nendstream",
            content.len(),
            content
        );
        let objs: Vec<String> = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".into(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".into(),
            stream,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        ];

        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objs.iter().enumerate() {
            offsets.push(out.len() as u32);
            out.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", i + 1, body).as_bytes());
        }
        let xref_pos = out.len() as u32;
        out.extend_from_slice(format!("xref\n0 {}\n", objs.len() + 1).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
                objs.len() + 1,
                xref_pos
            )
            .as_bytes(),
        );
        out
    }
}
