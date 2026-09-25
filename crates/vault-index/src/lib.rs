//! vault-index: motor de organización, clasificación y búsqueda.
//!
//! - Clasificador declarativo (TOML) por extensión y patrones de nombre.
//! - Extracción de texto de PDFs (lopdf) y OCR best-effort (tesseract si existe).
//! - Búsqueda compuesta estilo "categoria:Tesis AND departamento:\"Ingeniería\" AND año:2026".

use serde::{Deserialize, Serialize};
use std::io::Read;
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

/// Tope de texto indexable por documento (1 MiB).
///
/// Acota el crecimiento de la base cifrada ante contenedores enormes sin
/// perder capacidad de búsqueda: lo que se indexa es el contenido, no el
/// archivo completo.
pub const MAX_INDEXED_TEXT: usize = 1024 * 1024;

/// Extrae texto indexable de un archivo, **desde Word hasta PDF**:
///
/// - `pdf` (lopdf, primeras `max_pages` páginas)
/// - `docx` / `xlsx` / `pptx` (contenedor ZIP + XML de Office moderno)
/// - `odt` / `ods` / `odp` (OpenDocument)
/// - `rtf` y `.doc` / `.xls` / `.ppt` (binario antiguo, mejor esfuerzo)
/// - texto plano y marcado (`txt`, `md`, `csv`, `json`, `xml`, `log`…)
/// - imágenes: OCR con `tesseract` si está instalado (mejor esfuerzo)
///
/// Nunca falla: un archivo ilegible o de un formato desconocido devuelve texto
/// vacío, y el resultado se acota a [`MAX_INDEXED_TEXT`].
pub fn extract_text(path: &Path, max_pages: usize) -> String {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let text = match ext.as_str() {
        // PDF: extracción por páginas (lopdf)
        "pdf" => extract_pdf_text(path, max_pages).unwrap_or_default(),
        // Imágenes: OCR best-effort con tesseract si existe
        "jpg" | "jpeg" | "png" | "webp" | "heic" => ocr_best_effort(path),
        // Texto plano y marcado: legible directamente
        "txt" | "md" | "csv" | "tsv" | "toml" | "json" | "xml" | "yml" | "yaml" | "log" => {
            std::fs::read_to_string(path).unwrap_or_default()
        }
        // Office moderno: contenedor ZIP con el texto en partes XML conocidas
        "docx" => extract_office_text(path, OfficeKind::Docx),
        "xlsx" => extract_office_text(path, OfficeKind::Xlsx),
        "pptx" => extract_office_text(path, OfficeKind::Pptx),
        // OpenDocument (.odt/.ods/.odp): mismo contenedor, `content.xml`
        "odt" | "ods" | "odp" => extract_office_text(path, OfficeKind::Odf),
        // RTF: texto entre palabras de control
        "rtf" => rtf_to_text(path),
        // Office binario antiguo (OLE): utilidades clásicas si están instaladas
        "doc" | "xls" | "ppt" => legacy_office_text(path),
        _ => String::new(),
    };
    truncate_on_char_boundary(text, MAX_INDEXED_TEXT)
}

/// Contenedores OOXML/ODF: qué partes llevan el texto legible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfficeKind {
    /// Word: documento principal, encabezados, pies y notas.
    Docx,
    /// Excel: tabla de cadenas compartidas y hojas.
    Xlsx,
    /// PowerPoint: diapositivas y notas del orador.
    Pptx,
    /// OpenDocument: `content.xml`.
    Odf,
}

impl OfficeKind {
    /// ¿Esta parte del contenedor contiene texto indexable?
    fn matches(self, name: &str) -> bool {
        match self {
            OfficeKind::Docx => {
                matches!(
                    name,
                    "word/document.xml" | "word/footnotes.xml" | "word/endnotes.xml"
                ) || (name.ends_with(".xml")
                    && (name.starts_with("word/header") || name.starts_with("word/footer")))
            }
            OfficeKind::Xlsx => {
                name == "xl/sharedStrings.xml"
                    || (name.starts_with("xl/worksheets/sheet") && name.ends_with(".xml"))
            }
            OfficeKind::Pptx => {
                name.ends_with(".xml")
                    && (name.starts_with("ppt/slides/slide")
                        || name.starts_with("ppt/notesSlides/notesSlide"))
            }
            OfficeKind::Odf => name == "content.xml",
        }
    }
}

/// Extrae y concatena el texto de las partes XML que pide `kind`.
///
/// Un contenedor corrupto, protegido con contraseña o sin las partes esperadas
/// devuelve texto vacío (nunca un pánico).
fn extract_office_text(path: &Path, kind: OfficeKind) -> String {
    let Ok(file) = std::fs::File::open(path) else {
        tracing::debug!(path = %path.display(), "no se pudo abrir el contenedor Office");
        return String::new();
    };
    let Ok(mut zip) = zip::ZipArchive::new(file) else {
        tracing::debug!(
            path = %path.display(),
            "contenedor Office ilegible (¿corrupto o cifrado?); se indexa sin texto"
        );
        return String::new();
    };
    let mut names: Vec<String> = zip
        .file_names()
        .filter(|n| kind.matches(n))
        .map(|n| n.to_string())
        .collect();
    if names.is_empty() {
        tracing::debug!(path = %path.display(), "contenedor sin las partes XML esperadas");
        return String::new();
    }
    // Orden natural: `sheet2` antes que `sheet10` (y el documento principal primero).
    names.sort_by_cached_key(|n| natural_key(n));

    let mut out = String::new();
    for name in names {
        if out.len() >= MAX_INDEXED_TEXT {
            break;
        }
        let Ok(mut entry) = zip.by_name(&name) else {
            continue;
        };
        let mut xml = String::new();
        if entry.read_to_string(&mut xml).is_err() {
            continue;
        }
        push_limited(&mut out, &xml_to_text(&xml));
    }
    out
}

/// Convierte XML de Office/OpenDocument en texto plano: quita las etiquetas,
/// decodifica las entidades básicas y normaliza los espacios.
fn xml_to_text(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len() / 4);
    let mut in_tag = false;
    let mut chars = xml.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' '); // frontera entre dos nodos de texto
            }
            '&' if !in_tag => {
                let mut ent = String::new();
                while let Some(&n) = chars.peek() {
                    if n == ';' || ent.len() > 8 {
                        break;
                    }
                    ent.push(n);
                    chars.next();
                }
                if chars.peek() == Some(&';') {
                    chars.next();
                }
                out.push_str(match ent.as_str() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => " ",
                });
            }
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    collapse_ws(&out)
}

/// Rich Text Format: descarta grupos y palabras de control conservando el texto
/// legible — suficiente para que la búsqueda por contenido lo encuentre.
fn rtf_to_text(path: &Path) -> String {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' | '}' => {}
            '\\' => match chars.peek().copied() {
                // Carácter escapado: \\ \{ \}
                Some(next @ ('\\' | '{' | '}')) => {
                    out.push(next);
                    chars.next();
                }
                // Carácter en hexadecimal: \'e9
                Some('\'') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        out.push(byte as char);
                    }
                }
                // Palabra de control: se descarta junto con su parámetro
                _ => {
                    let mut word = String::new();
                    while let Some(&n) = chars.peek() {
                        if n.is_ascii_alphabetic() {
                            word.push(n);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    while let Some(&n) = chars.peek() {
                        if n.is_ascii_digit() || n == '-' {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if chars.peek() == Some(&' ') {
                        chars.next();
                    }
                    if matches!(word.as_str(), "par" | "line" | "tab" | "sect" | "page") {
                        out.push(' ');
                    }
                }
            },
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    collapse_ws(&out)
}

/// Office binario antiguo (`.doc`/`.xls`/`.ppt`, formato OLE compuesto).
///
/// No existe un lector puro-Rust razonable, así que se delega en las utilidades
/// clásicas si están instaladas (mismo criterio best-effort que el OCR).
fn legacy_office_text(path: &Path) -> String {
    const CANDIDATES: [(&str, &[&str]); 2] = [("antiword", &["-m", "UTF-8.txt"]), ("catdoc", &[])];
    for (bin, args) in CANDIDATES {
        let Ok(out) = std::process::Command::new(bin)
            .args(args)
            .arg(path)
            .output()
        else {
            continue; // utilidad no instalada
        };
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if !text.trim().is_empty() {
            return text;
        }
    }
    tracing::debug!(
        path = %path.display(),
        "Office binario sin extractor: instale antiword o catdoc para indexarlo"
    );
    String::new()
}

/// Clave de orden natural: separa el prefijo textual, el primer número y el
/// sufijo, de modo que `sheet2.xml` ordene antes que `sheet10.xml`.
fn natural_key(name: &str) -> (String, u32, String) {
    let stem = name.trim_end_matches(".xml");
    match stem.find(|c: char| c.is_ascii_digit()) {
        None => (stem.to_string(), 0, String::new()),
        Some(i) => {
            let rest = &stem[i..];
            let ndigits = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            (
                stem[..i].to_string(),
                rest[..ndigits].parse::<u32>().unwrap_or(0),
                rest[ndigits..].to_string(),
            )
        }
    }
}

/// Añade `src` a `dst` sin pasar de [`MAX_INDEXED_TEXT`], respetando las
/// fronteras de carácter UTF-8.
fn push_limited(dst: &mut String, src: &str) {
    if src.is_empty() || dst.len() >= MAX_INDEXED_TEXT {
        return;
    }
    if !dst.is_empty() {
        dst.push(' ');
    }
    let room = MAX_INDEXED_TEXT.saturating_sub(dst.len());
    let mut end = src.len().min(room);
    while end > 0 && !src.is_char_boundary(end) {
        end -= 1;
    }
    dst.push_str(&src[..end]);
}

/// Recorta `s` a `max` bytes sin partir un carácter UTF-8.
fn truncate_on_char_boundary(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_string()
}

/// Colapsa toda racha de espacios en blanco en un único espacio.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
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

    // ---------------- Indexado de Office (Word/Excel/PowerPoint/ODF) ----------------

    /// Construye un contenedor ZIP con las partes indicadas, como los que
    /// producen Word, Excel, PowerPoint y LibreOffice.
    fn office_zip(parts: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in parts {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(body.as_bytes()).unwrap();
            }
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn xml_becomes_plain_text() {
        assert_eq!(
            xml_to_text("<w:t>Acta &amp; anexo &quot;A&quot;</w:t><w:t>2026</w:t>"),
            "Acta & anexo \"A\" 2026"
        );
        assert_eq!(xml_to_text("<a>uno</a><b>dos</b>"), "uno dos");
        assert_eq!(xml_to_text("<a><b/></a>"), "");
    }

    #[test]
    fn natural_order_is_numeric_not_lexicographic() {
        let mut names = vec![
            "ppt/slides/slide10.xml".to_string(),
            "ppt/slides/slide2.xml".to_string(),
            "ppt/slides/slide1.xml".to_string(),
        ];
        names.sort_by_cached_key(|n| natural_key(n));
        assert_eq!(
            names,
            vec![
                "ppt/slides/slide1.xml",
                "ppt/slides/slide2.xml",
                "ppt/slides/slide10.xml"
            ]
        );
    }

    /// Word: el contenido del `.docx` se extrae (documento + encabezado) y la
    /// búsqueda por contenido lo encuentra.
    #[test]
    fn docx_content_is_indexed_and_searchable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tesis.docx");
        std::fs::write(
            &path,
            office_zip(&[
                ("[Content_Types].xml", "<Types/>"),
                (
                    "word/document.xml",
                    "<?xml version=\"1.0\"?><w:document><w:body>\
                     <w:p><w:r><w:t>Estudio sobre la penicilina</w:t></w:r></w:p>\
                     <w:p><w:r><w:t>resistente de 2026</w:t></w:r></w:p>\
                     </w:body></w:document>",
                ),
                (
                    "word/header1.xml",
                    "<w:hdr><w:t>Universidad Nacional</w:t></w:hdr>",
                ),
                ("word/media/imagen.png", "binario-irrelevante"),
            ]),
        )
        .unwrap();

        let text = extract_text(&path, 10);
        assert!(text.contains("penicilina"), "texto extraído: {text}");
        assert!(text.contains("2026"), "texto extraído: {text}");
        assert!(
            text.contains("Universidad Nacional"),
            "el encabezado también se indexa: {text}"
        );
        assert!(
            !text.contains("binario-irrelevante"),
            "los recursos binarios no se indexan: {text}"
        );
    }

    /// Excel, PowerPoint y OpenDocument: también se extrae su texto.
    #[test]
    fn xlsx_pptx_and_odt_content_is_indexed() {
        let dir = tempfile::tempdir().unwrap();

        let xlsx = dir.path().join("notas.xlsx");
        std::fs::write(
            &xlsx,
            office_zip(&[
                (
                    "xl/sharedStrings.xml",
                    "<sst><si><t>calificaciones finales</t></si></sst>",
                ),
                (
                    "xl/worksheets/sheet1.xml",
                    "<worksheet><sheetData><row><c><v>penicilina</v></c></row></sheetData></worksheet>",
                ),
            ]),
        )
        .unwrap();
        let t = extract_text(&xlsx, 10);
        assert!(t.contains("calificaciones finales"), "xlsx: {t}");
        assert!(t.contains("penicilina"), "xlsx: {t}");

        let pptx = dir.path().join("clase.pptx");
        std::fs::write(
            &pptx,
            office_zip(&[
                (
                    "ppt/slides/slide1.xml",
                    "<p:sld><a:t>Introducción al laboratorio</a:t></p:sld>",
                ),
                (
                    "ppt/slides/slide10.xml",
                    "<p:sld><a:t>Conclusiones del curso</a:t></p:sld>",
                ),
            ]),
        )
        .unwrap();
        let t = extract_text(&pptx, 10);
        assert!(t.contains("Introducción al laboratorio"), "pptx: {t}");
        assert!(t.contains("Conclusiones del curso"), "pptx: {t}");

        let odt = dir.path().join("acta.odt");
        std::fs::write(
            &odt,
            office_zip(&[(
                "content.xml",
                "<office:document-content><text:p>Acta de reunión</text:p>\
                 <text:p>tema: penicilina</text:p></office:document-content>",
            )]),
        )
        .unwrap();
        let t = extract_text(&odt, 10);
        assert!(t.contains("Acta de reunión"), "odt: {t}");
        assert!(t.contains("penicilina"), "odt: {t}");
    }

    /// RTF: se conserva el texto legible y se descartan los grupos de control.
    #[test]
    fn rtf_control_words_are_stripped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nota.rtf");
        std::fs::write(
            &path,
            r"{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}\fs24 Estudio sobre la penicilina\par resistente\'20de 2026}",
        )
        .unwrap();
        let text = extract_text(&path, 10);
        assert!(text.contains("penicilina"), "rtf: {text}");
        assert!(text.contains("resistente"), "rtf: {text}");
        assert!(!text.contains("fonttbl"), "sin palabras de control: {text}");
        assert!(!text.contains("rtf1"), "sin palabras de control: {text}");
    }

    /// Un contenedor corrupto, vacío o sin las partes esperadas devuelve texto
    /// vacío sin pánicos (el documento sigue entrando en la bóveda).
    #[test]
    fn malformed_office_files_never_panic() {
        let dir = tempfile::tempdir().unwrap();

        let basura = dir.path().join("corrupto.docx");
        std::fs::write(&basura, b"esto no es un zip").unwrap();
        assert_eq!(extract_text(&basura, 10), "");

        let vacio = dir.path().join("vacio.docx");
        std::fs::write(&vacio, office_zip(&[("docProps/app.xml", "<Properties/>")])).unwrap();
        assert_eq!(
            extract_text(&vacio, 10),
            "",
            "sin word/document.xml no hay texto"
        );

        let inexistente = dir.path().join("no-existe.xlsx");
        assert_eq!(extract_text(&inexistente, 10), "");

        let rtf_roto = dir.path().join("roto.rtf");
        std::fs::write(&rtf_roto, b"{\\rtf1 \\u9999 inacabado").unwrap();
        let _ = extract_text(&rtf_roto, 10); // no debe entrar en pánico
    }

    /// Lazo completo: un `.docx` sellado en la bóveda se encuentra por su
    /// contenido con `texto:` — el mismo camino que un PDF.
    #[test]
    fn sealed_docx_is_found_by_content_search() {
        let dir = tempfile::tempdir().unwrap();
        let kf = [9u8; 64];
        let layout = vault_fs::VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor Uno".to_string()]).unwrap();
        let mut db = VaultDb::open(&dir.path().join("db"), &kf).unwrap();

        let mut doc = Document {
            vault_id: vault_core::new_id(),
            sha256: "cc".repeat(32),
            blake3: "dd".repeat(32),
            size_bytes: 0,
            meta: DocumentMeta {
                title: "informe".into(),
                category: Category::ExpedienteProfesor,
                author: "Profesor Uno".into(),
                id_number: None,
                department: "Ingeniería".into(),
                registered_at: vault_core::now_rfc3339(),
                academic_year: Some(2026),
                file_name: "informe.docx".into(),
                extension: "docx".into(),
            },
            rel_path: String::new(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: IntegrityStatus::Ok,
            origin_device: None,
        };
        doc.rel_path = layout.rel_path_for(&doc.meta.author, &doc);
        let content = office_zip(&[(
            "word/document.xml",
            "<w:document><w:body><w:t>informe sobre la penicilina de 2026</w:t></w:body></w:document>",
        )]);
        layout.install_sealed(&doc.rel_path, &content).unwrap();
        db.add_document(doc.clone());

        // sin indexar no se encuentra; tras indexar, sí
        assert!(search(&db, &SearchQuery::parse("texto:penicilina")).is_empty());
        index_document(&mut db, &layout, &doc);
        let found = search(&db, &SearchQuery::parse("texto:penicilina"));
        assert_eq!(found.len(), 1, "el .docx debe encontrarse por su contenido");
        assert_eq!(found[0].vault_id, doc.vault_id);
        // y la búsqueda compuesta por metadatos + contenido también
        let compuesta = search(
            &db,
            &SearchQuery::parse("extension:docx AND texto:penicilina AND año:2026"),
        );
        assert_eq!(compuesta.len(), 1);
    }
}
