//! vault-audit: auditoría continua de integridad (anti bit-rot).
//!
//! Rehashea cada documento custodiado y lo compara contra el índice; cualquier
//! divergencia se marca como TAMPERED y se registra en la cadena de auditoría.

use vault_core::{Document, IntegrityStatus};
use vault_fs::VaultLayout;
use vault_store::VaultDb;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("error de almacenamiento: {0}")]
    Store(#[from] vault_store::StoreError),
}

/// Resultado de un barrido de integridad.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SweepReport {
    pub checked: usize,
    pub missing: usize,
    pub tampered: usize,
    pub ok: usize,
    pub repaired_status: usize,
    /// vault_id de documentos con problemas.
    pub problems: Vec<String>,
    pub finished_at: String,
}

/// Ejecuta un barrido completo de integridad sobre la bóveda.
pub fn sweep(db: &mut VaultDb, layout: &VaultLayout) -> Result<SweepReport, AuditError> {
    let docs: Vec<Document> = db.documents().to_vec();
    let mut report = SweepReport::default();

    for doc in &docs {
        report.checked += 1;
        let path = layout.abs_path(&doc.rel_path);
        if !path.exists() {
            // desaparecido: posible borrado externo
            db.update_integrity(&doc.vault_id, IntegrityStatus::Tampered);
            db.append_audit(
                "vault-audit",
                "integrity_missing",
                &doc.sha256,
                &format!("vault_id={} ruta={}", doc.vault_id, doc.rel_path),
            );
            report.missing += 1;
            report.problems.push(doc.vault_id.clone());
            continue;
        }
        let hp = vault_crypto::HashPair::from_file(&path)?;
        if hp.sha256 == doc.sha256 && hp.blake3 == doc.blake3 {
            if doc.integrity != IntegrityStatus::Ok {
                db.update_integrity(&doc.vault_id, IntegrityStatus::Ok);
                report.repaired_status += 1;
            }
            report.ok += 1;
        } else {
            // CORRUPCIÓN SILENCIOSA o manipulación: bit rot detectado
            db.update_integrity(&doc.vault_id, IntegrityStatus::Tampered);
            db.append_audit(
                "vault-audit",
                "integrity_tampered",
                &doc.sha256,
                &format!(
                    "vault_id={} esperado={} encontrado={} (bit rot o manipulación)",
                    doc.vault_id, doc.sha256, hp.sha256
                ),
            );
            report.tampered += 1;
            report.problems.push(doc.vault_id.clone());
        }
    }

    report.finished_at = vault_core::now_rfc3339();
    db.append_audit(
        "vault-audit",
        "sweep",
        "vault",
        &format!(
            "verificados={} ok={} perdidos={} manipulados={}",
            report.checked, report.ok, report.missing, report.tampered
        ),
    );
    db.flush()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Category, DocumentMeta};
    use vault_crypto::dbcrypto::generate_keyfile;
    use vault_crypto::LocalTsa;

    fn make_doc(file_name: &str, rel: &str) -> Document {
        Document {
            vault_id: vault_core::new_id(),
            sha256: String::new(),
            blake3: String::new(),
            size_bytes: 0,
            meta: DocumentMeta {
                title: "t".into(),
                category: Category::Tesis,
                author: "Profesor".into(),
                id_number: None,
                department: "d".into(),
                registered_at: String::new(),
                academic_year: None,
                file_name: file_name.into(),
                extension: "pdf".into(),
            },
            rel_path: rel.into(),
            rfc3161_token: None,
            rfc3161_time: None,
            integrity: IntegrityStatus::Ok,
            origin_device: None,
        }
    }

    #[test]
    fn detects_silent_corruption_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let kf = generate_keyfile();
        let mut db = VaultDb::open(&dir.path().join("db"), &kf).unwrap();
        let layout = VaultLayout::new(dir.path().join("vault"));
        layout.init(&["Profesor".to_string()]).unwrap();

        // documento 1: sano
        let content1 = b"contenido integro de la tesis";
        let hp1 = vault_crypto::HashPair::from_bytes(content1);
        let mut d1 = make_doc("tesis1.pdf", "Profesor/Tesis/tesis1.pdf");
        d1.sha256 = hp1.sha256.clone();
        d1.blake3 = hp1.blake3.clone();
        d1.size_bytes = content1.len() as u64;
        std::fs::write(layout.abs_path(&d1.rel_path), content1).unwrap();

        // documento 2: será corrupto
        let content2 = b"contenido de la tesis dos";
        let hp2 = vault_crypto::HashPair::from_bytes(content2);
        let mut d2 = make_doc("tesis2.pdf", "Profesor/Tesis/tesis2.pdf");
        d2.sha256 = hp2.sha256.clone();
        d2.blake3 = hp2.blake3.clone();
        d2.size_bytes = content2.len() as u64;
        let p2 = layout.abs_path(&d2.rel_path);
        std::fs::write(&p2, content2).unwrap();

        // documento 3: será borrado externamente
        let content3 = b"contenido de la tesis tres";
        let hp3 = vault_crypto::HashPair::from_bytes(content3);
        let mut d3 = make_doc("tesis3.pdf", "Profesor/Tesis/tesis3.pdf");
        d3.sha256 = hp3.sha256.clone();
        d3.blake3 = hp3.blake3.clone();
        d3.size_bytes = content3.len() as u64;
        let p3 = layout.abs_path(&d3.rel_path);
        std::fs::write(&p3, content3).unwrap();

        for d in [&d1, &d2, &d3] {
            db.add_document(d.clone());
        }

        // SIMULAR BIT ROT: corromper un byte de tesis2 (quitar solo lectura de test)
        let mut data = std::fs::read(&p2).unwrap();
        data[5] ^= 0xFF;
        std::fs::write(&p2, &data).unwrap();
        // SIMULAR BORRADO EXTERNO
        std::fs::remove_file(&p3).unwrap();

        let report = sweep(&mut db, &layout).unwrap();
        assert_eq!(report.checked, 3);
        assert_eq!(report.ok, 1);
        assert_eq!(report.tampered, 1, "debe detectar corrupción silenciosa");
        assert_eq!(report.missing, 1, "debe detectar borrado externo");
        assert_eq!(report.problems.len(), 2);

        // los estados quedaron actualizados en la BD
        assert_eq!(
            db.find_by_vault_id(&d2.vault_id).unwrap().integrity,
            IntegrityStatus::Tampered
        );
        assert_eq!(
            db.find_by_vault_id(&d3.vault_id).unwrap().integrity,
            IntegrityStatus::Tampered
        );
        assert_eq!(
            db.find_by_vault_id(&d1.vault_id).unwrap().integrity,
            IntegrityStatus::Ok
        );

        // la auditoría registra todo y sigue encadenada
        assert!(db.verify_audit_chain().is_ok());

        // REPARACIÓN: si el archivo vuelve a coincidir con su hash, el barrido
        // devuelve el documento a estado íntegro (y lo cuenta aparte).
        std::fs::write(&p2, content2).unwrap();
        let repaired = sweep(&mut db, &layout).unwrap();
        assert_eq!(repaired.repaired_status, 1, "debe reparar el estado previo");
        assert_eq!(repaired.tampered, 0);
        assert_eq!(
            repaired.missing, 1,
            "el borrado externo sigue siendo un problema"
        );
        assert_eq!(
            db.find_by_vault_id(&d2.vault_id).unwrap().integrity,
            IntegrityStatus::Ok
        );
        assert!(db.verify_audit_chain().is_ok());
        let _ = LocalTsa::new(); // smoke: TSA disponible para sellos de barrido futuros
    }
}
