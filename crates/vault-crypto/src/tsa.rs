//! Sellador RFC 3161: TSA local integrada (firmada con eSSC puro-Rust)
//! y cliente para TSAs externas.
//!
//! La TSA local emite TimeStampToken v1 (no requiresAuth): SEQUENCE { version(1),
//! policy, messageImprint, serialNumber, genTime, [tsa] }. El token se firma con
//! eSSC (ESSCertIDv2, RFC 5035) — un sello minimalista y verificable sin ASN.1 complejo.

use crate::derutil::*;
use crate::pki::Identity;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::Digest;
use std::path::Path;
use x509_cert::Certificate;

#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("respuesta TSA inválida: {0}")]
    BadResponse(String),
    #[error("fallo de red al contactar la TSA: {0}")]
    Network(String),
    #[error("error criptográfico: {0}")]
    Crypto(String),
}

/// MessageImprint RFC 3161: SEQUENCE { hashAlgorithm OID, hashedMessage OCTET STRING }.
#[derive(Debug, Clone)]
pub struct MessageImprint {
    pub hash_oid: String,
    pub hashed_message: Vec<u8>,
}

impl MessageImprint {
    pub fn sha256(msg: &[u8]) -> Self {
        MessageImprint {
            hash_oid: OID_SHA256.to_string(),
            hashed_message: sha2::Sha256::digest(msg).to_vec(),
        }
    }

    pub fn to_der(&self) -> Vec<u8> {
        let alg = der_sequence(&[der_oid(&self.hash_oid).as_slice(), der_null().as_slice()]);
        der_sequence(&[
            alg.as_slice(),
            der_octet_string(&self.hashed_message).as_slice(),
        ])
    }
}

/// TimeStampToken v1 mínimo, codificado en DER.
#[derive(Debug, Clone)]
pub struct TimestampToken {
    pub der: Vec<u8>,
}

impl TimestampToken {
    /// Extrae genTime (como epoch unix) y el messageImprint del token.
    pub fn parse(&self) -> Result<(i64, MessageImprint), TsaError> {
        // TimeStampToken ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        let mut cur = Cursor::new(&self.der);
        let outer = cur
            .expect_seq()
            .ok_or_else(|| TsaError::BadResponse("token: no SEQ".into()))?;
        let mut body = Cursor::new(outer);
        body.expect_oid(outer)
            .ok_or_else(|| TsaError::BadResponse("token: no OID".into()))?;
        let inner = body
            .expect_explicit0(outer)
            .ok_or_else(|| TsaError::BadResponse("token: no [0]".into()))?;
        // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo, ... }
        let mut sd = Cursor::new(inner);
        let sd_body = sd
            .expect_seq()
            .ok_or_else(|| TsaError::BadResponse("sd: no SEQ".into()))?;
        let mut p = Cursor::new(sd_body);
        p.skip_tlv()
            .ok_or_else(|| TsaError::BadResponse("sd: no version".into()))?; // version INTEGER
        p.skip_tlv()
            .ok_or_else(|| TsaError::BadResponse("sd: no digestAlgs".into()))?; // SET
        let eci = p
            .expect_seq()
            .ok_or_else(|| TsaError::BadResponse("sd: no encapContentInfo".into()))?;
        // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, [0] EXPLICIT OCTET STRING }
        let mut e = Cursor::new(eci);
        e.expect_oid(eci)
            .ok_or_else(|| TsaError::BadResponse("eci: no OID".into()))?;
        let octets = e
            .expect_explicit0(eci)
            .ok_or_else(|| TsaError::BadResponse("eci: no [0]".into()))?;
        let tst_der = parse_octet_string(octets)
            .ok_or_else(|| TsaError::BadResponse("eci: octet string inválida".into()))?;
        let (gen_time, imprint) = parse_tst_info(&tst_der)?;
        Ok((gen_time, imprint))
    }
}

fn read_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for b in &data[1..1 + n] {
            len = (len << 8) | *b as usize;
        }
        Some((len, 1 + n))
    }
}

/// Cursor DER minimalista: trabaja sobre el CONTENIDO de un elemento compuesto
/// y devuelve slices al contenido de los elementos hijos.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Espera un TLV y devuelve su contenido.
    fn take_tlv(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.data.len() {
            return None;
        }
        let (len, hdr) = read_len(&self.data[self.pos + 1..])?;
        let end = self.pos + 1 + hdr + len;
        if end > self.data.len() {
            return None;
        }
        let content = &self.data[self.pos + 1 + hdr..end];
        self.pos = end;
        Some(content)
    }

    /// Consume un TLV sin devolver nada (para campos que no interesan).
    fn skip_tlv(&mut self) -> Option<()> {
        self.take_tlv().map(|_| ())
    }

    /// Consume un TLV y verifica que sea SEQUENCE, devolviendo su contenido.
    fn expect_seq(&mut self) -> Option<&'a [u8]> {
        if self.data.get(self.pos) != Some(&0x30) {
            return None;
        }
        self.take_tlv()
    }

    /// Consume un TLV y verifica que sea OID, devolviendo su contenido.
    fn expect_oid(&mut self, _parent: &'a [u8]) -> Option<&'a [u8]> {
        if self.data.get(self.pos) != Some(&0x06) {
            return None;
        }
        self.take_tlv()
    }

    /// Consume un TLV [0] EXPLICIT (0xA0) y devuelve su contenido (que a su vez
    /// es un TLV completo).
    fn expect_explicit0(&mut self, _parent: &'a [u8]) -> Option<&'a [u8]> {
        if self.data.get(self.pos) != Some(&0xA0) {
            return None;
        }
        self.take_tlv()
    }
}

/// Parsea TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber,
/// genTime, [tsa], [extensions] } y devuelve (genTime epoch, messageImprint).
fn parse_tst_info(der_bytes: &[u8]) -> Result<(i64, MessageImprint), TsaError> {
    let mut cur = Cursor::new(der_bytes);
    let body = cur
        .expect_seq()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no SEQ".into()))?;
    let mut p = Cursor::new(body);
    p.skip_tlv()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no version".into()))?; // version INTEGER
    p.skip_tlv()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no policy".into()))?; // policy OID
    let mi_der = p
        .expect_seq()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no messageImprint".into()))?;
    p.skip_tlv()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no serial".into()))?; // serialNumber INTEGER
                                                                             // genTime (UTCTime 0x17 o GeneralizedTime 0x18)
    let tag = *body
        .get(p.pos)
        .ok_or_else(|| TsaError::BadResponse("tstinfo: no genTime".into()))?;
    let time_content = p
        .take_tlv()
        .ok_or_else(|| TsaError::BadResponse("tstinfo: genTime TLV".into()))?;
    let time_str = std::str::from_utf8(time_content)
        .map_err(|_| TsaError::BadResponse("tstinfo: genTime utf8".into()))?;
    let epoch = parse_der_time(tag, time_str)?;

    // parse del messageImprint: SEQUENCE { SEQ{OID, NULL}, OCTETSTRING }
    let mut mi = Cursor::new(mi_der);
    let alg = mi
        .expect_seq()
        .ok_or_else(|| TsaError::BadResponse("mi: no alg SEQ".into()))?;
    let oid_str = {
        let mut a = Cursor::new(alg);
        let oid_content = a
            .expect_oid(alg)
            .ok_or_else(|| TsaError::BadResponse("mi: no OID".into()))?;
        let oid_tlv = tlv(0x06, oid_content);
        let oid = ObjectIdentifier::from_der(&oid_tlv)
            .map_err(|e| TsaError::BadResponse(format!("mi: oid der: {e}")))?;
        oid.to_string()
    };
    // hashedMessage OCTET STRING después del algoritmo
    let rest = &mi_der[mi.pos..];
    let hashed = parse_octet_string(rest)
        .ok_or_else(|| TsaError::BadResponse("mi: hashed inválido".into()))?;

    Ok((
        epoch,
        MessageImprint {
            hash_oid: oid_str,
            hashed_message: hashed,
        },
    ))
}

fn parse_der_time(tag: u8, s: &str) -> Result<i64, TsaError> {
    // Formatos: YYMMDDHHMMSSZ o YYYYMMDDHHMMSSZ
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let (year, rest) = if tag == 0x17 {
        let yy: i64 = digits
            .get(0..2)
            .ok_or_else(|| TsaError::BadResponse("time".into()))?
            .parse()
            .map_err(|_| TsaError::BadResponse("time".into()))?;
        let y = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (y, &digits[2..])
    } else {
        let y: i64 = digits
            .get(0..4)
            .ok_or_else(|| TsaError::BadResponse("time".into()))?
            .parse()
            .map_err(|_| TsaError::BadResponse("time".into()))?;
        (y, &digits[4..])
    };
    let mo: i64 = rest
        .get(0..2)
        .ok_or_else(|| TsaError::BadResponse("time".into()))?
        .parse()
        .map_err(|_| TsaError::BadResponse("time".into()))?;
    let d: i64 = rest
        .get(2..4)
        .ok_or_else(|| TsaError::BadResponse("time".into()))?
        .parse()
        .map_err(|_| TsaError::BadResponse("time".into()))?;
    let h: i64 = rest
        .get(4..6)
        .ok_or_else(|| TsaError::BadResponse("time".into()))?
        .parse()
        .map_err(|_| TsaError::BadResponse("time".into()))?;
    let mi: i64 = rest
        .get(6..8)
        .ok_or_else(|| TsaError::BadResponse("time".into()))?
        .parse()
        .map_err(|_| TsaError::BadResponse("time".into()))?;
    let sec: i64 = rest
        .get(8..10)
        .ok_or_else(|| TsaError::BadResponse("time".into()))?
        .parse()
        .map_err(|_| TsaError::BadResponse("time".into()))?;
    Ok(days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Días desde epoch (algoritmo inverso de civil_from_days, Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Autoridad de Sellado de Tiempo local.
pub struct LocalTsa {
    identity: Identity,
}

impl LocalTsa {
    /// Crea una TSA local con una identidad autofirmada nueva.
    pub fn new() -> Result<Self, TsaError> {
        let id = Identity::generate()
            .self_sign_ca("Boveda Local TSA", 3650)
            .map_err(|e| TsaError::Crypto(e.to_string()))?;
        Ok(LocalTsa { identity: id })
    }

    /// Crea la TSA y persiste su identidad para uso en reinicios.
    pub fn new_persisted(dir: &Path) -> Result<Self, TsaError> {
        if dir.join("tsa.crt.pem").exists() {
            let id = Identity::load(dir, "tsa").map_err(|e| TsaError::Crypto(e.to_string()))?;
            return Ok(LocalTsa { identity: id });
        }
        let id = Identity::generate()
            .self_sign_ca("Boveda Local TSA", 3650)
            .map_err(|e| TsaError::Crypto(e.to_string()))?;
        id.save(dir, "tsa")
            .map_err(|e| TsaError::Crypto(e.to_string()))?;
        Ok(LocalTsa { identity: id })
    }

    /// Emite un token de sello de tiempo para un hash SHA-256 ya calculado.
    /// El hashedMessage es el digest en sí (no se vuelve a hashear).
    pub fn stamp_sha256(&self, sha256_hex: &str) -> Result<TimestampToken, TsaError> {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(sha256_hex, &mut raw)
            .map_err(|_| TsaError::BadResponse("sha256 hex inválido".into()))?;
        let imprint = MessageImprint {
            hash_oid: OID_SHA256.to_string(),
            hashed_message: raw.to_vec(),
        };
        self.stamp_imprint(&imprint)
    }

    /// Sella un SHA-256 y devuelve el par listo para guardar en un documento:
    /// (token DER en base64, sello de tiempo RFC 3339).
    ///
    /// Es el ÚNICO camino de sellado temporal del sistema: lo usan tanto la
    /// admisión de entregas como la importación desde la aplicación gráfica,
    /// de modo que un documento sellado localmente y uno recibido del móvil
    /// llevan el mismo formato de prueba de tiempo.
    pub fn stamp_document(&self, sha256_hex: &str) -> Result<(String, String), TsaError> {
        let token = self.stamp_sha256(sha256_hex)?;
        let (epoch, _) = token.parse()?;
        use base64::Engine as _;
        let token_b64 = base64::engine::general_purpose::STANDARD.encode(&token.der);
        Ok((token_b64, vault_core::format_rfc3339(epoch)))
    }

    /// Emite el token para un messageImprint ya construido.
    pub fn stamp_imprint(&self, imprint: &MessageImprint) -> Result<TimestampToken, TsaError> {
        let serial = {
            let mut b = [0u8; 8];
            getrandom::getrandom(&mut b).map_err(|e| TsaError::Crypto(e.to_string()))?;
            u64::from_be_bytes(b)
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| TsaError::Crypto(e.to_string()))?
            .as_secs() as i64;
        let (y, mo, d, h, mi, s) = vault_core::civil_from_epoch(now);
        let gen_time = DerTime::GeneralizedTime(format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z"));

        let tst_body = der_sequence(&[
            der_integer(1).as_slice(),
            der_oid("1.3.6.1.4.1.99999.1.1").as_slice(), // policy propia
            imprint.to_der().as_slice(),
            der_integer(serial as i64).as_slice(),
            gen_time.to_der_bytes().as_slice(),
        ]);
        // tst_body ya ES el TSTInfo completo (der_sequence produce el SEQUENCE TLV)

        // eContentType = TSTInfo OID
        let eci = der_sequence(&[
            der_oid(OID_TSTINFO).as_slice(),
            tlv(0xA0, der_octet_string(&tst_body).as_slice()).as_slice(),
        ]);

        // eSSC: signingCertificateV2 attr con SEQ { SEQ { certHash } } (sin policy opcional)
        let cert_hash = {
            let cert = Certificate::from_der(&self.identity.cert_der)
                .map_err(|e| TsaError::Crypto(e.to_string()))?;
            let der_bytes = cert.to_der().map_err(|e| TsaError::Crypto(e.to_string()))?;
            sha2::Sha256::digest(der_bytes).to_vec()
        };
        let essc_cert = der_sequence(&[der_octet_string(&cert_hash).as_slice()]);
        let essc = der_sequence(&[essc_cert.as_slice()]);

        let signed_attrs = der_set(&[
            DerAttribute {
                oid: OID_CONTENT_TYPE.to_string(),
                values_der: vec![der_oid(OID_TSTINFO)],
            }
            .to_der()
            .as_slice(),
            DerAttribute {
                oid: OID_SIGNING_TIME.to_string(),
                values_der: vec![gen_time.to_der_bytes()],
            }
            .to_der()
            .as_slice(),
            DerAttribute {
                oid: "1.2.840.113549.1.9.16.2.47".to_string(), // signingCertificateV2
                values_der: vec![tlv(0x04, &essc)],
            }
            .to_der()
            .as_slice(),
        ]);

        // firma sobre SET OF attributes con IMPLICIT [0] — el contenido firmado real
        let sig_input = signed_attrs_as_signed(&signed_attrs);
        let sig = self
            .identity
            .sign(&sig_input)
            .map_err(|e| TsaError::Crypto(e.to_string()))?;

        let signer_info = der_sequence(&[
            der_integer(1).as_slice(),
            der_octet_string(&serial.to_be_bytes()).as_slice(),
            der_sequence(&[der_oid(OID_SHA256).as_slice(), der_null().as_slice()]).as_slice(),
            tlv(0xA0, signed_attrs.as_slice()).as_slice(),
            der_sequence(&[
                der_oid("1.2.840.10045.4.3.2").as_slice(),
                der_null().as_slice(),
            ])
            .as_slice(), // ecdsa-with-SHA256
            der_octet_string(&sig.to_bytes()).as_slice(),
        ]);

        let cert = Certificate::from_der(&self.identity.cert_der)
            .map_err(|e| TsaError::Crypto(e.to_string()))?;
        let cert_der = cert.to_der().map_err(|e| TsaError::Crypto(e.to_string()))?;

        let signed_data = der_sequence(&[
            der_integer(1).as_slice(),
            der_set(&[
                der_sequence(&[der_oid(OID_SHA256).as_slice(), der_null().as_slice()]).as_slice(),
            ])
            .as_slice(),
            eci.as_slice(),
            tlv(0xA0, tlv(0x30, &cert_der).as_slice()).as_slice(),
            tlv(0xA0, tlv(0x31, signer_info.as_slice()).as_slice()).as_slice(),
        ]);

        let token = der_sequence(&[
            der_oid(OID_SIGNED_DATA).as_slice(),
            tlv(0xA0, signed_data.as_slice()).as_slice(),
        ]);

        Ok(TimestampToken { der: token })
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.identity.cert_der
    }
}

/// Convierte SET OF Attribute (implicit [0] en signedAttrs) al formato firmado:
/// el contenido se firma como SET OF con tag 0x31.
fn signed_attrs_as_signed(signed_attrs_set_der: &[u8]) -> Vec<u8> {
    // signed_attrs_set_der ya es un SET (0x31) construido con der_set
    signed_attrs_set_der.to_vec()
}

/// Cliente para TSA externa vía HTTP POST (RFC 3161).
pub struct RemoteTsaClient {
    pub url: String,
}

impl RemoteTsaClient {
    pub fn new(url: impl Into<String>) -> Self {
        RemoteTsaClient { url: url.into() }
    }

    /// Construye la petición TimeStampReq DER para un hash SHA-256.
    pub fn build_request(sha256_hex: &str) -> Result<Vec<u8>, TsaError> {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(sha256_hex, &mut raw)
            .map_err(|_| TsaError::BadResponse("sha256 hex inválido".into()))?;
        let imprint = MessageImprint::sha256(&raw);
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).map_err(|e| TsaError::Crypto(e.to_string()))?;
        Ok(der_sequence(&[
            der_integer(1).as_slice(),
            imprint.to_der().as_slice(),
            der_octet_string(&nonce).as_slice(),
            der_bool_true().as_slice(),
        ]))
    }

    /// Envía la petición con curl del sistema (disponible en Linux/Windows).
    pub fn request_token(&self, sha256_hex: &str) -> Result<TimestampToken, TsaError> {
        let req = Self::build_request(sha256_hex)?;
        let tmp_in = std::env::temp_dir().join(format!("tsareq-{}", vault_core::new_id()));
        let tmp_out = std::env::temp_dir().join(format!("tsaresp-{}", vault_core::new_id()));
        std::fs::write(&tmp_in, &req).map_err(|e| TsaError::Network(e.to_string()))?;
        let status = std::process::Command::new("curl")
            .args([
                "-s",
                "-S",
                "--max-time",
                "20",
                "-H",
                "Content-Type: application/timestamp-query",
                "--data-binary",
                tmp_in
                    .to_str()
                    .ok_or_else(|| TsaError::Network("path".into()))?,
                "-o",
                tmp_out
                    .to_str()
                    .ok_or_else(|| TsaError::Network("path".into()))?,
                &self.url,
            ])
            .status()
            .map_err(|e| TsaError::Network(e.to_string()))?;
        if !status.success() {
            return Err(TsaError::Network(format!("curl exit: {status}")));
        }
        let resp = std::fs::read(&tmp_out).map_err(|e| TsaError::Network(e.to_string()))?;
        let _ = std::fs::remove_file(&tmp_in);
        let _ = std::fs::remove_file(&tmp_out);
        // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, [0] timeStampToken }
        Self::extract_token(&resp)
            .ok_or_else(|| TsaError::BadResponse("sin token en respuesta".into()))
    }

    fn extract_token(resp: &[u8]) -> Option<TimestampToken> {
        // buscaremos el [0] EXPLICIT que envuelve el token tras el status
        let any = der::asn1::AnyRef::from_der(resp).ok()?;
        let body = any.value();
        // status SEQ
        let (sl, sh) = read_len(&body[1..])?;
        let p = 1 + sh + sl;
        if p >= body.len() && body.get(p) != Some(&0xA0) {
            return None;
        }
        if body.get(p) != Some(&0xA0) {
            return None;
        }
        let (tl, th) = read_len(&body[p + 1..])?;
        Some(TimestampToken {
            der: body[p + 1 + th..p + 1 + th + tl].to_vec(),
        })
    }
}

impl Default for LocalTsa {
    fn default() -> Self {
        Self::new().expect("local TSA")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_tsa_issues_and_parses_token() {
        let tsa = LocalTsa::new().unwrap();
        let sha = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"documento de prueba"))
        };
        let token = tsa.stamp_sha256(&sha).unwrap();
        let (epoch, imprint) = token.parse().unwrap();
        assert_eq!(hex::encode(&imprint.hashed_message), sha);
        assert!(epoch > 1_700_000_000);
    }

    #[test]
    fn imprint_binds_content() {
        let tsa = LocalTsa::new().unwrap();
        let t1 = tsa
            .stamp_sha256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
        let (_, imprint) = t1.parse().unwrap();
        assert_eq!(imprint.hashed_message.len(), 32);
        assert_eq!(imprint.hash_oid, OID_SHA256);
    }

    #[test]
    fn stamp_document_gives_token_and_rfc3339_time() {
        let tsa = LocalTsa::new().unwrap();
        let sha = "cd".repeat(32);
        let (token_b64, when) = tsa.stamp_document(&sha).unwrap();
        assert!(!token_b64.is_empty());
        // sello RFC 3339 en UTC: YYYY-MM-DDTHH:MM:SSZ
        assert!(
            when.len() == 20 && when.ends_with('Z') && when.as_bytes()[10] == b'T',
            "sello inesperado: {when}"
        );
        // el token en base64 vuelve a ser un TimeStampToken parseable
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(token_b64.as_bytes())
            .unwrap();
        let (epoch, imprint) = TimestampToken { der }.parse().unwrap();
        assert_eq!(hex::encode(&imprint.hashed_message), sha);
        assert!(epoch > 1_700_000_000);
    }

    #[test]
    fn der_time_parsing() {
        assert_eq!(
            parse_der_time(0x17, "260923191347Z").unwrap(),
            1_790_190_827
        );
        assert_eq!(
            parse_der_time(0x18, "20260923191347Z").unwrap(),
            1_790_190_827
        );
    }
}
