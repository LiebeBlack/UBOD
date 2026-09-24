//! ASN.1 DER de bajo nivel para mensajes de tiempo (RFC 3161) y atributos firmados.

use der::asn1::ObjectIdentifier;
use der::Decode;

/// OID de sha256 (2.16.840.1.101.3.4.2.1).
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// OID de contentType (1.2.840.113549.1.9.3).
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// OID de signingTime (1.2.840.113549.1.9.5).
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// OID de id-smime-aa-timeStampToken (1.2.840.113549.1.9.16.2.14).
pub const OID_TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
/// OID de TSTInfo (1.2.840.113549.1.9.16.1.4).
pub const OID_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
/// OID de signedData (1.2.840.113549.1.7.2).
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// Representación mínima de un UTCTime/GeneralizedTime para GEN_TIME.
#[derive(Debug, Clone)]
pub enum DerTime {
    UtcTime(String),         // YYMMDDHHMMSSZ
    GeneralizedTime(String), // YYYYMMDDHHMMSSZ
}

impl DerTime {
    /// Codifica como DER Time choice (UTCTime tag 23 / GeneralizedTime tag 24).
    pub fn to_der_bytes(&self) -> Vec<u8> {
        match self {
            DerTime::UtcTime(s) => tlv(0x17, s.as_bytes()),
            DerTime::GeneralizedTime(s) => tlv(0x18, s.as_bytes()),
        }
    }
}

/// Codifica un TLV DER con la etiqueta dada.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let n = 8 - start;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(content);
    out
}

/// OID codificado en DER.
pub fn der_oid(oid: &str) -> Vec<u8> {
    let oid = ObjectIdentifier::new_unwrap(oid);
    tlv(0x06, oid.as_bytes())
}

/// OCTET STRING codificada en DER.
pub fn der_octet_string(data: &[u8]) -> Vec<u8> {
    tlv(0x04, data)
}

/// NULL codificado en DER.
pub fn der_null() -> Vec<u8> {
    tlv(0x05, &[])
}

/// INTEGER codificado en DER.
pub fn der_integer(v: i64) -> Vec<u8> {
    tlv(0x02, &UintBytes(v).bytes())
}

/// SEQUENCE codificada en DER.
pub fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut content = Vec::with_capacity(total);
    for i in items {
        content.extend_from_slice(i);
    }
    tlv(0x30, &content)
}

/// SET codificado en DER.
pub fn der_set(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut content = Vec::with_capacity(total);
    for i in items {
        content.extend_from_slice(i);
    }
    tlv(0x31, &content)
}

/// BOOLEAN TRUE en DER.
pub fn der_bool_true() -> Vec<u8> {
    tlv(0x01, &[0xFF])
}

/// OCTET STRING decodificada desde DER crudo (para extraer el hash de respuesta).
pub fn parse_octet_string(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 || data[0] != 0x04 {
        return None;
    }
    let (len, consumed) = decode_length(&data[1..])?;
    if data.len() < consumed + len {
        return None;
    }
    Some(data[consumed + 1..consumed + 1 + len].to_vec())
}

/// Decodifica un OCTET STRING con salto de tag previo ya hecho.
pub fn parse_octet_string_body(data: &[u8]) -> Option<Vec<u8>> {
    parse_octet_string(data)
}

fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
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

struct UintBytes(i64);

impl UintBytes {
    fn bytes(&self) -> Vec<u8> {
        let v = self.0;
        if v == 0 {
            return vec![0];
        }
        let be = v.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap();
        let mut out = be[start..].to_vec();
        if out[0] & 0x80 != 0 {
            out.insert(0, 0);
        }
        out
    }
}

/// Un Attribute (RFC 5652): type + values.
#[derive(Debug, Clone)]
pub struct DerAttribute {
    pub oid: String,
    pub values_der: Vec<Vec<u8>>,
}

impl DerAttribute {
    pub fn to_der(&self) -> Vec<u8> {
        der_sequence(&[
            der_oid(&self.oid).as_slice(),
            der_set(
                &self
                    .values_der
                    .iter()
                    .map(|v| v.as_slice())
                    .collect::<Vec<_>>(),
            )
            .as_slice(),
        ])
    }
}

/// Extrae el OID de una OID DER codificada.
pub fn oid_from_der(data: &[u8]) -> Option<String> {
    if data.first() != Some(&0x06) {
        return None;
    }
    let (len, consumed) = decode_length(&data[1..])?;
    let total = 1 + consumed + len;
    if data.len() < total {
        return None;
    }
    let oid = ObjectIdentifier::from_der(&data[..total]).ok()?;
    Some(oid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_short_and_long_lengths() {
        assert_eq!(tlv(0x02, &[0x05]), vec![0x02, 0x01, 0x05]);
        let big = vec![0u8; 300];
        let enc = tlv(0x04, &big);
        assert_eq!(enc[1], 0x82);
        assert_eq!(u16::from_be_bytes([enc[2], enc[3]]), 300);
    }

    #[test]
    fn octet_string_roundtrip() {
        let enc = der_octet_string(b"hola mundo");
        assert_eq!(parse_octet_string(&enc).unwrap(), b"hola mundo");
    }

    #[test]
    fn oid_encoding() {
        let enc = der_oid(OID_SHA256);
        assert_eq!(oid_from_der(&enc).unwrap(), OID_SHA256);
    }
}
