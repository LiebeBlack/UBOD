//! PKI ligera de la bóveda: CA propia P-256, certificado de servidor y de dispositivos.
//!
//! El servidor de la bóveda es su propia autoridad certificadora. Cada dispositivo
//! Android obtiene un certificado de cliente firmado por la CA tras el emparejamiento
//! con código de un solo uso. mTLS exige certificado de cliente en ambas direcciones.

use der::asn1::{Any, Ia5String, ObjectIdentifier, OctetString, Utf8StringRef};
use der::{Decode, Encode};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use rand_core::OsRng;
use std::path::Path;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::Certificate;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("error PKI interno: {0}")]
    Der(#[from] der::Error),
    #[error("error de E/S PKI: {0}")]
    Io(#[from] std::io::Error),
    #[error("firma inválida o certificado inválido")]
    Invalid,
}

/// Identidad criptográfica completa: clave privada + certificado DER.
#[derive(Clone)]
pub struct Identity {
    pub cert_der: Vec<u8>,
    signing_key: SigningKey,
}

impl Identity {
    /// Genera una identidad nueva (clave P-256); el certificado se asigna después.
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        Identity {
            cert_der: Vec::new(),
            signing_key: SigningKey::from(secret),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key().to_owned()
    }

    pub fn verifying_key_from_secret(secret: &SecretKey) -> VerifyingKey {
        SigningKey::from(secret).verifying_key().to_owned()
    }

    pub fn sign(&self, msg: &[u8]) -> Result<DerSignature, PkiError> {
        use p256::ecdsa::signature::Signer;
        Ok(self.signing_key.sign(msg))
    }

    /// Guarda clave (PKCS8 PEM) y certificado (PEM) en el directorio dado.
    pub fn save(&self, dir: &Path, stem: &str) -> Result<(), PkiError> {
        std::fs::create_dir_all(dir)?;
        let key_pem = self
            .signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|_| PkiError::Invalid)?;
        std::fs::write(dir.join(format!("{stem}.key.pem")), key_pem.as_bytes())?;
        let cert_pem = pem_encode_cert(&self.cert_der);
        std::fs::write(dir.join(format!("{stem}.crt.pem")), cert_pem)?;
        Ok(())
    }

    /// Carga una identidad desde archivos PEM guardados con `save`.
    pub fn load(dir: &Path, stem: &str) -> Result<Self, PkiError> {
        use p256::pkcs8::DecodePrivateKey;
        let key_pem = std::fs::read_to_string(dir.join(format!("{stem}.key.pem")))?;
        let cert_pem = std::fs::read_to_string(dir.join(format!("{stem}.crt.pem")))?;
        let secret = SecretKey::from_pkcs8_pem(&key_pem).map_err(|_| PkiError::Invalid)?;
        let cert = load_pem_cert(cert_pem.as_bytes())?;
        Ok(Identity {
            cert_der: cert.to_der()?,
            signing_key: SigningKey::from(secret),
        })
    }

    /// Genera el certificado autofirmado de la CA (perfil raíz).
    pub fn self_sign_ca(mut self, cn: &str, days: u32) -> Result<Self, PkiError> {
        let vk = self.signing_key.verifying_key().to_owned();
        let cert = build_cert(
            cn,
            cn,
            vk,
            &self.signing_key,
            true,
            days,
            &[ca_key_usage()],
            &EMPTY_EKU,
            None,
        )?;
        self.cert_der = cert.to_der()?;
        Ok(self)
    }

    /// Firma un certificado hoja (servidor o dispositivo) con esta identidad CA.
    pub fn sign_leaf(
        &self,
        subject_cn: &str,
        subject_vk: VerifyingKey,
        is_server: bool,
        days: u32,
    ) -> Result<Vec<u8>, PkiError> {
        self.sign_leaf_with_san(subject_cn, subject_vk, is_server, days, None)
    }

    /// Igual que `sign_leaf`, añadiendo una extensión SubjectAltName
    /// (necesaria en certificados de servidor: rustls valida por SAN).
    pub fn sign_leaf_with_san(
        &self,
        subject_cn: &str,
        subject_vk: VerifyingKey,
        is_server: bool,
        days: u32,
        san: Option<Vec<GeneralName>>,
    ) -> Result<Vec<u8>, PkiError> {
        let ca_cert = Certificate::from_der(&self.cert_der)?;
        let issuer_cn = common_name(&ca_cert);
        let mut eku_vec = vec![OID_CLIENT_AUTH];
        if is_server {
            eku_vec.push(OID_SERVER_AUTH);
        }
        let eku = ExtendedKeyUsage(eku_vec);
        let cert = build_cert(
            subject_cn,
            &issuer_cn,
            subject_vk,
            &self.signing_key,
            false,
            days,
            &[leaf_key_usage()],
            &eku,
            san,
        )?;
        cert.to_der().map_err(PkiError::from)
    }
}

const OID_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

static EMPTY_EKU: std::sync::LazyLock<ExtendedKeyUsage> =
    std::sync::LazyLock::new(|| ExtendedKeyUsage(Vec::new()));

fn ca_key_usage() -> KeyUsage {
    KeyUsage::from(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign | KeyUsages::CRLSign)
}

fn leaf_key_usage() -> KeyUsage {
    KeyUsage::from(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment)
}

/// Codifica un certificado DER como PEM.
pub fn pem_encode_cert(der: &[u8]) -> String {
    use base64::Engine;
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Par de claves efímero para un dispositivo que solicita certificado.
pub struct DeviceKeyPair {
    pub secret: SecretKey,
}

impl DeviceKeyPair {
    pub fn generate() -> Self {
        DeviceKeyPair {
            secret: SecretKey::random(&mut OsRng),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        SigningKey::from(&self.secret).verifying_key().to_owned()
    }

    /// Exporta la clave privada en PKCS8 PEM (para el teléfono/CLI).
    pub fn to_pkcs8_pem(&self) -> String {
        self.secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map(|p| p.to_string())
            .expect("pkcs8 pem")
    }
}

/// Construye un `GeneralName::IpAddress` a partir de una IP.
pub fn san_ip(ip: std::net::IpAddr) -> Result<GeneralName, PkiError> {
    let octets: Vec<u8> = match ip {
        std::net::IpAddr::V4(v) => v.octets().to_vec(),
        std::net::IpAddr::V6(v) => v.octets().to_vec(),
    };
    Ok(GeneralName::IpAddress(OctetString::new(&octets[..])?))
}

/// Construye un `GeneralName::DnsName`.
pub fn san_dns(name: &str) -> Result<GeneralName, PkiError> {
    Ok(GeneralName::DnsName(Ia5String::new(name)?))
}

/// Detecta la IP local (no loopback) que se usaría para salir a Internet.
/// Truco estándar: conectar un socket UDP (no envía paquetes) y leer la dirección local.
pub fn detect_local_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Carga un certificado desde PEM o DER crudo.
pub fn load_pem_cert(data: &[u8]) -> Result<Certificate, PkiError> {
    let text = String::from_utf8_lossy(data);
    if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let body: String = text[start..]
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect();
        let der_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body.trim())
                .map_err(|_| PkiError::Invalid)?;
        return Certificate::from_der(&der_bytes).map_err(PkiError::from);
    }
    Certificate::from_der(data).map_err(PkiError::from)
}

/// Extrae el CommonName del subject.
pub fn common_name(cert: &Certificate) -> String {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for attr in rdn.0.iter() {
            if attr.oid.to_string() == "2.5.4.3" {
                if let Ok(der_bytes) = attr.value.to_der() {
                    if let Ok(any) = Any::from_der(&der_bytes) {
                        if let Ok(s) = any.decode_as::<Utf8StringRef>() {
                            return s.to_string();
                        }
                        if let Ok(s) = any.decode_as::<der::asn1::PrintableStringRef>() {
                            return s.to_string();
                        }
                    }
                }
            }
        }
    }
    String::new()
}

/// Extrae la clave pública SPKI (der) de un certificado.
pub fn spki_bytes(cert: &Certificate) -> Result<Vec<u8>, PkiError> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(PkiError::from)
}

#[allow(clippy::too_many_arguments)] // perfil completo de X.509: los 9 campos son necesarios
fn build_cert(
    subject_cn: &str,
    issuer_cn: &str,
    subject_vk: VerifyingKey,
    signer: &SigningKey,
    is_ca: bool,
    days: u32,
    key_usages: &[KeyUsage],
    ekus: &ExtendedKeyUsage,
    san: Option<Vec<GeneralName>>,
) -> Result<Certificate, PkiError> {
    let serial = SerialNumber::from(random_u64());
    let validity = Validity::from_now(std::time::Duration::from_secs(u64::from(days) * 86_400))
        .map_err(PkiError::from)?;

    let subject = name_from_cn(subject_cn);
    let issuer = name_from_cn(issuer_cn);

    let profile = if is_ca {
        Profile::Root
    } else {
        Profile::Leaf {
            issuer,
            enable_key_agreement: false,
            enable_key_encipherment: true,
        }
    };
    let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(subject_vk)
        .map_err(|_| PkiError::Invalid)?;

    let mut builder = CertificateBuilder::new(profile, serial, validity, subject, spki, signer)
        .map_err(|_| PkiError::Invalid)?;

    if is_ca {
        builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            })
            .map_err(|_| PkiError::Invalid)?;
    }
    for ku in key_usages {
        builder.add_extension(ku).map_err(|_| PkiError::Invalid)?;
    }
    if !ekus.0.is_empty() {
        builder.add_extension(ekus).map_err(|_| PkiError::Invalid)?;
    }
    if let Some(names) = san {
        let general_names = GeneralNames::try_from(names).map_err(|_| PkiError::Invalid)?;
        builder
            .add_extension(&SubjectAltName(general_names))
            .map_err(|_| PkiError::Invalid)?;
    }

    let cert = builder
        .build::<p256::ecdsa::DerSignature>()
        .map_err(|_| PkiError::Invalid)?;
    Ok(cert)
}

fn name_from_cn(cn: &str) -> Name {
    let oid_cn = ObjectIdentifier::new_unwrap("2.5.4.3");
    let value = Any::new(der::Tag::Utf8String, cn.as_bytes().to_vec()).expect("utf8 any");
    let atv = x509_cert::attr::AttributeTypeAndValue { oid: oid_cn, value };
    let set = der::asn1::SetOfVec::try_from(vec![atv]).expect("1 atv in set");
    RdnSequence(vec![RelativeDistinguishedName(set)])
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("os randomness");
    u64::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_and_leaf_lifecycle() {
        let ca = Identity::generate()
            .self_sign_ca("Boveda Root CA", 3650)
            .unwrap();
        let saved = tempfile::tempdir().unwrap();
        ca.save(saved.path(), "ca").unwrap();
        let ca2 = Identity::load(saved.path(), "ca").unwrap();
        assert!(!ca2.cert_der.is_empty());

        let dev = DeviceKeyPair::generate();
        let leaf_der = ca2
            .sign_leaf("AND_PROFE_0291", dev.verifying_key(), false, 730)
            .unwrap();
        let leaf = load_pem_cert(&pem_encode(&leaf_der)).unwrap();
        assert_eq!(common_name(&leaf), "AND_PROFE_0291");
    }

    #[test]
    fn sign_and_verify() {
        use p256::ecdsa::signature::Verifier;
        let id = Identity::generate().self_sign_ca("T", 1).unwrap();
        let sig = id.sign(b"payload").unwrap();
        let vk = id.verifying_key();
        assert!(vk.verify(b"payload", &sig).is_ok());
        assert!(vk.verify(b"otro", &sig).is_err());
    }

    fn pem_encode(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out.into_bytes()
    }
}
