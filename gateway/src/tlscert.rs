//! Certifikat gatewaya (ADR-001 §3): izrađuje se pri prvom pokretanju (ECDSA P-256, 10 godina), privatni ključ
//! je zaštićen DPAPI-jem računa usluge. Otisak (SHA-256 DER, "AB:CD:…") gateway javlja servisu porukom hello,
//! a prozor poslužitelja iz njega prikazuje kod za uparivanje (isti algoritam kao `tls.cpp`).

use crate::win;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use time::{Duration, OffsetDateTime};

const VALID_DAYS: i64 = 3650;
const RENEW_BEFORE_DAYS: i64 = 30;

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: String,
    pub not_after: String, // "2036-10-30"
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Kod za uparivanje (prvih 60 bita otiska u base32, XXXX-XXXX-XXXX) – za zapis i testove; prikazuje ga C++.
pub fn pairing_code(fingerprint: &str) -> Option<String> {
    let bytes: Vec<u8> = fingerprint.split(':').map(|h| u8::from_str_radix(h, 16)).collect::<Result<_, _>>().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    for b in &bytes[..8] {
        bits = (bits << 8) | u64::from(*b);
    }
    let code: String = (0..12).map(|i| ALPHABET[((bits >> (59 - i * 5)) & 31) as usize] as char).collect();
    Some(format!("{}-{}-{}", &code[0..4], &code[4..8], &code[8..12]))
}

fn date_text(t: OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

fn create(dir: &Path) -> io::Result<Identity> {
    let err = |e: rcgen::Error| io::Error::other(e.to_string());
    let mut params = rcgen::CertificateParams::new(vec!["solari-server".to_string()]).map_err(err)?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Solarni posluzitelj");
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALID_DAYS);
    let not_after = date_text(params.not_after);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(err)?;
    let cert = params.self_signed(&key).map_err(err)?;
    let der = cert.der().to_vec();
    let pkcs8 = key.serialize_der();
    std::fs::create_dir_all(dir)?;
    let (sealed, machine) = win::dpapi_protect(&pkcs8)?;
    if machine {
        crate::log::warn("DPAPI računa usluge nije dostupan – ključ je zaštićen DPAPI-jem računala i ACL-om mape gatewaya");
    }
    write_atomic(&dir.join("key.dpapi"), &sealed)?;
    write_atomic(&dir.join("cert.der"), &der)?;
    write_atomic(&dir.join("cert.pem"), cert.pem().as_bytes())?;
    write_atomic(&dir.join("cert.json"), serde_json::json!({ "not_after": not_after }).to_string().as_bytes())?;
    Ok(Identity {
        fingerprint: fingerprint(&der),
        cert: CertificateDer::from(der),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
        not_after,
    })
}

fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

fn load(dir: &Path) -> io::Result<Identity> {
    let der = std::fs::read(dir.join("cert.der"))?;
    let sealed = std::fs::read(dir.join("key.dpapi"))?;
    let pkcs8 = win::dpapi_unprotect(&sealed)?;
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("cert.json"))?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let not_after = meta["not_after"].as_str().unwrap_or_default().to_string();
    // obnova prije isteka (novi otisak → klijenti trebaju novi kod za uparivanje)
    let limit = date_text(OffsetDateTime::now_utc() + Duration::days(RENEW_BEFORE_DAYS));
    if not_after.len() != 10 || not_after <= limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "certifikat uskoro istječe"));
    }
    Ok(Identity {
        fingerprint: fingerprint(&der),
        cert: CertificateDer::from(der),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
        not_after,
    })
}

/// Postojeći certifikat ili novi (ako ga nema, ključ se ne može otključati ili uskoro istječe).
pub fn load_or_create(dir: &Path) -> io::Result<(Identity, bool)> {
    match load(dir) {
        Ok(id) => Ok((id, false)),
        Err(_) => Ok((create(dir)?, true)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_format_matches_cpp() {
        let f = fingerprint(b"abc");
        assert_eq!(f.len(), 32 * 3 - 1);
        assert!(f.starts_with("BA:78:16:BF"));
    }

    #[test]
    fn pairing_code_vector() {
        // isti vektor kao C++ (tls.cpp): prvih 8 bajtova SHA-256("abc") = BA7816BF8F01CFEA
        let code = pairing_code(&fingerprint(b"abc")).unwrap();
        assert_eq!(code, "XJ4B-NP4P-AHH6");
        assert!(pairing_code("AB:CD").is_none());
    }

    #[test]
    fn create_then_load_same_identity() {
        let dir = std::env::temp_dir().join(format!("solari_gw_cert_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (a, created) = load_or_create(&dir).unwrap();
        assert!(created);
        let (b, created) = load_or_create(&dir).unwrap();
        assert!(!created);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert!(a.not_after.as_str() > "2035-01-01");
        let key = std::fs::read(dir.join("key.dpapi")).unwrap();
        assert!(!key.windows(4).any(|w| w == b"\x30\x81\x87\x02"), "ključ nije u čistom obliku");
        // oštećen ključ → novi certifikat (ne pada)
        std::fs::write(dir.join("key.dpapi"), b"x").unwrap();
        let (c, created) = load_or_create(&dir).unwrap();
        assert!(created);
        assert_ne!(c.fingerprint, a.fingerprint);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
