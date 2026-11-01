//! Okvir IPC poruke: 4 bajta duljine (little-endian) + UTF-8 JSON objekt (isto kao `windows/src/ipc.cpp`).

use serde_json::Value;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Zahtjev prema C++ servisu (ADR-001 §3: ≤ 64 KB).
pub const MAX_REQUEST: usize = 64 * 1024;
/// Odgovor C++ servisa (slike u base64).
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;

pub fn encode(message: &Value) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(message).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if body.len() > MAX_REQUEST {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "poruka je prevelika"));
    }
    let len = u32::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "poruka je prevelika"))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Raščlamba tijela okvira; samo JSON objekt.
pub fn decode_body(body: &[u8]) -> io::Result<Value> {
    let value: Value = serde_json::from_slice(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if !value.is_object() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "poruka nije JSON objekt"));
    }
    Ok(value)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, message: &Value) -> io::Result<()> {
    let frame = encode(message)?;
    w.write_all(&frame).await?;
    w.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "okvir je prevelik"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    decode_body(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_matches_cpp_layout() {
        let f = encode(&json!({"a": 1})).unwrap();
        assert_eq!(&f[..4], &7u32.to_le_bytes());
        assert_eq!(&f[4..], br#"{"a":1}"#);
    }

    #[test]
    fn oversize_request_rejected() {
        let big = json!({"x": "a".repeat(MAX_REQUEST)});
        assert!(encode(&big).is_err());
    }

    #[tokio::test]
    async fn read_rejects_bad_frames() {
        let mut too_big: &[u8] = &[0xFF, 0xFF, 0xFF, 0x7F];
        assert!(read_frame(&mut too_big, MAX_RESPONSE).await.is_err());
        let mut not_object: &[u8] = &[2, 0, 0, 0, b'[', b']'];
        assert!(read_frame(&mut not_object, 1024).await.is_err());
        let mut truncated: &[u8] = &[10, 0, 0, 0, b'{'];
        assert!(read_frame(&mut truncated, 1024).await.is_err());
        let mut ok: &[u8] = &[2, 0, 0, 0, b'{', b'}'];
        assert!(read_frame(&mut ok, 1024).await.unwrap().is_object());
    }
}
