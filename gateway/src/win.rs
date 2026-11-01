//! Windows API (jedini modul s `unsafe`, AC-GW-1): kanal prema C++ servisu, vlasnik kanala, DPAPI, SID.

use std::ffi::c_void;
use std::io;
use std::ptr;
use tokio::net::windows::named_pipe::NamedPipeClient;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, ERROR_PIPE_BUSY, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Entropija DPAPI-ja za privatni ključ gatewaya (račun usluge)
const ENTROPY: &[u8] = b"SolarniMonitor/4.0/gateway-key";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: ručka je naša i zatvara se samo jednom
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// SID (S-1-…) u tekst; `sid` mora biti valjan dok traje poziv.
unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: pozivatelj jamči valjan SID; izlazni niz završava nulom i oslobađa se s LocalFree
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0usize;
        while *text.add(len) != 0 {
            len += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as *mut c_void);
        Ok(out)
    }
}

/// Vlasnik sigurnosnog opisnika objekta jezgre (kanala).
fn owner_sid(handle: HANDLE) -> io::Result<String> {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: izlazni pokazivači su lokalni; opisnik oslobađamo s LocalFree nakon pretvorbe
    unsafe {
        let rc = GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        );
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let out = sid_to_string(owner);
        LocalFree(sd);
        out
    }
}

/// Spajanje na kanal C++ servisa. Prije bilo kakvog slanja provjerava da je vlasnik kanala `expected_owner`
/// (u produkciji SYSTEM, S-1-5-18) – zaštita od lažnog kanala (AC-GW-5). Bez GENERIC_WRITE (ne treba
/// FILE_CREATE_PIPE_INSTANCE) i uz SECURITY_IDENTIFICATION (servis ne smije oponašati gateway).
pub fn connect_pipe(name: &str, expected_owner: &str) -> io::Result<NamedPipeClient> {
    let wname = wide(name);
    for _ in 0..40 {
        // SAFETY: wname završava nulom i živi do kraja poziva; ostali argumenti su konstante
        let h = unsafe {
            CreateFileW(
                wname.as_ptr(),
                GENERIC_READ | FILE_WRITE_DATA,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: bez argumenata
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                // SAFETY: wname završava nulom
                unsafe { WaitNamedPipeW(wname.as_ptr(), 250) };
                continue;
            }
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        let guard = OwnedHandle(h);
        let owner = owner_sid(h)?;
        if owner != expected_owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("vlasnik kanala je {owner}, očekivan {expected_owner} – ništa nije poslano"),
            ));
        }
        std::mem::forget(guard);
        // SAFETY: ručka je otvorena s FILE_FLAG_OVERLAPPED i vlasništvo prelazi na tokio (zatvara je on)
        return unsafe { NamedPipeClient::from_raw_handle(h as _) };
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "kanal je zauzet"))
}

/// SO_EXCLUSIVEADDRUSE prije bind(): drugi proces (ni sa SO_REUSEADDR) ne može preuzeti isti port.
pub fn exclusive_address(socket: &tokio::net::TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};
    let on: i32 = 1;
    // SAFETY: utičnica je valjana (posuđena), vrijednost je lokalna i živi do kraja poziva
    let rc = unsafe { setsockopt(socket.as_raw_socket() as SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &on as *const i32 as *const u8, 4) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

/// DPAPI računa pod kojim gateway radi (NT SERVICE\SolariGateway), uz entropiju aplikacije.
/// Zapis: 'U' + blob. Ako DPAPI računa nije dostupan (profil virtualnog računa), DPAPI računala: 'M' + blob –
/// tada ključ štiti samo ACL mape gatewaya (SYSTEM, administratori, usluga); vraća se i oznaka načina.
pub fn dpapi_protect(data: &[u8]) -> io::Result<(Vec<u8>, bool)> {
    match dpapi(data, true, false) {
        Ok(v) => Ok(([b"U".as_slice(), &v].concat(), false)),
        Err(_) => dpapi(data, true, true).map(|v| ([b"M".as_slice(), &v].concat(), true)),
    }
}

pub fn dpapi_unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
    match data.split_first() {
        Some((b'U', rest)) => dpapi(rest, false, false),
        Some((b'M', rest)) => dpapi(rest, false, true),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "nepoznat zapis ključa")),
    }
}

fn dpapi(data: &[u8], protect: bool, machine: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::CRYPTPROTECT_LOCAL_MACHINE;
    let input = blob(data);
    let entropy = blob(ENTROPY);
    let flags = CRYPTPROTECT_UI_FORBIDDEN | if machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() };
    // SAFETY: ulazni međuspremnici žive do kraja poziva; izlaz oslobađamo s LocalFree
    unsafe {
        let ok = if protect {
            CryptProtectData(&input, ptr::null(), &entropy, ptr::null(), ptr::null(), flags, &mut out)
        } else {
            CryptUnprotectData(&input, ptr::null_mut(), &entropy, ptr::null(), ptr::null(), flags, &mut out)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        ptr::write_bytes(out.pbData, 0, out.cbData as usize);
        LocalFree(out.pbData as *mut c_void);
        Ok(v)
    }
}

/// SID računa pod kojim proces radi (zapisnik, testovi).
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: pseudo-ručka procesa; token zatvara OwnedHandle
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let _guard = OwnedHandle(token);
        let mut size = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, size, &mut size) == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_roundtrip_and_tamper() {
        let (sealed, machine) = dpapi_protect(b"kljuc").unwrap();
        assert!(!machine, "u testu (korisnički profil) DPAPI računa mora raditi");
        assert_eq!(sealed[0], b'U');
        assert_ne!(sealed, b"kljuc");
        assert_eq!(dpapi_unprotect(&sealed).unwrap(), b"kljuc");
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        assert!(dpapi_unprotect(&bad).is_err());
        assert!(dpapi_unprotect(b"Xabc").is_err());
        let m = [b"M".as_slice(), &dpapi(b"k2", true, true).unwrap()].concat();
        assert_eq!(dpapi_unprotect(&m).unwrap(), b"k2");
    }

    #[test]
    fn current_sid_looks_valid() {
        assert!(current_user_sid().unwrap().starts_with("S-1-5-"));
    }

    #[tokio::test]
    async fn missing_pipe_is_error() {
        assert!(connect_pipe(r"\\.\pipe\SolariTest.ne.postoji.12345", "S-1-5-18").is_err());
    }
}
