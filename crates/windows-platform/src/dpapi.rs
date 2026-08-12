use codex_application::CredentialStoreError;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Default)]
pub struct DpapiCurrentUser;

#[cfg(windows)]
impl DpapiCurrentUser {
    pub fn protect(
        &self,
        entropy: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CredentialStoreError> {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
            },
        };

        let input = blob(plaintext)?;
        let entropy = blob(entropy)?;
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: input/entropy slices remain alive for the call; output is initialized by DPAPI
        // and released exactly once with LocalFree below. Optional UI/reserved pointers are null.
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return Err(CredentialStoreError::ProtectionFailed);
        }
        // SAFETY: successful DPAPI returns a valid buffer of cbData bytes.
        let protected = unsafe {
            std::slice::from_raw_parts(output.pbData.cast_const(), output.cbData as usize).to_vec()
        };
        // SAFETY: DPAPI documents pDataOut.pbData as LocalAlloc memory.
        unsafe { LocalFree(output.pbData.cast()) };
        Ok(protected)
    }

    pub fn unprotect<T>(
        &self,
        entropy: &[u8],
        protected: &[u8],
        consume: impl FnOnce(&[u8]) -> Result<T, CredentialStoreError>,
    ) -> Result<T, CredentialStoreError> {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
            },
        };

        let input = blob(protected)?;
        let entropy = blob(entropy)?;
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: input/entropy slices remain alive; output and optional description pointers are
        // initialized according to CryptUnprotectData and no UI is permitted.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 || output.pbData.is_null() {
            return Err(CredentialStoreError::ProtectionFailed);
        }
        // SAFETY: successful DPAPI returns cbData readable bytes until LocalFree.
        let mut plaintext = Zeroizing::new(unsafe {
            std::slice::from_raw_parts(output.pbData.cast_const(), output.cbData as usize).to_vec()
        });
        // SAFETY: the successful output buffer is writable for cbData bytes. Erase the original
        // DPAPI plaintext allocation before releasing it with the documented LocalFree API.
        unsafe {
            std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
            LocalFree(output.pbData.cast());
        }
        let result = consume(&plaintext);
        plaintext.zeroize();
        result
    }
}

#[cfg(windows)]
fn blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, CredentialStoreError> {
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len())
                .map_err(|_| CredentialStoreError::ProtectionFailed)?,
            pbData: bytes.as_ptr().cast_mut(),
        },
    )
}

#[cfg(not(windows))]
impl DpapiCurrentUser {
    pub fn protect(
        &self,
        _entropy: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, CredentialStoreError> {
        Err(CredentialStoreError::ProtectionFailed)
    }
    pub fn unprotect<T>(
        &self,
        _entropy: &[u8],
        _protected: &[u8],
        _consume: impl FnOnce(&[u8]) -> Result<T, CredentialStoreError>,
    ) -> Result<T, CredentialStoreError> {
        Err(CredentialStoreError::ProtectionFailed)
    }
}
