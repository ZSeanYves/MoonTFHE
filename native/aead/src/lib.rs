use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

const AEAD_OK: i32 = 0;
const AEAD_NULL_POINTER: i32 = 1;
const AEAD_AUTHENTICATION_FAILED: i32 = 2;
const AEAD_PANIC: i32 = 3;

unsafe fn encrypt_impl(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    tag: *mut u8,
) -> i32 {
    if key.is_null()
        || nonce.is_null()
        || plaintext.is_null()
        || ciphertext.is_null()
        || tag.is_null()
        || (aad_len > 0 && aad.is_null())
    {
        return AEAD_NULL_POINTER;
    }
    let key = Key::<Aes256Gcm>::from_slice(slice::from_raw_parts(key, 32));
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(slice::from_raw_parts(nonce, 12));
    let aad = if aad_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_len)
    };
    let source = slice::from_raw_parts(plaintext, plaintext_len);
    let destination = slice::from_raw_parts_mut(ciphertext, plaintext_len);
    destination.copy_from_slice(source);
    match cipher.encrypt_in_place_detached(nonce, aad, destination) {
        Ok(authentication_tag) => {
            slice::from_raw_parts_mut(tag, 16).copy_from_slice(authentication_tag.as_slice());
            AEAD_OK
        }
        Err(_) => AEAD_PANIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn aes256_gcm_encrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    tag: *mut u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        encrypt_impl(
            key,
            nonce,
            aad,
            aad_len,
            plaintext,
            plaintext_len,
            ciphertext,
            tag,
        )
    }))
    .unwrap_or(AEAD_PANIC)
}

unsafe fn decrypt_impl(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
) -> i32 {
    if key.is_null()
        || nonce.is_null()
        || ciphertext.is_null()
        || plaintext.is_null()
        || tag.is_null()
        || (aad_len > 0 && aad.is_null())
    {
        return AEAD_NULL_POINTER;
    }
    let key = Key::<Aes256Gcm>::from_slice(slice::from_raw_parts(key, 32));
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(slice::from_raw_parts(nonce, 12));
    let aad = if aad_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(aad, aad_len)
    };
    let source = slice::from_raw_parts(ciphertext, ciphertext_len);
    let destination = slice::from_raw_parts_mut(plaintext, ciphertext_len);
    destination.copy_from_slice(source);
    let tag = Tag::from_slice(slice::from_raw_parts(tag, 16));
    match cipher.decrypt_in_place_detached(nonce, aad, destination, tag) {
        Ok(()) => AEAD_OK,
        Err(_) => {
            destination.fill(0);
            AEAD_AUTHENTICATION_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aes256_gcm_decrypt(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    tag: *const u8,
    plaintext: *mut u8,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        decrypt_impl(
            key,
            nonce,
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            tag,
            plaintext,
        )
    }))
    .unwrap_or(AEAD_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_zero_vector_and_wrong_tag() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let mut ciphertext = [0u8; 16];
        let mut tag = [0u8; 16];
        let status = unsafe {
            encrypt_impl(
                key.as_ptr(),
                nonce.as_ptr(),
                std::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(status, AEAD_OK);
        assert_eq!(
            ciphertext,
            [
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18,
            ]
        );
        assert_eq!(
            tag,
            [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19,
            ]
        );

        tag[0] ^= 1;
        let mut recovered = [0xAA; 16];
        let status = unsafe {
            decrypt_impl(
                key.as_ptr(),
                nonce.as_ptr(),
                std::ptr::null(),
                0,
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                recovered.as_mut_ptr(),
            )
        };
        assert_eq!(status, AEAD_AUTHENTICATION_FAILED);
        assert_eq!(recovered, [0; 16]);
    }

    #[test]
    fn c_abi_rejects_missing_required_pointers() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut ciphertext = [0u8; 1];
        let mut tag = [0u8; 16];
        let status = unsafe {
            aes256_gcm_encrypt(
                key.as_ptr(),
                nonce.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        };
        assert_eq!(status, AEAD_NULL_POINTER);
    }
}
