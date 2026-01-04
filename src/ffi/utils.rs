//! FFI and JNI bindings for utility functions.
//!
//! This module provides C-compatible FFI wrappers and Android JNI bindings
//! that call the native Rust API in [`crate::utils`].

use crate::utils::encode_public_key;

// ============================================================================
// C FFI Functions (Thin wrappers with _ffi suffix)
// ============================================================================

/// Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
/// Wrapper around [`crate::utils::encode_public_key`].
///
/// # Safety
/// The caller must ensure that `out` is valid for writes of 33 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn encode_public_key_ffi(key: &[u8; 32], out: *mut u8) {
    if out.is_null() {
        return;
    }

    // Call native API
    let encoded = encode_public_key(key);

    // Copy to output buffer
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), out, 33);
    }
}

// ============================================================================
// JNI Bindings (Android Only)
// ============================================================================

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::JByteArray;
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jclass};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_encodePublicKey(
    mut env: JNIEnv,
    _class: jclass,
    key_byte_array: jbyteArray,
) -> jbyteArray {
    let key_obj = unsafe { JByteArray::from_raw(key_byte_array) };
    let key = match env.convert_byte_array(&key_obj) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };

    if key.len() != 32 {
        return std::ptr::null_mut();
    }

    let key_arr: [u8; 32] = match key.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };

    // Call native API directly
    let encoded = encode_public_key(&key_arr);

    create_byte_array(&mut env, &encoded).unwrap_or(std::ptr::null_mut())
}
