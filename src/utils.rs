//! Provides utility functions for cryptographic operations on Curve25519,
//! focusing on key generation and conversions between Montgomery (X25519)
//! and Edwards (Ed25519) curve forms.

use curve25519_dalek::traits::IsIdentity as _;
use curve25519_dalek::{
    EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT, montgomery::MontgomeryPoint,
};
use subtle::{Choice, ConditionallySelectable};

pub fn is_valid_public_key(pk: &[u8; 32]) -> bool {
    // Reject all-zero
    if pk.iter().all(|&b| b == 0) {
        return false;
    }

    // Convert to Edwards
    let edwards = convert_mont(*pk);

    // Check not identity
    if edwards.is_identity() {
        return false;
    }

    // Check cofactor-cleared point not identity (catches low-order)
    if edwards.mul_by_cofactor().is_identity() {
        return false;
    }

    true
}

/// Converts a Montgomery u-coordinate (X25519) to a compressed Edwards point (Ed25519).
///
/// This function is useful for converting a public key from its X25519 (key exchange)
/// form to its Ed25519 (signing) form. It attempts to decompress the Montgomery
/// point `u` to a full Edwards point.
///
/// # Arguments
///
/// * `u` - A 32-byte array representing the u-coordinate of a Montgomery point.
///
/// # Returns
///
/// A 32-byte array representing the corresponding compressed Edwards point (which
/// encodes the y-coordinate and a sign bit).
///
/// # Panics
///
/// This function will **panic** if the input `u` does not represent a valid point
/// on the Montgomery curve (i.e., not all 32-byte arrays are valid u-coordinates).
pub fn u_to_y(u: [u8; 32]) -> EdwardsPoint {
    let montgomery = MontgomeryPoint(u);
    // The sign bit (0) is chosen arbitrarily as X25519 public keys don't
    // encode a sign bit. to_edwards will recover the correct point.
    montgomery
        .to_edwards(0)
        .expect("Conversion from u-coordinate failed. Not all 32-byte arrays are valid points.")
}

/// Applies the Curve25519 "clamping" modification to a 32-byte private key.
///
/// Clamping is required for X25519 and Ed25519 private keys to ensure security
/// against small subgroup attacks.
///
/// It performs the following operations as defined in RFC 7748:
/// * `key[0] &= 248;` (clears the 3 least significant bits)
/// * `key[31] &= 127;` (clears the most significant bit)
/// * `key[31] |= 64;`  (sets the second most significant bit)
///
/// # Arguments
///
/// * `u` - A 32-byte array representing the raw private key (scalar).
///
/// # Returns
///
/// The clamped 32-byte private key.
pub fn clamp_private_key(mut u: [u8; 32]) -> [u8; 32] {
    u[0] &= 248;
    u[31] &= 127;
    u[31] |= 64;
    u
}

/// Calculates a "canonical" Ed25519 key pair from a 32-byte seed.
///
/// This function generates an Ed25519 key pair (`private_key`, `public_key`)
/// but with a specific modification: it ensures the resulting public key
/// always has a sign bit of 0.
///
/// # Arguments
///
/// * `u` - A 32-byte seed.
///
/// # Returns
///
/// A tuple `(private_key, public_key)` where:
/// * `private_key` is the `Scalar` (potentially negated to be "canonical").
/// * `public_key` is the `EdwardsPoint` corresponding to the `private_key`.
pub fn calculate_key_pair(u: [u8; 32]) -> (Scalar, EdwardsPoint) {
    let k = Scalar::from_bytes_mod_order(clamp_private_key(u));
    let ed = ED25519_BASEPOINT_POINT * k;

    // Check the sign bit of the compressed public key
    let sign = (ed.compress().to_bytes()[31] >> 7) & 1;

    // Conditionally negate the private key if the sign bit is 1
    // This ensures the resulting public key is "canonical" (has sign bit 0)
    let priv_key = Scalar::conditional_select(&k, &-k, Choice::from(sign));
    let public_key = priv_key * ED25519_BASEPOINT_POINT;

    (priv_key, public_key)
}

/// Converts a Montgomery u-coordinate to an Edwards point.
///
/// This acts as a wrapper around [`u_to_y`] but ensures the input is clamped/masked
/// correctly before conversion, specifically handling the sign bit.
///
/// # Arguments
///
/// * `u` - A 32-byte array representing the Montgomery u-coordinate.
///
/// # Returns
///
/// A `EdwardsPoint` on the Curve25519.
///
/// **Note:** The sign bit is always retrieved as 0 (matching Jivsov's approach).

pub fn convert_mont(u: [u8; 32]) -> EdwardsPoint {
    let mut u_masked = u;
    u_masked[31] &= 127;
    u_to_y(u_masked)
}

/// Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
///
/// This aligns with the Signal Protocol's `Encode(K)` specification for
/// standard X25519 public keys.
///
/// # Arguments
///
/// * `key` - The 32-byte public key.
/// * `out` - A pointer to a 33-byte buffer where the encoded key will be written.
///
/// # Safety
///
/// The caller must ensure that `out` is valid for writes of 33 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn encode_public_key(key: &[u8; 32], out: *mut u8) {
    if out.is_null() {
        return;
    }
    unsafe {
        *out = 0x05;
        std::ptr::copy_nonoverlapping(key.as_ptr(), out.add(1), 32);
    }
}

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JClass};
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

    let mut encoded = [0u8; 33];
    encode_public_key(&key_arr, encoded.as_mut_ptr());

    match create_byte_array(&mut env, &encoded) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}
