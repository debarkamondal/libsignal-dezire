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
pub fn u_to_y(u: [u8; 32]) -> EdwardsPoint {
    let montgomery = MontgomeryPoint(u);
    montgomery
        .to_edwards(0)
        .expect("Conversion from u-coordinate failed. Not all 32-byte arrays are valid points.")
}

/// Applies the Curve25519 "clamping" modification to a 32-byte private key.
pub fn clamp_private_key(mut u: [u8; 32]) -> [u8; 32] {
    u[0] &= 248;
    u[31] &= 127;
    u[31] |= 64;
    u
}

/// Calculates a "canonical" Ed25519 key pair from a 32-byte seed.
pub fn calculate_key_pair(u: [u8; 32]) -> (Scalar, EdwardsPoint) {
    let k = Scalar::from_bytes_mod_order(clamp_private_key(u));
    let ed = ED25519_BASEPOINT_POINT * k;

    let sign = (ed.compress().to_bytes()[31] >> 7) & 1;

    let priv_key = Scalar::conditional_select(&k, &-k, Choice::from(sign));
    let public_key = priv_key * ED25519_BASEPOINT_POINT;

    (priv_key, public_key)
}

/// Converts a Montgomery u-coordinate to an Edwards point.
pub fn convert_mont(u: [u8; 32]) -> EdwardsPoint {
    let mut u_masked = u;
    u_masked[31] &= 127;
    u_to_y(u_masked)
}

/// Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
/// This is the native Rust API version.
pub fn encode_public_key(key: &[u8; 32]) -> [u8; 33] {
    let mut encoded = [0u8; 33];
    encoded[0] = 0x05;
    encoded[1..33].copy_from_slice(key);
    encoded
}
