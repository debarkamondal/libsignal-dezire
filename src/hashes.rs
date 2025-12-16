use sha2::{Digest, Sha512};

/// Computes the SHA-512 hash of the input.
///
/// This is a standard cryptographic hash function wrapper.
///
/// # Arguments
///
/// * `x` - The input byte slice to be hashed.
///
/// # Returns
///
/// A 64-byte array containing the SHA-512 digest.
pub fn hash(x: &[u8]) -> [u8; 64] {
    Sha512::digest(x).into()
}

/// Computes the domain-separated hash `hashi`.
///
/// The function calculates `H( ((2^256 - 1) - i) || x )`.
/// This is used in the VXEdDSA protocol to derive various scalars and points
/// while ensuring domain separation.
///
/// # Arguments
///
/// * `i` - The domain separation index (a small integer, e.g., 0, 1, 2, 3, 4).
/// * `x` - The input byte slice.
///
/// # Returns
///
/// A 64-byte array containing the SHA-512 digest.
pub fn hashi(i: u8, x: &[u8]) -> [u8; 64] {
    // 1. Calculate the prefix: (2^256 - 1) - i
    // In Little Endian, (2^256 - 1) is [0xFF; 32].
    // Subtracting 'i' (where i is small) simply subtracts from the first byte.
    let mut prefix = [0xFFu8; 32];
    prefix[0] -= i; // e.g., 0xFF - 1 = 0xFE

    let mut hasher = Sha512::new();
    hasher.update(&prefix);
    hasher.update(x);
    hasher.finalize().into()
}
