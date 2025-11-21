use sha2::{Digest, Sha512};

/// Implements an abstraction over standard hashing function
///
///
/// # Arguments
///
/// * `x` - The 32-byte input message (or key).
///
/// # Returns
///
/// A 64-byte array containing the SHA-512 digest.
pub fn hash(x: &[u8]) -> [u8; 64] {
    Sha512::digest(x).into()
}


/// Implements the domain-separated hashing function 'hashi'.
///
/// It calculates `H( ((2^b - 1) - i) || X )`.
///
/// # Arguments
///
/// * `i` - The domain index (assumed to be small, e.g., 0, 1, 2).
/// * `x` - The 32-byte input message (or key).
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
