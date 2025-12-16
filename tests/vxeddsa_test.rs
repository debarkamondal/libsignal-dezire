use rand_core::{OsRng, RngCore};

// Replace 'vxeddsa_rust' with the actual name of your crate defined in Cargo.toml
use libsignal_dezire::{
    utils::calculate_key_pair,
    vxeddsa::{vxeddsa_sign, vxeddsa_verify},
};

/// Helper to generate a random 32-byte array using rand_core::OsRng
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Helper to derive the X25519 public key (u-coordinate) from a seed.
/// This mimics what a client would hold as their "Public Identity".
fn derive_public_u(seed: [u8; 32]) -> [u8; 32] {
    // 1. Calculate Edwards Key Pair (Canonical)
    let (_, public_edwards) = calculate_key_pair(seed);

    // 2. Convert to Montgomery (X25519) form
    let public_montgomery = public_edwards.to_montgomery();

    // 3. Return bytes (u-coordinate)
    public_montgomery.to_bytes()
}

#[test]
fn test_sign_and_verify_success() {
    // 1. Setup Keys and Context
    let seed_k = random_bytes(); // Private Key Seed
    // let nonce_z = random_bytes(); // Random Context (Internal now)

    // The sign function expects a fixed [u8; 32] for the message (usually a hash)
    let msg_bytes = random_bytes();

    // 2. Derive Public Key (u) for verification later
    let public_u = derive_public_u(seed_k);

    // 3. Sign
    let (signature, v_generated) = vxeddsa_sign(seed_k, &msg_bytes);

    // 4. Verify
    let v_verified = vxeddsa_verify(public_u, &msg_bytes, &signature);

    // 5. Assertions
    assert!(
        v_verified.is_some(),
        "Verification failed for valid signature"
    );
    assert_eq!(
        v_verified.unwrap(),
        v_generated,
        "VRF output from verification does not match signing output"
    );
}

#[test]
fn test_verify_fails_on_wrong_message() {
    let seed_k = random_bytes();

    let msg_bytes = random_bytes();
    let public_u = derive_public_u(seed_k);

    let (signature, _) = vxeddsa_sign(seed_k, &msg_bytes);

    // Create a different message
    let mut wrong_msg = msg_bytes;
    wrong_msg[0] ^= 0xFF; // Flip bits in the first byte

    let result = vxeddsa_verify(public_u, &wrong_msg, &signature);

    assert!(
        result.is_none(),
        "Verification should fail for modified message"
    );
}

#[test]
fn test_verify_fails_on_wrong_key() {
    let seed_k = random_bytes();

    let msg_bytes = random_bytes();

    let (signature, _) = vxeddsa_sign(seed_k, &msg_bytes);

    // Use a completely different key for verification
    let wrong_seed = random_bytes();
    let wrong_public_u = derive_public_u(wrong_seed);

    let result = vxeddsa_verify(wrong_public_u, &msg_bytes, &signature);

    assert!(
        result.is_none(),
        "Verification should fail for wrong public key"
    );
}

#[test]
fn test_verify_fails_on_corrupted_signature() {
    let seed_k = random_bytes();

    let msg_bytes = random_bytes();
    let public_u = derive_public_u(seed_k);

    let (original_sig, _) = vxeddsa_sign(seed_k, &msg_bytes);

    // Corrupt the V part (first 32 bytes)
    let mut sig_corrupt_v = original_sig;
    sig_corrupt_v[0] ^= 0xFF;
    assert!(vxeddsa_verify(public_u, &msg_bytes, &sig_corrupt_v).is_none());

    // Corrupt the h part (middle 32 bytes)
    let mut sig_corrupt_h = original_sig;
    sig_corrupt_h[35] ^= 0xFF;
    assert!(vxeddsa_verify(public_u, &msg_bytes, &sig_corrupt_h).is_none());

    // Corrupt the s part (last 32 bytes)
    let mut sig_corrupt_s = original_sig;
    sig_corrupt_s[90] ^= 0xFF;
    assert!(vxeddsa_verify(public_u, &msg_bytes, &sig_corrupt_s).is_none());
}
