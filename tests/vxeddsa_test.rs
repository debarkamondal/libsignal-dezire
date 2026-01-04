// Tests for VXEdDSA signing and verification using native Rust API
use libsignal_dezire::vxeddsa::{gen_pubkey, gen_secret, vxeddsa_sign, vxeddsa_verify};

#[test]
fn test_sign_and_verify_success() {
    // 1. Setup Keys using native API
    let seed_k = gen_secret();
    let msg_bytes = gen_secret(); // Random 32-byte message

    // 2. Derive Public Key (u) for verification
    let public_u = gen_pubkey(&seed_k);

    // 3. Sign using native API (returns Result<VXEdDSAOutput, ()>)
    let output = vxeddsa_sign(&seed_k, &msg_bytes).expect("Signing failed");

    let signature = output.signature;
    let v_generated = output.vrf;

    // 4. Verify using native API (returns Option<[u8; 32]>)
    let v_verified_out = vxeddsa_verify(&public_u, &msg_bytes, &signature);

    // 5. Assertions
    assert!(
        v_verified_out.is_some(),
        "Verification failed for valid signature"
    );
    assert_eq!(
        v_verified_out.unwrap(),
        v_generated,
        "VRF output from verification does not match signing output"
    );
}

#[test]
fn test_verify_fails_on_wrong_message() {
    let seed_k = gen_secret();
    let msg_bytes = gen_secret();
    let public_u = gen_pubkey(&seed_k);

    let output = vxeddsa_sign(&seed_k, &msg_bytes).expect("Signing failed");
    let signature = output.signature;

    // Create a different message
    let mut wrong_msg = msg_bytes;
    wrong_msg[0] ^= 0xFF;

    let result = vxeddsa_verify(&public_u, &wrong_msg, &signature);
    assert!(
        result.is_none(),
        "Verification should fail for modified message"
    );
}

#[test]
fn test_verify_fails_on_wrong_key() {
    let seed_k = gen_secret();
    let msg_bytes = gen_secret();

    let output = vxeddsa_sign(&seed_k, &msg_bytes).expect("Signing failed");
    let signature = output.signature;

    // Use a completely different key for verification
    let wrong_seed = gen_secret();
    let wrong_public_u = gen_pubkey(&wrong_seed);

    let result = vxeddsa_verify(&wrong_public_u, &msg_bytes, &signature);
    assert!(
        result.is_none(),
        "Verification should fail for wrong public key"
    );
}

#[test]
fn test_verify_fails_on_corrupted_signature() {
    let seed_k = gen_secret();
    let msg_bytes = gen_secret();
    let public_u = gen_pubkey(&seed_k);

    let output = vxeddsa_sign(&seed_k, &msg_bytes).expect("Signing failed");
    let original_sig = output.signature;

    // Corrupt the V part (first 32 bytes)
    let mut sig_corrupt_v = original_sig;
    sig_corrupt_v[0] ^= 0xFF;
    assert!(
        vxeddsa_verify(&public_u, &msg_bytes, &sig_corrupt_v).is_none(),
        "Verification should fail for corrupted V"
    );

    // Corrupt the h part (middle 32 bytes)
    let mut sig_corrupt_h = original_sig;
    sig_corrupt_h[35] ^= 0xFF;
    assert!(
        vxeddsa_verify(&public_u, &msg_bytes, &sig_corrupt_h).is_none(),
        "Verification should fail for corrupted h"
    );

    // Corrupt the s part (last 32 bytes)
    let mut sig_corrupt_s = original_sig;
    sig_corrupt_s[90] ^= 0xFF;
    assert!(
        vxeddsa_verify(&public_u, &msg_bytes, &sig_corrupt_s).is_none(),
        "Verification should fail for corrupted s"
    );
}
