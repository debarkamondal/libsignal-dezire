// Replace 'vxeddsa_rust' with the actual name of your crate defined in Cargo.toml
use libsignal_dezire::vxeddsa::{gen_pubkey, gen_secret, vxeddsa_sign, vxeddsa_verify};

#[test]
fn test_sign_and_verify_success() {
    // 1. Setup Keys and Context
    let mut seed_k = [0u8; 32];
    gen_secret(&mut seed_k as *mut [u8; 32]);

    // The sign function expects a fixed [u8; 32] for the message (usually a hash)
    let mut msg_bytes = [0u8; 32];
    gen_secret(&mut msg_bytes as *mut [u8; 32]);

    // 2. Derive Public Key (u) for verification later
    let mut public_u = [0u8; 32];
    gen_pubkey(&seed_k, &mut public_u as *mut [u8; 32]);

    // 3. Sign (nonce is now generated internally)
    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };

    let status = vxeddsa_sign(&seed_k, msg_bytes.as_ptr(), msg_bytes.len(), &mut output);
    assert_eq!(status, 0, "Signing failed");

    let signature = output.signature;
    let v_generated = output.vrf;

    // 4. Verify
    let mut v_verified_out = [0u8; 32];
    let valid = vxeddsa_verify(
        &public_u,
        msg_bytes.as_ptr(),
        msg_bytes.len(),
        &signature,
        &mut v_verified_out as *mut [u8; 32],
    );

    // 5. Assertions
    assert!(valid, "Verification failed for valid signature");
    assert_eq!(
        v_verified_out, v_generated,
        "VRF output from verification does not match signing output"
    );
}

#[test]
fn test_verify_fails_on_wrong_message() {
    let mut seed_k = [0u8; 32];
    gen_secret(&mut seed_k as *mut [u8; 32]);

    let mut msg_bytes = [0u8; 32];
    gen_secret(&mut msg_bytes as *mut [u8; 32]);

    let mut public_u = [0u8; 32];
    gen_pubkey(&seed_k, &mut public_u as *mut [u8; 32]);

    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(&seed_k, msg_bytes.as_ptr(), msg_bytes.len(), &mut output);
    let signature = output.signature;

    // Create a different message
    let mut wrong_msg = msg_bytes;
    wrong_msg[0] ^= 0xFF; // Flip bits in the first byte

    let mut v_out = [0u8; 32];
    let result = vxeddsa_verify(
        &public_u,
        wrong_msg.as_ptr(),
        wrong_msg.len(),
        &signature,
        &mut v_out as *mut [u8; 32],
    );

    assert!(!result, "Verification should fail for modified message");
}

#[test]
fn test_verify_fails_on_wrong_key() {
    let mut seed_k = [0u8; 32];
    gen_secret(&mut seed_k as *mut [u8; 32]);

    let mut msg_bytes = [0u8; 32];
    gen_secret(&mut msg_bytes as *mut [u8; 32]);

    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(&seed_k, msg_bytes.as_ptr(), msg_bytes.len(), &mut output);
    let signature = output.signature;

    // Use a completely different key for verification
    let mut wrong_seed = [0u8; 32];
    gen_secret(&mut wrong_seed as *mut [u8; 32]);

    let mut wrong_public_u = [0u8; 32];
    gen_pubkey(&wrong_seed, &mut wrong_public_u as *mut [u8; 32]);

    let mut v_out = [0u8; 32];
    let result = vxeddsa_verify(
        &wrong_public_u,
        msg_bytes.as_ptr(),
        msg_bytes.len(),
        &signature,
        &mut v_out as *mut [u8; 32],
    );

    assert!(!result, "Verification should fail for wrong public key");
}

#[test]
fn test_verify_fails_on_corrupted_signature() {
    let mut seed_k = [0u8; 32];
    gen_secret(&mut seed_k as *mut [u8; 32]);

    let mut msg_bytes = [0u8; 32];
    gen_secret(&mut msg_bytes as *mut [u8; 32]);

    let mut public_u = [0u8; 32];
    gen_pubkey(&seed_k, &mut public_u as *mut [u8; 32]);

    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(&seed_k, msg_bytes.as_ptr(), msg_bytes.len(), &mut output);
    let original_sig = output.signature;

    // Corrupt the V part (first 32 bytes)
    let mut sig_corrupt_v = original_sig;
    sig_corrupt_v[0] ^= 0xFF;
    let mut v_out = [0u8; 32];
    assert!(!vxeddsa_verify(
        &public_u,
        msg_bytes.as_ptr(),
        msg_bytes.len(),
        &sig_corrupt_v,
        &mut v_out as *mut [u8; 32]
    ));

    // Corrupt the h part (middle 32 bytes)
    let mut sig_corrupt_h = original_sig;
    sig_corrupt_h[35] ^= 0xFF;
    assert!(!vxeddsa_verify(
        &public_u,
        msg_bytes.as_ptr(),
        msg_bytes.len(),
        &sig_corrupt_h,
        &mut v_out as *mut [u8; 32]
    ));

    // Corrupt the s part (last 32 bytes)
    let mut sig_corrupt_s = original_sig;
    sig_corrupt_s[90] ^= 0xFF;
    assert!(!vxeddsa_verify(
        &public_u,
        msg_bytes.as_ptr(),
        msg_bytes.len(),
        &sig_corrupt_s,
        &mut v_out as *mut [u8; 32]
    ));
}
