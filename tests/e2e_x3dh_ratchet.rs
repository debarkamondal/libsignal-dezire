use libsignal_dezire::{
    ratchet::DoubleRatchet,
    utils::encode_public_key,
    vxeddsa::{VXEdDSAOutput, gen_keypair, vxeddsa_sign},
    x3dh::{X3DHInitOutput, x3dh_initiator, x3dh_responder},
};

use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_e2e_x3dh_double_ratchet_integration() {
    // =========================================================================
    // PART 1: X3DH Key Agreement
    // =========================================================================

    // 1. Setup Bob's Identity and Prekeys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = bob_identity_keypair.public;

    // Bob's Signed Prekey (SPK)
    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = bob_spk_keypair.public;

    // Bob signs the SPK
    let mut encoded_spk = [0u8; 33];
    encode_public_key(&bob_spk_public, encoded_spk.as_mut_ptr());
    let mut sig_output = VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(
        &bob_identity_private,
        encoded_spk.as_ptr(),
        encoded_spk.len(),
        &mut sig_output,
    );
    let spk_sig = sig_output.signature;

    // Bob's One-Time Prekey (OPK) - Optional but good for full test
    let bob_opk_keypair = gen_keypair();
    let bob_opk_private = bob_opk_keypair.secret;
    let bob_opk_public = bob_opk_keypair.public;

    // 2. Setup Alice's Identity
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    let alice_identity_public = alice_identity_keypair.public;

    // 3. Alice runs X3DH Initiator
    let mut alice_x3dh_out = X3DHInitOutput {
        shared_secret: [0u8; 32],
        ephemeral_public: [0u8; 32],
        status: -99,
    };

    let status = x3dh_initiator(
        &alice_identity_private,
        &bob_identity_public,
        1, // info string length or similar (dummy here as logic is internal?) Check usage in x3dh_test
        &bob_spk_public,
        &spk_sig,
        1, // One-Time Prekey ID/Selector
        &bob_opk_public as *const u8,
        true, // use_opk
        &mut alice_x3dh_out,
    );
    assert_eq!(status, 0, "Alice X3DH initiation failed");

    let alice_sk = alice_x3dh_out.shared_secret;
    let alice_ek_public = alice_x3dh_out.ephemeral_public;

    // 4. Bob runs X3DH Responder
    let mut bob_sk = [0u8; 32];
    let status = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        &bob_opk_private as *const u8,
        true,
        &alice_identity_public,
        &alice_ek_public,
        &mut bob_sk as *mut [u8; 32],
    );
    assert_eq!(status, 0, "Bob X3DH response failed");

    // 5. Verify Connected
    assert_eq!(alice_sk, bob_sk, "Shared secrets do not match!");

    // =========================================================================
    // PART 2: Double Ratchet Session Setup with Header Encryption
    // =========================================================================

    // Convert raw byte arrays to x25519_dalek types where needed for Ratchet API
    let bob_dh_public_obj = PublicKey::from(bob_spk_public);
    let bob_dh_private_obj = StaticSecret::from(bob_spk_private);

    // Derive header encryption keys from the shared secret
    // In a real implementation, these would be derived from X3DH using KDF
    // For this test, we'll use simple derivation
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&alice_sk);
    hasher.update(b"header-key-alice");
    let shared_hka: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(&alice_sk);
    hasher.update(b"header-key-bob");
    let shared_nhkb: [u8; 32] = hasher.finalize().into();

    // Alice Initialize
    // She needs the Shared Secret (alice_sk), Bob's SPK Public Key, and header encryption keys
    let mut alice_ratchet =
        DoubleRatchet::new_alice(alice_sk, bob_dh_public_obj, shared_hka, shared_nhkb);

    // Bob Initialize
    // He needs the Shared Secret (bob_sk), His SPK Keypair, and header encryption keys
    let mut bob_ratchet = DoubleRatchet::new_bob(
        bob_sk,
        (bob_dh_private_obj, bob_dh_public_obj),
        shared_hka,
        shared_nhkb,
    );

    // =========================================================================
    // PART 3: Encrypted Chat
    // =========================================================================

    // 1. Alice sends message to Bob
    let msg1 = b"Hello Bob! This is our secure channel.";
    let ad1 = b"metadata-1";

    let (header1, ciphertext1) = alice_ratchet.ratchet_encrypt(msg1, ad1).expect("encrypt 1");

    // Bob decrypts
    let plaintext1 = bob_ratchet
        .ratchet_decrypt(&header1, &ciphertext1, ad1)
        .expect("Bob failed to decrypt message 1");
    assert_eq!(plaintext1, msg1);

    // 2. Bob replies to Alice
    let msg2 = b"Hi Alice! Secure channel confirmed.";
    let ad2 = b"metadata-2";

    let (header2, ciphertext2) = bob_ratchet.ratchet_encrypt(msg2, ad2).expect("encrypt 2");

    // Alice decrypts
    let plaintext2 = alice_ratchet
        .ratchet_decrypt(&header2, &ciphertext2, ad2)
        .expect("Alice failed to decrypt message 2");
    assert_eq!(plaintext2, msg2);

    // 3. Exchange more messages (Ping-Pong to trigger ratchets)
    let msg3 = b"How are you doing?";
    let (header3, ciphertext3) = alice_ratchet.ratchet_encrypt(msg3, &[]).expect("encrypt 3");

    let plaintext3 = bob_ratchet
        .ratchet_decrypt(&header3, &ciphertext3, &[])
        .expect("Bob failed to decrypt message 3");
    assert_eq!(plaintext3, msg3);

    let msg4 = b"I am doing great, thanks for asking!";
    let (header4, ciphertext4) = bob_ratchet.ratchet_encrypt(msg4, &[]).expect("encrypt 4");

    let plaintext4 = alice_ratchet
        .ratchet_decrypt(&header4, &ciphertext4, &[])
        .expect("Alice failed to decrypt message 4");
    assert_eq!(plaintext4, msg4);
}
