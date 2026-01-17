use libsignal_dezire::{
    ratchet::{decrypt, encrypt, init_receiver_state, init_sender_state},
    utils::encode_public_key,
    vxeddsa::{gen_keypair, vxeddsa_sign, vxeddsa_verify},
    x3dh::{OneTimePreKey, PreKeyBundle, SignedPreKey, x3dh_initiator, x3dh_responder},
};

use x25519_dalek::{PublicKey, StaticSecret};

/// Simulates the wire format of a Signal "Initial Message"
///
/// Contains:
/// 1. Unencrypted X3DH public keys and IDs (so Bob can reconstruct the shared secret)
/// 2. Encrypted Double Ratchet Header
/// 3. Encrypted Payload
struct SignalInitialMessage {
    // --- Unencrypted X3DH "Ingredients" ---
    pub sender_identity_key: [u8; 32],  // IK_A
    pub sender_ephemeral_key: [u8; 32], // EK_A
    pub prekey_id: u32,
    pub onetime_prekey_id: Option<u32>,

    // --- Encrypted Double Ratchet Parts ---
    pub header: Vec<u8>,     // Encrypted Header
    pub ciphertext: Vec<u8>, // Encrypted Payload
}

#[test]
fn test_e2e_signal_initial_message_flow() {
    // =========================================================================
    // PART 1: PRE-HANDSHAKE SETUP (Server / Bob publish)
    // =========================================================================

    // 1. Setup Bob's Identity (IK_B)
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = bob_identity_keypair.public;

    // 2. Bob's Signed Prekey (SPK_B)
    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = bob_spk_keypair.public;
    let bob_spk_id = 1;

    // Sign SPK
    let encoded_spk = encode_public_key(&bob_spk_public);
    let sig_output = vxeddsa_sign(&bob_identity_private, &encoded_spk).expect("Signing failed");
    let spk_sig = sig_output.signature;

    // 3. Bob's One-Time Prekey (OPK_B)
    let bob_opk_keypair = gen_keypair();
    let bob_opk_private = bob_opk_keypair.secret;
    let bob_opk_public = bob_opk_keypair.public;
    let bob_opk_id = 1;

    // 4. Bob "Uploads" Bundle to Server
    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: bob_spk_id,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: Some(OneTimePreKey {
            id: bob_opk_id,
            public_key: bob_opk_public,
        }),
    };

    // =========================================================================
    // PART 2: SENDING INITIAL MESSAGE (Alice / Client A)
    // =========================================================================

    // 1. Setup Alice's Identity
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    // Alice's public identity key will be sent in the clear

    // 1b. Alice verifies Bob's Signed PreKey Signature
    let encoded_spk_verify = encode_public_key(&bundle.signed_prekey.public_key);
    vxeddsa_verify(
        &bundle.identity_key,
        &encoded_spk_verify,
        &bundle.signed_prekey.signature,
    )
    .expect("Bob's SPK signature verification failed!");

    // 2. Alice runs X3DH Initiator
    // This generates her Ephemeral Key (EK_A) and the Shared Secret (SK)
    let alice_result =
        x3dh_initiator(&alice_identity_private, &bundle).expect("Alice X3DH initiation failed");

    let alice_sk = alice_result.shared_secret;

    // 3. Alice initializes her Ratchet Session
    // Note: Header keys are now derived internally from the shared secret using HKDF
    // The init function uses proper context separation per Signal spec
    let bob_initial_ratchet_key = PublicKey::from(bob_spk_public);

    let mut alice_ratchet = init_sender_state(alice_sk, bob_initial_ratchet_key).unwrap();

    // 5. Construct Associated Data (consistent for entire session)
    // Format: IK_A || IK_B || session_version
    let mut session_ad = Vec::new();
    session_ad.extend_from_slice(&alice_identity_keypair.public); // IK_A
    session_ad.extend_from_slice(&bob_identity_public); // IK_B
    session_ad.extend_from_slice(b"v1"); // Version/Context

    // 6. Alice Encrypts Initial Message
    let msg_plaintext = b"Hello Bob! This is an initial message.";
    let (enc_header, ciphertext) =
        encrypt(&mut alice_ratchet, msg_plaintext, &session_ad).expect("Alice encrypt failed");

    // 7. Alice CONSTRUCTS the Wire Message
    let initial_message = SignalInitialMessage {
        sender_identity_key: alice_identity_keypair.public,
        sender_ephemeral_key: alice_result.ephemeral_public,
        prekey_id: bob_spk_id,
        onetime_prekey_id: Some(bob_opk_id),
        header: enc_header,
        ciphertext: ciphertext,
    };

    // NETWORK TRANSMISSION ---> (Message sent to Bob)

    // =========================================================================
    // PART 3: RECEIVING INITIAL MESSAGE (Bob / Client B)
    // =========================================================================

    // 1. Bob receives the `initial_message` struct.
    // He uses the IDs to look up his keys (simulated check)
    assert_eq!(initial_message.prekey_id, bob_spk_id);
    assert_eq!(initial_message.onetime_prekey_id, Some(bob_opk_id));

    // 2. Bob runs X3DH Responder
    let bob_sk = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        Some(&bob_opk_private),
        &initial_message.sender_identity_key,
        &initial_message.sender_ephemeral_key,
    )
    .expect("Bob X3DH response failed");

    // VERIFY: The shared secrets must match exactly
    assert_eq!(
        alice_sk, bob_sk,
        "Shared secrets derived from X3DH do not match!"
    );

    // 3. Bob initializes his Ratchet Session
    // Note: Header keys are now derived internally from the shared secret using HKDF
    let bob_initial_ratchet_pair = (
        StaticSecret::from(bob_spk_private),
        PublicKey::from(bob_spk_public),
    );

    let mut bob_ratchet = init_receiver_state(bob_sk, bob_initial_ratchet_pair);

    // 4. Bob Decrypts the Initial Message
    let decrypted_plaintext = decrypt(
        &mut bob_ratchet,
        &initial_message.header,
        &initial_message.ciphertext,
        &session_ad,
    )
    .expect("Bob failed to decrypt initial message");

    assert_eq!(decrypted_plaintext, msg_plaintext);

    // =========================================================================
    // PART 4: MULTI-ROUND CONVERSATION (Real-world scenario)
    // =========================================================================

    // Bob replies (triggers DH ratchet)
    let reply1 = b"Hi Alice! Channel established.";
    let (reply1_header, reply1_cipher) =
        encrypt(&mut bob_ratchet, reply1, &session_ad).expect("Bob reply 1 failed");

    // Alice decrypts Bob's reply
    let reply1_decrypted = decrypt(
        &mut alice_ratchet,
        &reply1_header,
        &reply1_cipher,
        &session_ad,
    )
    .expect("Alice decrypt reply 1 failed");
    assert_eq!(reply1_decrypted, reply1);

    // Alice sends another message
    let alice_msg2 = b"Great! How are you?";
    let (alice2_header, alice2_cipher) =
        encrypt(&mut alice_ratchet, alice_msg2, &session_ad).expect("Alice msg 2 failed");

    // Bob decrypts
    let alice2_decrypted = decrypt(
        &mut bob_ratchet,
        &alice2_header,
        &alice2_cipher,
        &session_ad,
    )
    .expect("Bob decrypt alice 2 failed");
    assert_eq!(alice2_decrypted, alice_msg2);

    // Bob sends multiple messages in a row (same sending chain)
    let bob_msg2 = b"I'm doing well!";
    let (bob2_header, bob2_cipher) =
        encrypt(&mut bob_ratchet, bob_msg2, &session_ad).expect("Bob msg 2 failed");

    let bob_msg3 = b"Thanks for asking.";
    let (bob3_header, bob3_cipher) =
        encrypt(&mut bob_ratchet, bob_msg3, &session_ad).expect("Bob msg 3 failed");

    // =========================================================================
    // PART 5: OUT-OF-ORDER MESSAGE DELIVERY (Real-world scenario)
    // =========================================================================

    // Simulate network reordering: Alice receives bob_msg3 BEFORE bob_msg2
    // This should trigger skipped message key storage

    // Alice receives bob_msg3 first (message #3)
    let bob3_decrypted = decrypt(&mut alice_ratchet, &bob3_header, &bob3_cipher, &session_ad)
        .expect("Alice decrypt bob 3 (out of order) failed");
    assert_eq!(bob3_decrypted, bob_msg3);

    // Alice receives bob_msg2 later (message #2, which was skipped)
    let bob2_decrypted = decrypt(&mut alice_ratchet, &bob2_header, &bob2_cipher, &session_ad)
        .expect("Alice decrypt bob 2 (delayed) failed");
    assert_eq!(bob2_decrypted, bob_msg2);

    // =========================================================================
    // PART 6: DUPLICATE MESSAGE DETECTION (Real-world scenario)
    // =========================================================================

    // Try to decrypt bob_msg2 again (should fail - already processed)
    let duplicate_result = decrypt(&mut alice_ratchet, &bob2_header, &bob2_cipher, &session_ad);
    assert!(
        duplicate_result.is_err(),
        "Duplicate message should be rejected"
    );

    println!("✅ All real-world scenario tests passed!");
    println!("   - Initial X3DH handshake");
    println!("   - Multi-round conversation with DH ratchet steps");
    println!("   - Out-of-order message delivery");
    println!("   - Skipped message handling");
    println!("   - Duplicate message detection");
    println!("   - Consistent associated data usage");
}
