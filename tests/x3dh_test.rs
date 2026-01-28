use libsignal_dezire::{
    utils::encode_public_key,
    vxeddsa::{gen_keypair, vxeddsa_sign},
    x3dh::{OneTimePreKey, PreKeyBundle, SignedPreKey, X3DHError, x3dh_initiator, x3dh_responder},
};

#[test]
fn test_x3dh_success_with_opk() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = encode_public_key(&bob_identity_keypair.public);

    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = encode_public_key(&bob_spk_keypair.public);

    // Sign SPK using native API
    // SPK is already encoded
    let sig_output = vxeddsa_sign(&bob_identity_private, &bob_spk_public).expect("Signing failed");
    let spk_sig = sig_output.signature;

    let bob_opk_keypair = gen_keypair();
    let bob_opk_private = bob_opk_keypair.secret;
    let bob_opk_public = encode_public_key(&bob_opk_keypair.public);

    // 2. Setup Alice's Keys
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    let alice_identity_public = encode_public_key(&alice_identity_keypair.public);

    // 3. Build PreKey Bundle
    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: 1,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: Some(OneTimePreKey {
            id: 1,
            public_key: bob_opk_public,
        }),
    };

    // 4. Alice runs X3DH Initiator
    let alice_result =
        x3dh_initiator(&alice_identity_private, &bundle).expect("Alice X3DH initiation failed");

    let alice_sk = alice_result.shared_secret;
    let alice_ek_public = alice_result.ephemeral_public;

    // 5. Bob runs X3DH Responder
    let bob_sk = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        Some(&bob_opk_private),
        &alice_identity_public,
        &alice_ek_public,
    )
    .expect("Bob X3DH response failed");

    // 6. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_x3dh_success_without_opk() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = encode_public_key(&bob_identity_keypair.public);

    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = encode_public_key(&bob_spk_keypair.public);

    // Sign SPK
    // Sign SPK
    let sig_output = vxeddsa_sign(&bob_identity_private, &bob_spk_public).expect("Signing failed");
    let spk_sig = sig_output.signature;

    // 2. Setup Alice's Keys
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    let alice_identity_public = encode_public_key(&alice_identity_keypair.public);

    // 3. Build PreKey Bundle without OPK
    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: 1,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: None,
    };

    // 4. Alice runs X3DH Initiator
    let alice_result =
        x3dh_initiator(&alice_identity_private, &bundle).expect("Alice X3DH initiation failed");

    let alice_sk = alice_result.shared_secret;
    let alice_ek_public = alice_result.ephemeral_public;

    // 5. Bob runs X3DH Responder without OPK
    let bob_sk = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        None,
        &alice_identity_public,
        &alice_ek_public,
    )
    .expect("Bob X3DH response failed");

    // 6. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_invalid_signature() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = encode_public_key(&bob_identity_keypair.public);

    let bob_spk_keypair = gen_keypair();
    let bob_spk_public = encode_public_key(&bob_spk_keypair.public);

    let sig_output = vxeddsa_sign(&bob_identity_private, &bob_spk_public).expect("Signing failed");
    let mut spk_sig = sig_output.signature;

    // Corrupt signature
    spk_sig[0] ^= 0xFF;

    // 2. Setup Alice's Keys
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;

    // 3. Build bundle with corrupted signature
    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: 1,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: None,
    };

    // 4. Alice runs X3DH - should fail with InvalidSignature
    let result = x3dh_initiator(&alice_identity_private, &bundle);
    assert_eq!(result, Err(X3DHError::InvalidSignature));
}
