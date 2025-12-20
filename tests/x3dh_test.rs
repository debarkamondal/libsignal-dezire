use libsignal_dezire::{
    vxeddsa::{gen_pubkey, gen_secret, vxeddsa_sign},
    x3dh::{OneTimePreKey, PreKeyBundle, SignedPreKey, X3DHError, x3dh_initiator, x3dh_responder},
};

#[test]
fn test_x3dh_success_with_opk() {
    // 1. Setup Bob's Keys
    let mut bob_identity_private = [0u8; 32];
    gen_secret(&mut bob_identity_private as *mut [u8; 32]);
    let mut bob_identity_public = [0u8; 32];
    gen_pubkey(
        &bob_identity_private,
        &mut bob_identity_public as *mut [u8; 32],
    );

    let mut bob_spk_private = [0u8; 32];
    gen_secret(&mut bob_spk_private as *mut [u8; 32]);
    let mut bob_spk_public = [0u8; 32];
    gen_pubkey(&bob_spk_private, &mut bob_spk_public as *mut [u8; 32]);

    // Sign SPK directly
    let output = vxeddsa_sign(
        &bob_identity_private,
        bob_spk_public.as_ptr(),
        bob_spk_public.len(),
    );
    let spk_sig = output.signature;

    let mut bob_opk_private = [0u8; 32];
    gen_secret(&mut bob_opk_private as *mut [u8; 32]);
    let mut bob_opk_public = [0u8; 32];
    gen_pubkey(&bob_opk_private, &mut bob_opk_public as *mut [u8; 32]);

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

    // 2. Setup Alice's Keys
    let mut alice_identity_private = [0u8; 32];
    gen_secret(&mut alice_identity_private as *mut [u8; 32]);
    let mut alice_identity_public = [0u8; 32];
    gen_pubkey(
        &alice_identity_private,
        &mut alice_identity_public as *mut [u8; 32],
    );

    // 3. Alice runs Init
    let (alice_sk, alice_ek_public) = x3dh_initiator(&alice_identity_private, &bundle).unwrap();

    // 4. Bob runs Responder
    let bob_sk = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        Some(&bob_opk_private),
        &alice_identity_public,
        &alice_ek_public,
    )
    .unwrap();

    // 5. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_x3dh_success_without_opk() {
    // 1. Setup Bob's Keys
    let mut bob_identity_private = [0u8; 32];
    gen_secret(&mut bob_identity_private as *mut [u8; 32]);
    let mut bob_identity_public = [0u8; 32];
    gen_pubkey(
        &bob_identity_private,
        &mut bob_identity_public as *mut [u8; 32],
    );

    let mut bob_spk_private = [0u8; 32];
    gen_secret(&mut bob_spk_private as *mut [u8; 32]);
    let mut bob_spk_public = [0u8; 32];
    gen_pubkey(&bob_spk_private, &mut bob_spk_public as *mut [u8; 32]);

    // Sign SPK
    let output = vxeddsa_sign(
        &bob_identity_private,
        bob_spk_public.as_ptr(),
        bob_spk_public.len(),
    );
    let spk_sig = output.signature;

    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: 1,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: None,
    };

    // 2. Setup Alice's Keys
    let mut alice_identity_private = [0u8; 32];
    gen_secret(&mut alice_identity_private as *mut [u8; 32]);
    let mut alice_identity_public = [0u8; 32];
    gen_pubkey(
        &alice_identity_private,
        &mut alice_identity_public as *mut [u8; 32],
    );

    // 3. Alice runs Init
    let (alice_sk, alice_ek_public) = x3dh_initiator(&alice_identity_private, &bundle).unwrap();

    // 4. Bob runs Responder
    let bob_sk = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        None,
        &alice_identity_public,
        &alice_ek_public,
    )
    .unwrap();

    // 5. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_invalid_signature() {
    // 1. Setup Bob's Keys
    let mut bob_identity_private = [0u8; 32];
    gen_secret(&mut bob_identity_private as *mut [u8; 32]);
    let mut bob_identity_public = [0u8; 32];
    gen_pubkey(
        &bob_identity_private,
        &mut bob_identity_public as *mut [u8; 32],
    );

    let mut bob_spk_private = [0u8; 32];
    gen_secret(&mut bob_spk_private as *mut [u8; 32]);
    let mut bob_spk_public = [0u8; 32];
    gen_pubkey(&bob_spk_private, &mut bob_spk_public as *mut [u8; 32]);

    let output = vxeddsa_sign(
        &bob_identity_private,
        bob_spk_public.as_ptr(),
        bob_spk_public.len(),
    );
    let mut spk_sig = output.signature;

    // Corrupt signature
    spk_sig[0] ^= 0xFF;

    let bundle = PreKeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: SignedPreKey {
            id: 1,
            public_key: bob_spk_public,
            signature: spk_sig,
        },
        one_time_prekey: None,
    };

    let mut alice_identity_private = [0u8; 32];
    gen_secret(&mut alice_identity_private as *mut [u8; 32]);

    let result = x3dh_initiator(&alice_identity_private, &bundle);
    assert_eq!(result, Err(X3DHError::InvalidSignature));
}
