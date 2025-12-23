use libsignal_dezire::{
    utils::encode_public_key,
    vxeddsa::{gen_keypair, vxeddsa_sign},
    x3dh::{X3DHInitOutput, x3dh_initiator, x3dh_responder},
};

#[test]
fn test_x3dh_success_with_opk() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = bob_identity_keypair.public;

    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = bob_spk_keypair.public;

    // Sign SPK directly
    let mut encoded_spk = [0u8; 33];
    encode_public_key(&bob_spk_public, encoded_spk.as_mut_ptr());
    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(
        &bob_identity_private,
        encoded_spk.as_ptr(),
        encoded_spk.len(),
        &mut output,
    );
    let spk_sig = output.signature;

    let bob_opk_keypair = gen_keypair();
    let bob_opk_private = bob_opk_keypair.secret;
    let bob_opk_public = bob_opk_keypair.public;

    // bundle not needed for extern C calls
    // let bundle = PreKeyBundle { ... };

    // 2. Setup Alice's Keys
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    let alice_identity_public = alice_identity_keypair.public;

    // 3. Alice runs Init
    let mut output = X3DHInitOutput {
        shared_secret: [0u8; 32],
        ephemeral_public: [0u8; 32],
        status: -99,
    };

    let status = x3dh_initiator(
        &alice_identity_private,
        &bob_identity_public,
        1,
        &bob_spk_public,
        &spk_sig,
        1,
        &bob_opk_public as *const u8,
        true,
        &mut output,
    );
    assert_eq!(status, 0);

    let alice_sk = output.shared_secret;
    let alice_ek_public = output.ephemeral_public;

    // 4. Bob runs Responder
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

    assert_eq!(status, 0);

    // 5. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_x3dh_success_without_opk() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = bob_identity_keypair.public;

    let bob_spk_keypair = gen_keypair();
    let bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = bob_spk_keypair.public;

    // Sign SPK
    let mut encoded_spk = [0u8; 33];
    encode_public_key(&bob_spk_public, encoded_spk.as_mut_ptr());
    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(
        &bob_identity_private,
        encoded_spk.as_ptr(),
        encoded_spk.len(),
        &mut output,
    );
    let spk_sig = output.signature;

    // bundle not needed for extern C calls

    // 2. Setup Alice's Keys
    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;
    let alice_identity_public = alice_identity_keypair.public;

    // 3. Alice runs Init
    let mut output = X3DHInitOutput {
        shared_secret: [0u8; 32],
        ephemeral_public: [0u8; 32],
        status: -99,
    };
    let status = x3dh_initiator(
        &alice_identity_private,
        &bob_identity_public,
        1,
        &bob_spk_public,
        &spk_sig,
        0,
        std::ptr::null(),
        false,
        &mut output,
    );
    assert_eq!(status, 0);

    let alice_sk = output.shared_secret;
    let alice_ek_public = output.ephemeral_public;

    // 4. Bob runs Responder
    let mut bob_sk = [0u8; 32];
    let status = x3dh_responder(
        &bob_identity_private,
        &bob_spk_private,
        std::ptr::null(),
        false,
        &alice_identity_public,
        &alice_ek_public,
        &mut bob_sk as *mut [u8; 32],
    );
    assert_eq!(status, 0);

    // 5. Assert Shared Secrets Match
    assert_eq!(alice_sk, bob_sk);
}

#[test]
fn test_invalid_signature() {
    // 1. Setup Bob's Keys
    let bob_identity_keypair = gen_keypair();
    let bob_identity_private = bob_identity_keypair.secret;
    let bob_identity_public = bob_identity_keypair.public;

    let bob_spk_keypair = gen_keypair();
    let _bob_spk_private = bob_spk_keypair.secret;
    let bob_spk_public = bob_spk_keypair.public;

    let mut encoded_spk = [0u8; 33];
    encode_public_key(&bob_spk_public, encoded_spk.as_mut_ptr());
    let mut output = libsignal_dezire::vxeddsa::VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };
    vxeddsa_sign(
        &bob_identity_private,
        encoded_spk.as_ptr(),
        encoded_spk.len(),
        &mut output,
    );
    let mut spk_sig = output.signature;

    // Corrupt signature
    spk_sig[0] ^= 0xFF;

    // bundle not needed for extern C calls

    let alice_identity_keypair = gen_keypair();
    let alice_identity_private = alice_identity_keypair.secret;

    let mut output = X3DHInitOutput {
        shared_secret: [0u8; 32],
        ephemeral_public: [0u8; 32],
        status: -99,
    };
    let status = x3dh_initiator(
        &alice_identity_private,
        &bob_identity_public,
        1,
        &bob_spk_public,
        &spk_sig,
        0,
        std::ptr::null(),
        false,
        &mut output,
    );

    assert_eq!(status, -1);
}
