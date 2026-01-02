use libsignal_dezire::ratchet::DoubleRatchet;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_ratchet_integration_basic_flow() {
    let sk = [0x55u8; 32]; // Shared secret

    // 1. Setup Alice and Bob
    let mut rng = OsRng;
    let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
    let bob_dh_public = PublicKey::from(&bob_dh_private);

    // Header encryption keys (shared between Alice and Bob)
    let shared_hka = [0xAAu8; 32];
    let shared_nhkb = [0xBBu8; 32];

    let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
    let mut bob =
        DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

    // 2. Alice sends message 1 to Bob
    let msg1 = b"Hello Bob!";
    let ad1 = b"Metadata";
    let (head1, cipher1) = alice.ratchet_encrypt(msg1, ad1).expect("encrypt 1");

    let decrypted1 = bob
        .ratchet_decrypt(&head1, &cipher1, ad1)
        .expect("Bob decrypts msg1");
    assert_eq!(decrypted1, msg1);

    // 3. Bob sends message 1 to Alice (Reply)
    let msg2 = b"Hello Alice!";
    let ad2 = b"More Metadata";
    let (head2, cipher2) = bob.ratchet_encrypt(msg2, ad2).expect("encrypt 2");

    let decrypted2 = alice
        .ratchet_decrypt(&head2, &cipher2, ad2)
        .expect("Alice decrypts msg2");
    assert_eq!(decrypted2, msg2);

    // 4. Alice sends message 2
    let msg3 = b"How are you?";
    let (head3, cipher3) = alice.ratchet_encrypt(msg3, &[]).expect("encrypt 3");
    let decrypted3 = bob
        .ratchet_decrypt(&head3, &cipher3, &[])
        .expect("Bob decrypts msg3");
    assert_eq!(decrypted3, msg3);
}

#[test]
fn test_ratchet_integration_out_of_order() {
    let sk = [0x66u8; 32];
    let mut rng = OsRng;
    let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
    let bob_dh_public = PublicKey::from(&bob_dh_private);

    // Header encryption keys (shared between Alice and Bob)
    let shared_hka = [0xAAu8; 32];
    let shared_nhkb = [0xBBu8; 32];

    let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
    let mut bob =
        DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

    // Alice sends 3 messages
    let (h1, c1) = alice.ratchet_encrypt(b"M1", &[]).expect("encrypt 1");
    let (h2, c2) = alice.ratchet_encrypt(b"M2", &[]).expect("encrypt 2");
    let (h3, c3) = alice.ratchet_encrypt(b"M3", &[]).expect("encrypt 3");

    // Bob receives 2, then 3, then 1 (Skipped handling)
    // Recv M2
    // Should skip M1.
    let d2 = bob.ratchet_decrypt(&h2, &c2, &[]).expect("Decrypt M2");
    assert_eq!(d2, b"M2");

    // Recv M3
    // Should use chain key
    let d3 = bob.ratchet_decrypt(&h3, &c3, &[]).expect("Decrypt M3");
    assert_eq!(d3, b"M3");

    // Recv M1
    // Should check mkskipped
    let d1 = bob
        .ratchet_decrypt(&h1, &c1, &[])
        .expect("Decrypt M1 from buffer");
    assert_eq!(d1, b"M1");
}
