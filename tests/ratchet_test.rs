use libsignal_dezire::ratchet::{decrypt, encrypt, init_receiver_state, init_sender_state};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn test_ratchet_integration_basic_flow() {
    let sk = [0x55u8; 32]; // Shared secret

    // 1. Setup Sender and Receiver
    let mut rng = OsRng;
    let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
    let receiver_dh_public = PublicKey::from(&receiver_dh_private);

    // Header encryption keys (shared between Sender and Receiver)
    
    

    let sender = init_sender_state(sk, receiver_dh_public).unwrap();
    let receiver = init_receiver_state(
        sk,
        (receiver_dh_private, receiver_dh_public),
        
        
    );

    // 2. Sender sends message 1 to Receiver
    let msg1 = b"Hello Receiver!";
    let ad1 = b"Metadata";
    let (sender, head1, cipher1) = encrypt(sender, msg1, ad1).expect("encrypt 1");

    let (receiver, decrypted1) =
        decrypt(receiver, &head1, &cipher1, ad1).expect("Receiver decrypts msg1");
    assert_eq!(decrypted1, msg1);

    // 3. Receiver sends message 1 to Sender (Reply)
    let msg2 = b"Hello Sender!";
    let ad2 = b"More Metadata";
    let (receiver, head2, cipher2) = encrypt(receiver, msg2, ad2).expect("encrypt 2");

    let (sender, decrypted2) =
        decrypt(sender, &head2, &cipher2, ad2).expect("Sender decrypts msg2");
    assert_eq!(decrypted2, msg2);

    // 4. Sender sends message 2
    let msg3 = b"How are you?";
    let (sender, head3, cipher3) = encrypt(sender, msg3, &[]).expect("encrypt 3");
    let (_receiver, decrypted3) =
        decrypt(receiver, &head3, &cipher3, &[]).expect("Receiver decrypts msg3");
    assert_eq!(decrypted3, msg3);

    // Suppress unused variable warning
    let _ = sender;
}

#[test]
fn test_ratchet_integration_out_of_order() {
    let sk = [0x66u8; 32];
    let mut rng = OsRng;
    let receiver_dh_private = StaticSecret::random_from_rng(&mut rng);
    let receiver_dh_public = PublicKey::from(&receiver_dh_private);

    // Header encryption keys (shared between Sender and Receiver)
    
    

    let sender = init_sender_state(sk, receiver_dh_public).unwrap();
    let receiver = init_receiver_state(
        sk,
        (receiver_dh_private, receiver_dh_public),
        
        
    );

    // Sender sends 3 messages
    let (sender, h1, c1) = encrypt(sender, b"M1", &[]).expect("encrypt 1");
    let (sender, h2, c2) = encrypt(sender, b"M2", &[]).expect("encrypt 2");
    let (_sender, h3, c3) = encrypt(sender, b"M3", &[]).expect("encrypt 3");

    // Receiver receives 2, then 3, then 1 (Skipped handling)
    // Recv M2
    // Should skip M1.
    let (receiver, d2) = decrypt(receiver, &h2, &c2, &[]).expect("Decrypt M2");
    assert_eq!(d2, b"M2");

    // Recv M3
    // Should use chain key
    let (receiver, d3) = decrypt(receiver, &h3, &c3, &[]).expect("Decrypt M3");
    assert_eq!(d3, b"M3");

    // Recv M1
    // Should check mkskipped
    let (_receiver, d1) = decrypt(receiver, &h1, &c1, &[]).expect("Decrypt M1 from buffer");
    assert_eq!(d1, b"M1");
}
