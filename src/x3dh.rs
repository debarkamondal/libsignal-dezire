use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::vxeddsa::{gen_pubkey, gen_secret, vxeddsa_verify};

/// Represents a 32-byte X25519 Public Key.
pub type X3DHPublicKey = [u8; 32];

/// Represents a 32-byte Private Key (scalar).
pub type X3DHPrivateKey = [u8; 32];

/// Represents a Signed Prekey (Public Part).
#[derive(Clone, Debug)]
pub struct SignedPreKey {
    pub id: u32,
    pub public_key: X3DHPublicKey,
    pub signature: [u8; 96], // VXEdDSA signature is 96 bytes (64 sig + 32 vrf)
}

/// Represents a One-Time Prekey (Public Part).
#[derive(Clone, Debug)]
pub struct OneTimePreKey {
    pub id: u32,
    pub public_key: X3DHPublicKey,
}

/// Represents a PreKey Bundle that Bob publishes.
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    pub identity_key: X3DHPublicKey,
    pub signed_prekey: SignedPreKey,
    pub one_time_prekey: Option<OneTimePreKey>,
}

/// Error types for X3DH operations.
#[derive(Debug, PartialEq)]
pub enum X3DHError {
    InvalidSignature,
    InvalidKey,
    MissingOneTimeKey, // If protocol requires it but it's missing
}

/// KDF as defined in X3DH: HKDF using SHA-512 (matching VXEdDSA ecosystem).
/// Inputs: F || KM. F = 32 bytes of 0xFF (for X25519).
pub fn kdf(km: &[u8]) -> [u8; 32] {
    // F is a byte sequence containing 32 0xFF bytes if curve is X25519.
    let mut input_key_material = Vec::with_capacity(32 + km.len());
    input_key_material.extend_from_slice(&[0xFF; 32]);
    input_key_material.extend_from_slice(km);

    // HKDF-SHA512
    // Salt is zero-filled byte sequence with length equal to hash output length (64 bytes for SHA512).
    let salt = [0u8; 64];

    // Info is application specific. We'll use a default "Signal-X3DH" for now or empty.
    // The spec example says "MyProtocol". Let's use "X3DH".
    let info = b"X3DH";

    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha512>::new(Some(&salt), &input_key_material)
        .expand(info, &mut okm)
        .expect("HKDF expansion failed");
    okm
}

/// Perform Diffie-Hellman: DH(priv, pub)
fn dh(private: &X3DHPrivateKey, public_key_bytes: &X3DHPublicKey) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    let public = PublicKey::from(*public_key_bytes);
    *secret.diffie_hellman(&public).as_bytes()
}

/// Alice (Initiator) performs the X3DH key agreement.
///
/// # Arguments
/// * `identity_private` - Alice's identity private key.
/// * `bundle` - Bob's prekey bundle.
///
/// # Returns
/// * `(SharedSecret, EphemeralPublicKey)` - The calculated shared secret and Alice's ephemeral key.
pub fn x3dh_initiator(
    identity_private: &X3DHPrivateKey,
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], X3DHPublicKey), X3DHError> {
    // 1. Verify Signed PreKey Signature
    // Sig(IKB, Encode(SPKB))
    // We used to hash, but now we sign raw bytes as per user request/spec alignment
    let mut v_out = [0u8; 32];
    if !vxeddsa_verify(
        &bundle.identity_key,
        bundle.signed_prekey.public_key.as_ptr(),
        bundle.signed_prekey.public_key.len(),
        &bundle.signed_prekey.signature,
        &mut v_out as *mut [u8; 32],
    ) {
        return Err(X3DHError::InvalidSignature);
    }

    // 2. Generate Ephemeral Key EKA
    // 2. Generate Ephemeral Key EKA
    let mut ephemeral_private = [0u8; 32];
    gen_secret(&mut ephemeral_private as *mut [u8; 32]);

    let mut ephemeral_public = [0u8; 32];
    gen_pubkey(&ephemeral_private, &mut ephemeral_public as *mut [u8; 32]);

    // 3. Calculate separate DHs
    // DH1 = DH(IKA, SPKB)
    let dh1 = dh(identity_private, &bundle.signed_prekey.public_key);

    // DH2 = DH(EKA, IKB)
    let dh2 = dh(&ephemeral_private, &bundle.identity_key);

    // DH3 = DH(EKA, SPKB)
    let dh3 = dh(&ephemeral_private, &bundle.signed_prekey.public_key);

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(EKA, OPKB) if present
    if let Some(opk) = &bundle.one_time_prekey {
        let dh4 = dh(&ephemeral_private, &opk.public_key);
        chained_key_material.extend_from_slice(&dh4);
    }

    // 4. KDF(DH1 || DH2 || DH3 [|| DH4])
    let sk = kdf(&chained_key_material);

    Ok((sk, ephemeral_public))
}

/// Bob (Responder) performs the X3DH key agreement.
///
/// # Arguments
/// * `identity_private` - Bob's identity private key.
/// * `signed_prekey_private` - Bob's signed prekey private key.
/// * `one_time_prekey_private` - Bob's one-time prekey private key (optional).
/// * `alice_identity_public` - Alice's identity public key.
/// * `alice_ephemeral_public` - Alice's ephemeral public key.
///
/// # Returns
/// * `SharedSecret` - The calculated shared secret.
pub fn x3dh_responder(
    identity_private: &X3DHPrivateKey,
    signed_prekey_private: &X3DHPrivateKey,
    one_time_prekey_private: Option<&X3DHPrivateKey>,
    alice_identity_public: &X3DHPublicKey,
    alice_ephemeral_public: &X3DHPublicKey,
) -> Result<[u8; 32], X3DHError> {
    // 1. Calculate DHs

    // DH1 = DH(SPKB, IKA)  <-- Note: Role reversal requires corresponding private/public match
    // Alice calculated DH(IKA, SPKB).
    // Bob calculates DH(SPKB, IKA).
    let dh1 = dh(signed_prekey_private, alice_identity_public);

    // DH2 = DH(IKB, EKA)
    // Alice calculated DH(EKA, IKB).
    // Bob calculates DH(IKB, EKA).
    let dh2 = dh(identity_private, alice_ephemeral_public);

    // DH3 = DH(SPKB, EKA)
    // Alice calculated DH(EKA, SPKB).
    // Bob calculates DH(SPKB, EKA).
    let dh3 = dh(signed_prekey_private, alice_ephemeral_public);

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(OPKB, EKA) if OPK used
    if let Some(opk_private) = one_time_prekey_private {
        let dh4 = dh(opk_private, alice_ephemeral_public);
        chained_key_material.extend_from_slice(&dh4);
    }

    // 2. KDF
    let sk = kdf(&chained_key_material);

    Ok(sk)
}
