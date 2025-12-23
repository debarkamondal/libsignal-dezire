use crate::vxeddsa::{VXEdDSAOutput, vxeddsa_sign, vxeddsa_verify};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

/// Error types for Ratchet operations
#[derive(Debug, PartialEq)]
pub enum RatchetError {
    InvalidSignature,
    InvalidKey,
    DecryptionFailed,
    OldMessageKeysLimitReached,
    DuplicateMessage,
    InvalidHeader,
}

// ----------------------------------------------------------------------------
// Constants and Configuration
// ----------------------------------------------------------------------------

const MAX_SKIP: u32 = 1000;
const HKDF_INFO_ROOT: &[u8] = b"Signal-DoubleRatchet-Root";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

pub type DhPublicKey = PublicKey;
pub type DhPrivateKey = StaticSecret;
pub type KeyPair = (DhPrivateKey, DhPublicKey);

/// The Header sent with every message
#[derive(Clone, Debug, PartialEq)]
pub struct RatchetHeader {
    pub dh_pub: DhPublicKey,
    pub pn: u32,
    pub n: u32,
    pub signature: [u8; 96], // VXEdDSA Signature
}

impl RatchetHeader {
    /// Serializes the header components that need to be signed.
    /// Format: [dh_pub (32)] || [pn (4, be)] || [n (4, be)]
    pub fn to_bytes_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 4);
        bytes.extend_from_slice(self.dh_pub.as_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes
    }

    /// Serializes the full header to a byte vector.
    /// Format: [dh_pub (32)] || [pn (4, be)] || [n (4, be)] || [signature (96)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 4 + 96);
        bytes.extend_from_slice(self.dh_pub.as_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Deserializes the header from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() < 40 + 96 {
            return Err(RatchetError::InvalidHeader); // Minimum valid length
        }
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);
        let dh_pub = PublicKey::from(dh_bytes);

        let mut pn_bytes = [0u8; 4];
        pn_bytes.copy_from_slice(&bytes[32..36]);
        let pn = u32::from_be_bytes(pn_bytes);

        let mut n_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[36..40]);
        let n = u32::from_be_bytes(n_bytes);

        let mut signature = [0u8; 96];
        signature.copy_from_slice(&bytes[40..136]);

        Ok(RatchetHeader {
            dh_pub,
            pn,
            n,
            signature,
        })
    }
}

// ----------------------------------------------------------------------------
// Core Structures
// ----------------------------------------------------------------------------

/// The Double Ratchet Session
pub struct DoubleRatchet {
    // Diffie-Hellman Ratchet
    dh_pair: KeyPair,
    dh_remote: Option<DhPublicKey>,

    // Identity Keys for Signing
    self_identity_key: [u8; 32],
    remote_identity_public_key: [u8; 32],

    // Root Chain
    rk: [u8; 32],

    // Symmetric-Key Ratchets
    ck_s: Option<[u8; 32]>,
    ck_r: Option<[u8; 32]>,

    // State
    ns: u32,
    nr: u32,
    pn: u32,

    // Skipped Message Keys
    mkskipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl DoubleRatchet {
    /// Initialize Alice's session
    pub fn new_alice(
        sk: [u8; 32],
        bob_dh_public_key: DhPublicKey,
        self_identity_key: [u8; 32],
        bob_identity_public_key: [u8; 32],
    ) -> Self {
        let mut rng = rand_core::OsRng;
        let dh_s = StaticSecret::random_from_rng(&mut rng);
        let dh_s_pub = PublicKey::from(&dh_s);

        let dh_out = dh_s.diffie_hellman(&bob_dh_public_key);
        let (rk, ck_s) = Self::kdf_rk(&sk, dh_out.as_bytes());

        DoubleRatchet {
            dh_pair: (dh_s, dh_s_pub),
            dh_remote: Some(bob_dh_public_key),
            self_identity_key,
            remote_identity_public_key: bob_identity_public_key,
            rk,
            ck_s: Some(ck_s),
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    /// Initialize Bob's session
    pub fn new_bob(
        sk: [u8; 32],
        bob_key_pair: KeyPair,
        self_identity_key: [u8; 32],
        alice_identity_public_key: [u8; 32],
    ) -> Self {
        DoubleRatchet {
            dh_pair: bob_key_pair,
            dh_remote: None,
            self_identity_key,
            remote_identity_public_key: alice_identity_public_key,
            rk: sk,
            ck_s: None,
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        }
    }

    /// Encrypt a message
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> (RatchetHeader, Vec<u8>) {
        let (ck_s, mk) = Self::kdf_ck(&self.ck_s.expect("Sender chain key missing"));
        self.ck_s = Some(ck_s);

        let mut header = RatchetHeader {
            dh_pub: self.dh_pair.1,
            pn: self.pn,
            n: self.ns,
            signature: [0u8; 96], // Placeholder
        };
        self.ns += 1;

        // Sign the header
        let sign_bytes = header.to_bytes_for_signing();
        let mut output = VXEdDSAOutput {
            signature: [0u8; 96],
            vrf: [0u8; 32],
        };

        // This call is slightly unsafe due to FFI design, but we are inside Rust calling Rust FFI
        vxeddsa_sign(
            &self.self_identity_key,
            sign_bytes.as_ptr(),
            sign_bytes.len(),
            &mut output,
        );
        header.signature = output.signature;

        let mut ad = Vec::with_capacity(associated_data.len() + header.to_bytes().len());
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(&header.to_bytes());

        let ciphertext = Self::encrypt(&mk, plaintext, &ad);

        (header, ciphertext)
    }

    /// Decrypt a message
    pub fn ratchet_decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Verify Signature First
        let sign_bytes = header.to_bytes_for_signing();
        let mut v_out = [0u8; 32];
        let valid = vxeddsa_verify(
            &self.remote_identity_public_key,
            sign_bytes.as_ptr(),
            sign_bytes.len(),
            &header.signature,
            &mut v_out,
        );

        if !valid {
            return Err(RatchetError::InvalidSignature);
        }

        // 1. Try skipped message keys
        if let Some(mk) = self
            .mkskipped
            .remove(&(header.dh_pub.as_bytes().clone(), header.n))
        {
            let mut ad = Vec::with_capacity(associated_data.len() + header.to_bytes().len());
            ad.extend_from_slice(associated_data);
            ad.extend_from_slice(&header.to_bytes());

            return Self::decrypt(&mk, ciphertext, &ad);
        }

        // 2. Check for DHRatchet step
        let new_dh = if let Some(current_remote) = self.dh_remote {
            current_remote != header.dh_pub
        } else {
            true
        };

        if new_dh {
            if let Some(ck_r) = self.ck_r {
                self.skip_message_keys(ck_r, self.nr, header.pn, &self.dh_remote.unwrap())?;
            }
            self.dh_ratchet(header)?;
        }

        // 3. Skip message keys in current chain
        if let Some(ck_r) = self.ck_r {
            self.skip_message_keys(ck_r, self.nr, header.n, &self.dh_remote.unwrap())?;
        }

        // 4. Decrypt
        let (new_ck_r, mk) = Self::kdf_ck(&self.ck_r.unwrap());
        self.ck_r = Some(new_ck_r);
        self.nr += 1;

        let mut ad = Vec::with_capacity(associated_data.len() + header.to_bytes().len());
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(&header.to_bytes());

        Self::decrypt(&mk, ciphertext, &ad)
    }

    fn dh_ratchet(&mut self, header: &RatchetHeader) -> Result<(), RatchetError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dh_remote = Some(header.dh_pub);

        // Root Ratchet Step 1
        let dh_out_receive = self.dh_pair.0.diffie_hellman(&header.dh_pub);
        let (new_rk, new_ck_r) = Self::kdf_rk(&self.rk, dh_out_receive.as_bytes());
        self.rk = new_rk;
        self.ck_r = Some(new_ck_r);

        // Root Ratchet Step 2
        let mut rng = rand_core::OsRng;
        let new_dh_s = StaticSecret::random_from_rng(&mut rng);
        let new_dh_s_pub = PublicKey::from(&new_dh_s);

        let dh_out_send = new_dh_s.diffie_hellman(&header.dh_pub);
        let (new_rk_2, new_ck_s) = Self::kdf_rk(&self.rk, dh_out_send.as_bytes());
        self.rk = new_rk_2;
        self.ck_s = Some(new_ck_s);

        self.dh_pair = (new_dh_s, new_dh_s_pub);

        Ok(())
    }

    fn skip_message_keys(
        &mut self,
        mut local_ck: [u8; 32],
        start_n: u32,
        until_n: u32,
        remote_dh: &DhPublicKey,
    ) -> Result<(), RatchetError> {
        if start_n + MAX_SKIP < until_n {
            return Err(RatchetError::OldMessageKeysLimitReached);
        }

        let mut curr_n = start_n;
        while curr_n < until_n {
            let (next_ck, mk) = Self::kdf_ck(&local_ck);
            local_ck = next_ck;
            self.mkskipped
                .insert((remote_dh.as_bytes().clone(), curr_n), mk);
            curr_n += 1;
        }

        self.ck_r = Some(local_ck);
        self.nr = curr_n;

        Ok(())
    }

    // ---------------- Helper Crypto Functions ----------------

    fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha512>::new(Some(rk), dh_out);
        let mut okm = [0u8; 64];
        hk.expand(HKDF_INFO_ROOT, &mut okm).expect("KDF Check");

        let mut new_rk = [0u8; 32];
        let mut new_ck = [0u8; 32];
        new_rk.copy_from_slice(&okm[0..32]);
        new_ck.copy_from_slice(&okm[32..64]);

        (new_rk, new_ck)
    }

    fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC can take any key size");
        mac.update(&[0x01]);
        let next_ck_bytes = mac.finalize().into_bytes();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC can take any key size");
        mac.update(&[0x02]);
        let mk_bytes = mac.finalize().into_bytes();

        let mut next_ck = [0u8; 32];
        let mut mk = [0u8; 32];
        next_ck.copy_from_slice(&next_ck_bytes);
        mk.copy_from_slice(&mk_bytes);

        (next_ck, mk)
    }

    fn encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(mk);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::default(); // 96-bits of zeros

        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .expect("Encryption failure")
    }

    fn decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let key = Key::<Aes256Gcm>::from_slice(mk);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::default();

        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| RatchetError::DecryptionFailed)
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vxeddsa::gen_keypair;

    #[test]
    fn test_ratchet_basic_flow_signed() {
        let sk = [0x55u8; 32];

        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let alice_id = gen_keypair();
        let bob_id = gen_keypair();

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, alice_id.secret, bob_id.public);
        let mut bob = DoubleRatchet::new_bob(
            sk,
            (bob_dh_private, bob_dh_public),
            bob_id.secret,
            alice_id.public,
        );

        let msg1 = b"Hello Bob!";
        let ad1 = b"Metadata";
        let (head1, cipher1) = alice.ratchet_encrypt(msg1, ad1);

        let decrypted1 = bob
            .ratchet_decrypt(&head1, &cipher1, ad1)
            .expect("Bob decrypts msg1");
        assert_eq!(decrypted1, msg1);

        let msg2 = b"Hello Alice!";
        let (head2, cipher2) = bob.ratchet_encrypt(msg2, &[]);

        let decrypted2 = alice
            .ratchet_decrypt(&head2, &cipher2, &[])
            .expect("Alice decrypts msg2");
        assert_eq!(decrypted2, msg2);
    }

    #[test]
    fn test_invalid_signature() {
        let sk = [0x77u8; 32];
        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let alice_id = gen_keypair();
        let bob_id = gen_keypair();

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, alice_id.secret, bob_id.public);
        let mut bob = DoubleRatchet::new_bob(
            sk,
            (bob_dh_private, bob_dh_public),
            bob_id.secret,
            alice_id.public,
        );

        let msg = b"Tampered";
        let (mut head, cipher) = alice.ratchet_encrypt(msg, &[]);

        // Tamper signature
        head.signature[0] ^= 0xFF; // Flip bits

        let err = bob.ratchet_decrypt(&head, &cipher, &[]);
        assert_eq!(err, Err(RatchetError::InvalidSignature));
    }
}
