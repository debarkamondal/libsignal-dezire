use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error types for Ratchet operations
#[derive(Debug, PartialEq)]
pub enum RatchetError {
    InvalidKey,
    DecryptionFailed,
    OldMessageKeysLimitReached,
    DuplicateMessage,
    InvalidHeader,
    HeaderDecryptionFailed,
    CounterOverflow,
    ADTooLarge,
    InvalidState,
    TooManyMessages,
}

// ----------------------------------------------------------------------------
// Constants and Configuration
// ----------------------------------------------------------------------------

const MAX_SKIP: u32 = 1000;
const MAX_SKIPPED_KEYS: usize = 2000;
const MAX_AD_SIZE: usize = 64 * 1024; // 64KB
const MAX_RECEIVED_TRACKING: usize = 10000; // Limit replay tracking (HIGH-2)
const HKDF_INFO_ROOT: &[u8] = b"Signal-DoubleRatchet-Root";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

pub type DhPublicKey = PublicKey;
pub type DhPrivateKey = StaticSecret;
pub type KeyPair = (DhPrivateKey, DhPublicKey);

/// Skipped message key with timestamp for LRU eviction
#[derive(Clone, Debug)]
struct SkippedKey {
    mk: [u8; 32],
    timestamp: std::time::Instant,
}

/// The Header sent with every message (unencrypted form)
#[derive(Clone, Debug, PartialEq)]
pub struct RatchetHeader {
    pub dh_pub: DhPublicKey,
    pub pn: u32, // Previous chain length
    pub n: u32,  // Message number in current chain
}

impl RatchetHeader {
    /// Serializes the header to a byte vector.
    /// Format: [dh_pub (32)] || [pn (4, be)] || [n (4, be)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 4 + 4);
        bytes.extend_from_slice(self.dh_pub.as_bytes());
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes
    }

    /// Deserializes the header from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RatchetError> {
        if bytes.len() != 32 + 4 + 4 {
            return Err(RatchetError::InvalidHeader);
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

        Ok(RatchetHeader { dh_pub, pn, n })
    }
}

// ----------------------------------------------------------------------------
// Core Structures
// ----------------------------------------------------------------------------

/// The Double Ratchet Session with Header Encryption
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchet {
    // Diffie-Hellman Ratchet
    #[zeroize(skip)]
    dh_pair: KeyPair,
    #[zeroize(skip)]
    dh_remote: Option<DhPublicKey>,

    // Root Chain
    rk: [u8; 32],

    // Symmetric-Key Ratchets
    ck_s: Option<[u8; 32]>,
    ck_r: Option<[u8; 32]>,

    // Header Encryption Keys
    hk_s: Option<[u8; 32]>, // Sending header key
    hk_r: Option<[u8; 32]>, // Receiving header key
    nhk_s: [u8; 32],        // Next sending header key
    nhk_r: [u8; 32],        // Next receiving header key

    // State
    #[zeroize(skip)]
    ns: u32, // Sending chain message number
    #[zeroize(skip)]
    nr: u32, // Receiving chain message number
    #[zeroize(skip)]
    pn: u32, // Previous sending chain length

    // Skipped Message Keys: (HeaderKey, message_number) -> SkippedKey
    // Note: We store the header key instead of DH public key for proper header encryption
    #[zeroize(skip)]
    mkskipped: HashMap<([u8; 32], u32), SkippedKey>,

    // Nonce counter for header encryption (stateful, per-session)
    #[zeroize(skip)]
    header_nonce_counter: u64,

    // Party identifier for nonce uniqueness (CRITICAL-1 fix)
    #[zeroize(skip)]
    is_alice: bool,

    // Received message tracking for replay attack prevention (CRITICAL-3 fix)
    #[zeroize(skip)]
    received_messages: std::collections::HashSet<([u8; 32], u32)>,
}

impl DoubleRatchet {
    /// Initialize Alice's session with header encryption
    pub fn new_alice(
        sk: [u8; 32],
        bob_dh_public_key: DhPublicKey,
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> Self {
        let mut rng = rand_core::OsRng;
        let dh_s = StaticSecret::random_from_rng(&mut rng);
        let dh_s_pub = PublicKey::from(&dh_s);

        let dh_out = dh_s.diffie_hellman(&bob_dh_public_key);
        let (rk, ck_s, nhk_s) = Self::kdf_rk_he(&sk, dh_out.as_bytes());

        DoubleRatchet {
            dh_pair: (dh_s, dh_s_pub),
            dh_remote: Some(bob_dh_public_key),
            rk,
            ck_s: Some(ck_s),
            ck_r: None,
            hk_s: Some(shared_hka),
            hk_r: None,
            nhk_s,
            nhk_r: shared_nhkb,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            header_nonce_counter: 0,
            is_alice: true,
            received_messages: std::collections::HashSet::new(),
        }
    }

    /// Initialize Bob's session with header encryption
    pub fn new_bob(
        sk: [u8; 32],
        bob_key_pair: KeyPair,
        shared_hka: [u8; 32],
        shared_nhkb: [u8; 32],
    ) -> Self {
        DoubleRatchet {
            dh_pair: bob_key_pair,
            dh_remote: None,
            rk: sk,
            ck_s: None,
            ck_r: None,
            hk_s: None,
            hk_r: None,
            nhk_s: shared_nhkb,
            nhk_r: shared_hka,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
            header_nonce_counter: 0,
            is_alice: false,
            received_messages: std::collections::HashSet::new(),
        }
    }

    /// Encrypt a message with header encryption
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), RatchetError> {
        // Validate state before encryption (MEDIUM-2 fix)
        self.validate_encryption_state()?;

        // Validate input sizes (LOW-1 fix)
        if associated_data.len() > MAX_AD_SIZE {
            return Err(RatchetError::ADTooLarge);
        }

        // Derive message key
        let (ck_s, mut mk) = Self::kdf_ck(&self.ck_s.expect("Sender chain key missing"));
        self.ck_s = Some(ck_s);

        // Create header
        let header = RatchetHeader {
            dh_pub: self.dh_pair.1,
            pn: self.pn,
            n: self.ns,
        };

        // Check for counter overflow (MEDIUM-1 fix)
        self.ns = self
            .ns
            .checked_add(1)
            .ok_or(RatchetError::CounterOverflow)?;

        // Encrypt header
        let enc_header = self.encrypt_header(&header)?;

        // Encrypt message with AD = concat(associated_data, encrypted_header)
        let ad = Self::concat_ad(associated_data, &enc_header);
        let ciphertext = Self::encrypt(&mk, plaintext, &ad)?;

        mk.zeroize(); // LOW-2: Zeroize message key after use

        Ok((enc_header, ciphertext))
    }

    /// Decrypt a message with header encryption (ATOMIC)
    pub fn ratchet_decrypt(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        // Validate input sizes (LOW-1 fix)
        if associated_data.len() > MAX_AD_SIZE {
            return Err(RatchetError::ADTooLarge);
        }

        // Prepare AD
        let ad = Self::concat_ad(associated_data, enc_header);

        // 1. Try skipped message keys first
        if let Some(plaintext) = self.try_skipped_message_keys(enc_header, ciphertext, &ad)? {
            return Ok(plaintext);
        }

        // 2. Decrypt header
        let (header, dh_ratchet) = self.decrypt_header(enc_header)?;

        // 3. Check for duplicate message (CRITICAL-3 fix)
        let msg_id = (header.dh_pub.to_bytes(), header.n);
        if self.received_messages.contains(&msg_id) {
            return Err(RatchetError::DuplicateMessage);
        }

        // 4. Compute the message key WITHOUT modifying state
        let mut mk = self.compute_message_key(&header, dh_ratchet)?;

        // 5. Attempt decryption - this is the authentication step
        let plaintext = Self::decrypt(&mk, ciphertext, &ad)?;

        mk.zeroize(); // LOW-2: Zeroize message key after use

        // 6. SUCCESS - Now commit state changes atomically
        self.commit_state_changes(&header, dh_ratchet)?;

        // 7. Track this message to prevent replay (HIGH-2: with limit)
        if self.received_messages.len() >= MAX_RECEIVED_TRACKING {
            return Err(RatchetError::TooManyMessages);
        }
        self.received_messages.insert(msg_id);

        Ok(plaintext)
    }

    /// Try to decrypt with skipped message keys
    fn try_skipped_message_keys(
        &mut self,
        enc_header: &[u8],
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Option<Vec<u8>>, RatchetError> {
        // Try to decrypt header with each skipped header key
        for ((hk, n), skipped_key) in self.mkskipped.iter() {
            if let Ok(header) = Self::decrypt_header_with_key(hk, enc_header) {
                if header.n.ct_eq(n).into() {
                    // Try to decrypt message
                    match Self::decrypt(&skipped_key.mk, ciphertext, ad) {
                        Ok(plaintext) => {
                            // Success! Remove the key and return
                            self.mkskipped.remove(&(*hk, *n));
                            return Ok(Some(plaintext));
                        }
                        Err(_) => {
                            // Failed authentication, continue trying other keys
                            continue;
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Decrypt header and determine if DH ratchet is needed
    fn decrypt_header(&self, enc_header: &[u8]) -> Result<(RatchetHeader, bool), RatchetError> {
        // Try current receiving header key
        if let Some(hk_r) = self.hk_r {
            if let Ok(header) = Self::decrypt_header_with_key(&hk_r, enc_header) {
                return Ok((header, false)); // No DH ratchet needed
            }
        }

        // Try next receiving header key (indicates DH ratchet)
        if let Ok(header) = Self::decrypt_header_with_key(&self.nhk_r, enc_header) {
            return Ok((header, true)); // DH ratchet needed
        }

        Err(RatchetError::HeaderDecryptionFailed)
    }

    /// Compute the message key without modifying state
    fn compute_message_key(
        &self,
        header: &RatchetHeader,
        dh_ratchet: bool,
    ) -> Result<[u8; 32], RatchetError> {
        let mut ck_r = self.ck_r;
        let mut nr = self.nr;

        if dh_ratchet {
            // Perform simulated DH ratchet
            let dh_out = self.dh_pair.0.diffie_hellman(&header.dh_pub);
            let mut dh_bytes = *dh_out.as_bytes();
            let (_, new_ck_r, _) = Self::kdf_rk_he(&self.rk, &dh_bytes);
            dh_bytes.zeroize(); // MEDIUM-4: Zeroize DH output
            ck_r = Some(new_ck_r);
            nr = 0;
        }

        // Check skip limit
        if nr + MAX_SKIP < header.n {
            return Err(RatchetError::OldMessageKeysLimitReached);
        }

        // Advance chain to message number
        let mut current_ck = ck_r.ok_or(RatchetError::InvalidKey)?;
        while nr < header.n {
            let mut old_ck = current_ck;
            let (next_ck, _) = Self::kdf_ck(&current_ck);
            old_ck.zeroize(); // MEDIUM-4: Zeroize before overwrite
            current_ck = next_ck;
            nr += 1;
        }

        // Derive message key
        let (_, mk) = Self::kdf_ck(&current_ck);
        current_ck.zeroize(); // MEDIUM-4: Zeroize final key
        Ok(mk)
    }

    /// Commit state changes after successful decryption (ATOMIC)
    fn commit_state_changes(
        &mut self,
        header: &RatchetHeader,
        dh_ratchet: bool,
    ) -> Result<(), RatchetError> {
        if dh_ratchet {
            // Store skipped keys from previous receiving chain
            if let Some(ck_r) = self.ck_r {
                if let Some(hk_r) = self.hk_r {
                    self.skip_message_keys(ck_r, hk_r, self.nr, header.pn)?;
                }
            }

            // Perform DH ratchet
            self.pn = self.ns;
            self.ns = 0;
            self.nr = 0;
            self.hk_s = Some(self.nhk_s);
            self.hk_r = Some(self.nhk_r);
            self.dh_remote = Some(header.dh_pub);

            // First KDF: derive receiving chain
            let dh_out_recv = self.dh_pair.0.diffie_hellman(&header.dh_pub);
            let (new_rk, new_ck_r, new_nhk_r) = Self::kdf_rk_he(&self.rk, dh_out_recv.as_bytes());
            self.rk = new_rk;
            self.ck_r = Some(new_ck_r);
            self.nhk_r = new_nhk_r;

            // Generate new DH key pair
            let mut rng = rand_core::OsRng;
            let new_dh_s = StaticSecret::random_from_rng(&mut rng);
            let new_dh_s_pub = PublicKey::from(&new_dh_s);

            // Second KDF: derive sending chain
            let dh_out_send = new_dh_s.diffie_hellman(&header.dh_pub);
            let (new_rk_2, new_ck_s, new_nhk_s) = Self::kdf_rk_he(&self.rk, dh_out_send.as_bytes());
            self.rk = new_rk_2;
            self.ck_s = Some(new_ck_s);
            self.nhk_s = new_nhk_s;
            self.dh_pair = (new_dh_s, new_dh_s_pub);

            // Clear received messages after DH ratchet (CRITICAL-3 fix)
            self.received_messages.clear();
        }

        // Store skipped keys in current receiving chain
        if let Some(ck_r) = self.ck_r {
            if let Some(hk_r) = self.hk_r {
                self.skip_message_keys(ck_r, hk_r, self.nr, header.n)?;
            }
        }

        // Advance to current message
        let (new_ck_r, _) = Self::kdf_ck(&self.ck_r.expect("Receiving chain key missing"));
        self.ck_r = Some(new_ck_r);

        // Add overflow protection (HIGH-1 fix)
        self.nr = self
            .nr
            .checked_add(1)
            .ok_or(RatchetError::CounterOverflow)?;

        Ok(())
    }

    /// Skip message keys in the current receiving chain
    fn skip_message_keys(
        &mut self,
        mut ck: [u8; 32],
        hk: [u8; 32],
        from: u32,
        to: u32,
    ) -> Result<(), RatchetError> {
        // Validate range (MEDIUM-2 fix)
        if to < from {
            return Err(RatchetError::InvalidHeader);
        }

        // Double-check skip limit (defense in depth)
        let skip_count = to.saturating_sub(from);
        if skip_count > MAX_SKIP {
            return Err(RatchetError::OldMessageKeysLimitReached);
        }

        let mut current = from;
        while current < to {
            // Enforce total size limit before adding (CRITICAL-2 fix)
            if self.mkskipped.len() >= MAX_SKIPPED_KEYS {
                self.evict_oldest_skipped_keys(MAX_SKIPPED_KEYS / 2);
            }

            let (next_ck, mk) = Self::kdf_ck(&ck);
            self.mkskipped.insert(
                (hk, current),
                SkippedKey {
                    mk,
                    timestamp: std::time::Instant::now(),
                },
            );
            ck = next_ck;

            // Add overflow protection (HIGH-1 fix)
            current = current
                .checked_add(1)
                .ok_or(RatchetError::CounterOverflow)?;
        }
        Ok(())
    }

    /// Validate encryption state (MEDIUM-2 fix)
    fn validate_encryption_state(&self) -> Result<(), RatchetError> {
        if self.ck_s.is_none() {
            return Err(RatchetError::InvalidState);
        }
        if self.hk_s.is_none() {
            return Err(RatchetError::InvalidState);
        }
        if self.dh_remote.is_none() {
            return Err(RatchetError::InvalidState);
        }
        Ok(())
    }

    /// Evict oldest skipped keys to prevent memory exhaustion (CRITICAL-2 fix)
    fn evict_oldest_skipped_keys(&mut self, target_size: usize) {
        let mut entries: Vec<_> = self
            .mkskipped
            .iter()
            .map(|(k, v)| (*k, v.timestamp))
            .collect();

        // Sort by timestamp (oldest first)
        entries.sort_by_key(|(_, time)| *time);

        // Remove oldest entries
        let to_remove = entries.len().saturating_sub(target_size);
        for (key, _) in entries.iter().take(to_remove) {
            self.mkskipped.remove(key);
        }
    }

    // ---------------- Cryptographic Helper Functions ----------------

    /// KDF_RK_HE: Derive root key, chain key, and next header key
    fn kdf_rk_he(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha512>::new(Some(rk), dh_out);
        let mut okm = [0u8; 96];
        hk.expand(HKDF_INFO_ROOT, &mut okm)
            .expect("KDF expansion failed");

        let mut new_rk = [0u8; 32];
        let mut new_ck = [0u8; 32];
        let mut new_nhk = [0u8; 32];
        new_rk.copy_from_slice(&okm[0..32]);
        new_ck.copy_from_slice(&okm[32..64]);
        new_nhk.copy_from_slice(&okm[64..96]);

        (new_rk, new_ck, new_nhk)
    }

    /// KDF_CK: Derive next chain key and message key
    fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        type HmacSha256 = Hmac<Sha256>;

        // 1. Message Key (0x01 per spec section 7.2)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC initialization failed");
        mac.update(&[0x01]);
        let mut mk_bytes = mac.finalize().into_bytes();

        // 2. Next Chain Key (0x02 per spec section 7.2)
        let mut mac = <HmacSha256 as Mac>::new_from_slice(ck).expect("HMAC initialization failed");
        mac.update(&[0x02]);
        let mut next_ck_bytes = mac.finalize().into_bytes();

        let mut next_ck = [0u8; 32];
        let mut mk = [0u8; 32];
        next_ck.copy_from_slice(&next_ck_bytes);
        mk.copy_from_slice(&mk_bytes);

        // Zeroize intermediates (HIGH-2 fix)
        next_ck_bytes.zeroize();
        mk_bytes.zeroize();

        (next_ck, mk)
    }

    /// Encrypt header with current sending header key
    fn encrypt_header(&mut self, header: &RatchetHeader) -> Result<Vec<u8>, RatchetError> {
        let hk = self.hk_s.ok_or(RatchetError::InvalidKey)?;
        let plaintext = header.to_bytes();

        // Use stateful counter as nonce with party identifier (CRITICAL-1 fix)
        let nonce_value = self.header_nonce_counter;
        // Check for overflow (MEDIUM-1 fix)
        self.header_nonce_counter = self
            .header_nonce_counter
            .checked_add(1)
            .ok_or(RatchetError::CounterOverflow)?;

        let mut nonce_bytes = [0u8; 12];
        // Include party identifier to prevent nonce reuse between Alice and Bob
        nonce_bytes[0] = if self.is_alice { 0x00 } else { 0xFF };
        nonce_bytes[4..12].copy_from_slice(&nonce_value.to_be_bytes());

        let key = Key::<Aes256Gcm>::from_slice(&hk);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .expect("Header encryption failure");

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt header with a specific header key
    fn decrypt_header_with_key(
        hk: &[u8; 32],
        enc_header: &[u8],
    ) -> Result<RatchetHeader, RatchetError> {
        if enc_header.len() < 12 {
            return Err(RatchetError::HeaderDecryptionFailed);
        }

        let nonce_bytes = &enc_header[0..12];
        let ciphertext = &enc_header[12..];

        let key = Key::<Aes256Gcm>::from_slice(hk);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| RatchetError::HeaderDecryptionFailed)?;

        RatchetHeader::from_bytes(&plaintext)
    }

    /// Concatenate associated data with encrypted header per Signal spec
    fn concat_ad(associated_data: &[u8], header: &[u8]) -> Vec<u8> {
        let mut ad = Vec::with_capacity(8 + associated_data.len() + header.len());
        ad.extend_from_slice(&(associated_data.len() as u64).to_be_bytes());
        ad.extend_from_slice(associated_data);
        ad.extend_from_slice(header);
        ad
    }

    /// Encrypt message with CBC+HMAC (per Signal spec section 7.2)
    ///
    /// Uses HKDF to derive 80 bytes: 32-byte encryption key, 32-byte auth key, 16-byte IV
    /// Then AES-256-CBC with PKCS#7, followed by HMAC-SHA256 authentication
    fn encrypt(mk: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
        type HmacSha256 = Hmac<Sha256>;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        // Derive encryption key (32), auth key (32), and IV (16) from message key
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
        let mut okm = [0u8; 80];
        hk.expand(b"Signal-DoubleRatchet-Encrypt", &mut okm)
            .expect("HKDF expansion failed");

        let enc_key: [u8; 32] = okm[0..32].try_into().unwrap();
        let auth_key: [u8; 32] = okm[32..64].try_into().unwrap();
        let iv: [u8; 16] = okm[64..80].try_into().unwrap();

        // Encrypt with AES-256-CBC + PKCS#7 padding
        let cipher = Aes256CbcEnc::new((&enc_key).into(), (&iv).into());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        // Calculate HMAC over (AD || ciphertext)
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("HMAC initialization failed");
        mac.update(ad);
        mac.update(&ciphertext);
        let tag = mac.finalize().into_bytes();

        // Return ciphertext || tag (32 bytes)
        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    /// Decrypt message with CBC+HMAC (per Signal spec section 7.2)
    fn decrypt(mk: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
        type HmacSha256 = Hmac<Sha256>;
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        // Minimum size: 16 bytes (one AES block) + 32 bytes (HMAC tag)
        if ciphertext.len() < 48 {
            return Err(RatchetError::DecryptionFailed);
        }

        // Split ciphertext and tag
        let tag_start = ciphertext.len() - 32;
        let ct_bytes = &ciphertext[..tag_start];
        let received_tag = &ciphertext[tag_start..];

        // Derive encryption key (32), auth key (32), and IV (16) from message key
        let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
        let mut okm = [0u8; 80];
        hk.expand(b"Signal-DoubleRatchet-Encrypt", &mut okm)
            .expect("HKDF expansion failed");

        let enc_key: [u8; 32] = okm[0..32].try_into().unwrap();
        let auth_key: [u8; 32] = okm[32..64].try_into().unwrap();
        let iv: [u8; 16] = okm[64..80].try_into().unwrap();

        // Verify HMAC first (authenticate-then-decrypt)
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&auth_key).expect("HMAC initialization failed");
        mac.update(ad);
        mac.update(ct_bytes);
        let expected_tag = mac.finalize().into_bytes();

        // Constant-time tag comparison
        if !bool::from(expected_tag.ct_eq(received_tag)) {
            return Err(RatchetError::DecryptionFailed);
        }

        // Decrypt with AES-256-CBC + PKCS#7 unpadding
        let cipher = Aes256CbcDec::new((&enc_key).into(), (&iv).into());
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(ct_bytes)
            .map_err(|_| RatchetError::DecryptionFailed)
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_basic_flow() {
        let sk = [0x55u8; 32];
        let shared_hka = [0xAAu8; 32];
        let shared_nhkb = [0xBBu8; 32];

        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
        let mut bob =
            DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

        let msg1 = b"Hello Bob!";
        let ad1 = b"Metadata";
        let (enc_header1, cipher1) = alice
            .ratchet_encrypt(msg1, ad1)
            .expect("Alice encrypts msg1");

        let decrypted1 = bob
            .ratchet_decrypt(&enc_header1, &cipher1, ad1)
            .expect("Bob decrypts msg1");
        assert_eq!(decrypted1, msg1);

        let msg2 = b"Hello Alice!";
        let (enc_header2, cipher2) = bob.ratchet_encrypt(msg2, &[]).expect("Bob encrypts msg2");

        let decrypted2 = alice
            .ratchet_decrypt(&enc_header2, &cipher2, &[])
            .expect("Alice decrypts msg2");
        assert_eq!(decrypted2, msg2);
    }

    #[test]
    fn test_out_of_order_messages() {
        let sk = [0x66u8; 32];
        let shared_hka = [0xAAu8; 32];
        let shared_nhkb = [0xBBu8; 32];

        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
        let mut bob =
            DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

        // Alice sends 3 messages
        let (h1, c1) = alice
            .ratchet_encrypt(b"Message 1", &[])
            .expect("encrypts 1");
        let (h2, c2) = alice
            .ratchet_encrypt(b"Message 2", &[])
            .expect("encrypts 2");
        let (h3, c3) = alice
            .ratchet_encrypt(b"Message 3", &[])
            .expect("encrypts 3");

        // Bob receives them out of order: 1, 3, 2
        let d1 = bob.ratchet_decrypt(&h1, &c1, &[]).expect("Decrypt 1");
        assert_eq!(d1, b"Message 1");

        let d3 = bob.ratchet_decrypt(&h3, &c3, &[]).expect("Decrypt 3");
        assert_eq!(d3, b"Message 3");

        let d2 = bob.ratchet_decrypt(&h2, &c2, &[]).expect("Decrypt 2");
        assert_eq!(d2, b"Message 2");
    }

    #[test]
    fn test_max_skip_exceeded() {
        let sk = [0x88u8; 32];
        let shared_hka = [0xAAu8; 32];
        let shared_nhkb = [0xBBu8; 32];

        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
        let mut bob =
            DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

        let (h1, c1) = alice.ratchet_encrypt(b"Message 1", &[]).expect("encrypt 1");
        bob.ratchet_decrypt(&h1, &c1, &[]).expect("Decrypt 1");

        // Alice sends MAX_SKIP + 2 more messages
        for _ in 0..(MAX_SKIP + 2) {
            let _ = alice.ratchet_encrypt(b"Skip me", &[]);
        }

        let (h_final, c_final) = alice.ratchet_encrypt(b"Final", &[]).expect("encrypt final");

        // Bob tries to decrypt - should fail due to MAX_SKIP
        let err = bob.ratchet_decrypt(&h_final, &c_final, &[]);
        assert_eq!(err, Err(RatchetError::OldMessageKeysLimitReached));
    }

    #[test]
    fn test_tampered_ciphertext() {
        let sk = [0x77u8; 32];
        let shared_hka = [0xAAu8; 32];
        let shared_nhkb = [0xBBu8; 32];

        let mut rng = rand_core::OsRng;
        let bob_dh_private = StaticSecret::random_from_rng(&mut rng);
        let bob_dh_public = PublicKey::from(&bob_dh_private);

        let mut alice = DoubleRatchet::new_alice(sk, bob_dh_public, shared_hka, shared_nhkb);
        let mut bob =
            DoubleRatchet::new_bob(sk, (bob_dh_private, bob_dh_public), shared_hka, shared_nhkb);

        let msg = b"Tampered";
        let (enc_header, mut cipher) = alice.ratchet_encrypt(msg, &[]).expect("encrypt tampered");

        // Tamper ciphertext
        if !cipher.is_empty() {
            cipher[0] ^= 0xFF;
        }

        let err = bob.ratchet_decrypt(&enc_header, &cipher, &[]);
        assert_eq!(err, Err(RatchetError::DecryptionFailed));
    }
}
