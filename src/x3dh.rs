use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::utils::{encode_public_key, is_valid_public_key};
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

/// Structure for returning multiple values from x3dh_initiator
#[repr(C)]
pub struct X3DHInitOutput {
    pub shared_secret: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub status: i32, // 0 = Success, -1 = Invalid Signature, -2 = Other error
}

/// Alice (Initiator) performs the X3DH key agreement.
///
/// This function is the `extern "C"` entry point.
///
/// # Arguments
/// Flattened arguments for C-ABI compatibility.
#[unsafe(no_mangle)]
pub extern "C" fn x3dh_initiator(
    identity_private: &[u8; 32],
    bob_identity_public: &[u8; 32],
    bob_spk_id: u32,
    bob_spk_public: &[u8; 32],
    bob_spk_signature: &[u8; 96],
    bob_opk_id: u32,
    bob_opk_public: *const u8, // Optional, null if not present
    has_opk: bool,
    output: *mut X3DHInitOutput,
) -> i32 {
    let signed_prekey = SignedPreKey {
        id: bob_spk_id,
        public_key: *bob_spk_public,
        signature: *bob_spk_signature,
    };

    let one_time_prekey = if has_opk && !bob_opk_public.is_null() {
        let opk_pub = unsafe { *(bob_opk_public as *const [u8; 32]) };
        Some(OneTimePreKey {
            id: bob_opk_id,
            public_key: opk_pub,
        })
    } else {
        None
    };

    // 0. Verify Key Validity (Public keys must be valid points)
    if !is_valid_public_key(bob_identity_public)
        || !is_valid_public_key(bob_spk_public)
        || (has_opk
            && !bob_opk_public.is_null()
            && !is_valid_public_key(unsafe { &*(bob_opk_public as *const [u8; 32]) }))
    {
        unsafe {
            (*output).status = -2; // Invalid Key
        }
        return -1;
    }

    let bundle = PreKeyBundle {
        identity_key: *bob_identity_public,
        signed_prekey,
        one_time_prekey,
    };

    // 1. Verify Signed PreKey Signature
    // Sig(IKB, Encode(SPKB))
    // Encode(SPKB) = 0x05 || Public Key (32 bytes)
    // Encode(SPKB) = 0x05 || Public Key (32 bytes)
    let mut encoded_spk = [0u8; 33];
    encode_public_key(&bundle.signed_prekey.public_key, encoded_spk.as_mut_ptr());

    let mut v_out = [0u8; 32];

    if !vxeddsa_verify(
        &bundle.identity_key,
        encoded_spk.as_ptr(),
        encoded_spk.len(),
        &bundle.signed_prekey.signature,
        &mut v_out as *mut [u8; 32],
    ) {
        unsafe {
            (*output).status = -1;
        }
        return -1;
    }

    // 2. Generate Ephemeral Key EKA
    let mut ephemeral_private = [0u8; 32];
    gen_secret(&mut ephemeral_private as *mut [u8; 32]);

    let mut ephemeral_public = [0u8; 32];
    gen_pubkey(&ephemeral_private, &mut ephemeral_public as *mut [u8; 32]);

    // 3. Calculate separate DHs
    // DH1 = DH(IKA, SPKB)
    let mut dh1 = dh(identity_private, &bundle.signed_prekey.public_key);

    // DH2 = DH(EKA, IKB)
    let mut dh2 = dh(&ephemeral_private, &bundle.identity_key);

    // DH3 = DH(EKA, SPKB)
    let mut dh3 = dh(&ephemeral_private, &bundle.signed_prekey.public_key);

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(EKA, OPKB) if present
    let mut dh4_opt: Option<[u8; 32]> = None;
    if let Some(opk) = &bundle.one_time_prekey {
        let dh4 = dh(&ephemeral_private, &opk.public_key);
        chained_key_material.extend_from_slice(&dh4);
        dh4_opt = Some(dh4);
    }

    // 4. KDF(DH1 || DH2 || DH3 [|| DH4])
    let sk = kdf(&chained_key_material);

    // Zeroize sensitive key material after use (Signal spec requirement)
    use zeroize::Zeroize;
    ephemeral_private.zeroize();
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    if let Some(ref mut dh4) = dh4_opt {
        dh4.zeroize();
    }
    chained_key_material.zeroize();

    unsafe {
        (*output).shared_secret = sk;
        (*output).ephemeral_public = ephemeral_public;
        (*output).status = 0;
    }

    0
}

/// Bob (Responder) performs the X3DH key agreement.
///
/// This function is the `extern "C"` entry point.
#[unsafe(no_mangle)]
pub extern "C" fn x3dh_responder(
    identity_private: &[u8; 32],
    signed_prekey_private: &[u8; 32],
    one_time_prekey_private: *const u8, // Optional private key, null if not used
    has_opk: bool,
    alice_identity_public: &[u8; 32],
    alice_ephemeral_public: &[u8; 32],
    shared_secret_out: *mut [u8; 32],
) -> i32 {
    let opk_private = if has_opk && !one_time_prekey_private.is_null() {
        unsafe { Some(&*(one_time_prekey_private as *const [u8; 32])) }
    } else {
        None
    };

    // 0. Verify Key Validity
    if !is_valid_public_key(alice_identity_public) || !is_valid_public_key(alice_ephemeral_public) {
        unsafe {
            *shared_secret_out = [0u8; 32];
        }
        return -1;
    }

    // 1. Calculate DHs

    // DH1 = DH(SPKB, IKA)  <-- Note: Role reversal requires corresponding private/public match
    // Alice calculated DH(IKA, SPKB).
    // Bob calculates DH(SPKB, IKA).
    let mut dh1 = dh(signed_prekey_private, alice_identity_public);

    // DH2 = DH(IKB, EKA)
    // Alice calculated DH(EKA, IKB).
    // Bob calculates DH(IKB, EKA).
    let mut dh2 = dh(identity_private, alice_ephemeral_public);

    // DH3 = DH(SPKB, EKA)
    // Alice calculated DH(EKA, SPKB).
    // Bob calculates DH(SPKB, EKA).
    let mut dh3 = dh(signed_prekey_private, alice_ephemeral_public);

    let mut chained_key_material = Vec::with_capacity(32 * 4);
    chained_key_material.extend_from_slice(&dh1);
    chained_key_material.extend_from_slice(&dh2);
    chained_key_material.extend_from_slice(&dh3);

    // DH4 = DH(OPKB, EKA) if OPK used
    let mut dh4_opt: Option<[u8; 32]> = None;
    if let Some(opk_private) = opk_private {
        let dh4 = dh(opk_private, alice_ephemeral_public);
        chained_key_material.extend_from_slice(&dh4);
        dh4_opt = Some(dh4);
    }

    // 2. KDF
    let sk = kdf(&chained_key_material);

    // Zeroize sensitive key material after use (Signal spec requirement)
    use zeroize::Zeroize;
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    if let Some(ref mut dh4) = dh4_opt {
        dh4.zeroize();
    }
    chained_key_material.zeroize();

    unsafe {
        *shared_secret_out = sk;
    }
    0
}

// --- JNI Bindings for Android ---

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jboolean, jbyteArray, jclass, jint, jobject};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_x3dhInitiator(
    mut env: JNIEnv,
    _class: jclass,
    identity_private_arr: jbyteArray,
    bob_identity_public_arr: jbyteArray,
    bob_spk_id: jint,
    bob_spk_public_arr: jbyteArray,
    bob_spk_signature_arr: jbyteArray,
    bob_opk_id: jint,
    bob_opk_public_arr: jbyteArray, // Pass null if no OPK
) -> jobject {
    // Helper to convert jbyteArray to [u8; N]
    let get_array = |env: &mut JNIEnv, arr: jbyteArray| -> Option<Vec<u8>> {
        if arr.is_null() {
            return None;
        }
        let obj = unsafe { JByteArray::from_raw(arr) };
        env.convert_byte_array(&obj).ok()
    };

    let id_priv = get_array(&mut env, identity_private_arr).expect("Invalid ID Priv");
    let bob_id_pub = get_array(&mut env, bob_identity_public_arr).expect("Invalid Bob ID Pub");
    let bob_spk_pub = get_array(&mut env, bob_spk_public_arr).expect("Invalid Bob SPK Pub");
    let bob_spk_sig = get_array(&mut env, bob_spk_signature_arr).expect("Invalid Bob SPK Sig");
    let bob_opk_pub = get_array(&mut env, bob_opk_public_arr); // Option

    if id_priv.len() != 32
        || bob_id_pub.len() != 32
        || bob_spk_pub.len() != 32
        || bob_spk_sig.len() != 96
    {
        return JObject::null().into_raw();
    }

    let id_priv_fixed: [u8; 32] = id_priv.try_into().unwrap();
    let bob_id_pub_fixed: [u8; 32] = bob_id_pub.try_into().unwrap();
    let bob_spk_pub_fixed: [u8; 32] = bob_spk_pub.try_into().unwrap();
    let bob_spk_sig_fixed: [u8; 96] = bob_spk_sig.try_into().unwrap();

    let (opk_ptr, has_opk) = if let Some(opk_vec) = bob_opk_pub {
        if opk_vec.len() == 32 {
            (opk_vec.as_ptr(), true)
        } else {
            (std::ptr::null(), false)
        }
    } else {
        (std::ptr::null(), false)
    };

    let mut output = X3DHInitOutput {
        shared_secret: [0u8; 32],
        ephemeral_public: [0u8; 32],
        status: -99,
    };

    x3dh_initiator(
        &id_priv_fixed,
        &bob_id_pub_fixed,
        bob_spk_id as u32,
        &bob_spk_pub_fixed,
        &bob_spk_sig_fixed,
        bob_opk_id as u32,
        opk_ptr,
        has_opk,
        &mut output,
    );

    if output.status != 0 {
        return JObject::null().into_raw();
    }

    // Return HashMap { "shared_secret": byte[], "ephemeral_public": byte[] }
    let map_class = env.find_class("java/util/HashMap").unwrap();
    let map = env.new_object(map_class, "()V", &[]).unwrap();

    let secret_array = create_byte_array(&mut env, &output.shared_secret).unwrap();
    let public_array = create_byte_array(&mut env, &output.ephemeral_public).unwrap();

    let secret_key = env.new_string("shared_secret").unwrap();
    let public_key = env.new_string("ephemeral_public").unwrap();

    let secret_key_obj = JObject::from(secret_key);
    let secret_array_obj = unsafe { JObject::from_raw(secret_array) };
    let public_key_obj = JObject::from(public_key);
    let public_array_obj = unsafe { JObject::from_raw(public_array) };

    env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&secret_key_obj),
            JValue::Object(&secret_array_obj),
        ],
    )
    .unwrap();

    env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&public_key_obj),
            JValue::Object(&public_array_obj),
        ],
    )
    .unwrap();

    map.into_raw()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_x3dhResponder(
    mut env: JNIEnv,
    _class: jclass,
    identity_private_arr: jbyteArray,
    signed_prekey_private_arr: jbyteArray,
    one_time_prekey_private_arr: jbyteArray, // Pass null if not used
    alice_identity_public_arr: jbyteArray,
    alice_ephemeral_public_arr: jbyteArray,
) -> jbyteArray {
    let get_array = |env: &mut JNIEnv, arr: jbyteArray| -> Option<Vec<u8>> {
        if arr.is_null() {
            return None;
        }
        let obj = unsafe { JByteArray::from_raw(arr) };
        env.convert_byte_array(&obj).ok()
    };

    let id_priv = get_array(&mut env, identity_private_arr).expect("Invalid ID Priv");
    let spk_priv = get_array(&mut env, signed_prekey_private_arr).expect("Invalid SPK Priv");
    let opk_priv = get_array(&mut env, one_time_prekey_private_arr); // Option
    let alice_id_pub =
        get_array(&mut env, alice_identity_public_arr).expect("Invalid Alice ID Pub");
    let alice_ek_pub =
        get_array(&mut env, alice_ephemeral_public_arr).expect("Invalid Alice EK Pub");

    if id_priv.len() != 32
        || spk_priv.len() != 32
        || alice_id_pub.len() != 32
        || alice_ek_pub.len() != 32
    {
        return std::ptr::null_mut();
    }

    let id_priv_fixed: [u8; 32] = id_priv.try_into().unwrap();
    let spk_priv_fixed: [u8; 32] = spk_priv.try_into().unwrap();
    let alice_id_pub_fixed: [u8; 32] = alice_id_pub.try_into().unwrap();
    let alice_ek_pub_fixed: [u8; 32] = alice_ek_pub.try_into().unwrap();

    let (opk_ptr, has_opk) = if let Some(opk_vec) = opk_priv {
        if opk_vec.len() == 32 {
            (opk_vec.as_ptr(), true)
        } else {
            (std::ptr::null(), false)
        }
    } else {
        (std::ptr::null(), false)
    };

    let mut shared_secret = [0u8; 32];

    let status = x3dh_responder(
        &id_priv_fixed,
        &spk_priv_fixed,
        opk_ptr,
        has_opk,
        &alice_id_pub_fixed,
        &alice_ek_pub_fixed,
        &mut shared_secret,
    );

    if status != 0 {
        return std::ptr::null_mut();
    }

    create_byte_array(&mut env, &shared_secret).unwrap()
}
