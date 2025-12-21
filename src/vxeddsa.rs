#![allow(non_snake_case)]
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    hashes::{SignalHash2, hash_i},
    utils::{calculate_key_pair, convert_mont},
};
/// Represents a key pair containing a 32-byte secret key and a 32-byte public key.
#[repr(C)]
pub struct KeyPair {
    /// The 32-byte secret key.
    pub secret: [u8; 32],
    /// The 32-byte public key.
    pub public: [u8; 32],
}

/// Represents the output of a VXEdDSA signature operation.
#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct VXEdDSAOutput {
    /// The 96-byte signature, consisting of `V || h || s`.
    pub signature: [u8; 96],
    /// The 32-byte VRF output `v`, which serves as a proof of randomness.
    pub vrf: [u8; 32],
}

/// Generates a random Curve25519 key pair.
///
/// Use this function to create a new identity. It uses a cryptographically secure
/// random number generator to create the secret key.
#[unsafe(no_mangle)]
pub extern "C" fn gen_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(&mut OsRng);

    let public = PublicKey::from(&secret);
    KeyPair {
        secret: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

/// Generates a random 32-byte secret key and writes it to the provided buffer.
///
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that `secret_out` points to a valid, writable 32-byte memory region.
#[unsafe(no_mangle)]
pub extern "C" fn gen_secret(secret_out: *mut [u8; 32]) {
    let secret = StaticSecret::random_from_rng(&mut OsRng);
    unsafe {
        (*secret_out).copy_from_slice(&secret.to_bytes());
    }
}

/// Derives a public key from a given 32-byte secret key.
///
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that `pubkey` points to a valid, writable 32-byte memory region.
#[unsafe(no_mangle)]
pub extern "C" fn gen_pubkey(k: &[u8; 32], pubkey: *mut [u8; 32]) {
    let secret = StaticSecret::from(*k);
    unsafe {
        (*pubkey).copy_from_slice(&PublicKey::from(&secret).as_bytes()[0..32]);
    }
}

/// Computes a VXEdDSA signature and generates the associated VRF output.
///
/// This function implements the signing logic specified in the VXEdDSA protocol (Signal).
/// It produces a deterministic signature and a proof of randomness (v).
///
/// The random nonce `Z` is generated internally using `OsRng` for security.
///
/// # Arguments
///
/// * `k` - The 32-byte private key seed. Note that this is the raw seed, not the clamped scalar.
/// * `msg_ptr` - Pointer to the message bytes to sign.
/// * `msg_len` - Length of the message.
/// * `output` - Pointer to a VXEdDSAOutput struct where results will be written.
///
/// # Returns
///
/// * `0` on success.
/// * `-1` on error (e.g. invalid scalar).
///
/// A VXEdDSAOutput struct is written to `output` pointer on success.
#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_sign(
    k: &[u8; 32],
    msg_ptr: *const u8,
    msg_len: usize,
    output: *mut VXEdDSAOutput,
) -> i32 {
    use rand_core::RngCore;
    use zeroize::Zeroize;

    // Generate random nonce internally for security
    let mut Z = [0u8; 64];
    OsRng.fill_bytes(&mut Z);

    let M = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    let (a, A) = calculate_key_pair(*k);

    let a_bytes = A.compress().to_bytes();
    let mut point_msg = Vec::with_capacity(a_bytes.iter().len() + M.len());
    point_msg.extend_from_slice(&a_bytes);
    point_msg.extend_from_slice(M);

    // We are using the Elligator2 according to the VXEdDSA protocol
    // It was deprecated back in 2023 in favour of RFC 9380
    // It's still secure cryptographically (atleast for now)
    // We currently plan to follow signal and their implementation
    #[allow(deprecated)]
    // Map to curve (Elligator 2) and clear cofactor (multiply by 8)
    let Bv = EdwardsPoint::nonspec_map_to_curve::<SignalHash2>(&point_msg).mul_by_cofactor();

    // 3. V = a * Bv
    let V = Bv * a;
    let V_bytes = V.compress().to_bytes();

    // 4. r = hash3(a || V || Z) (mod q)
    // We concatenate bytes into a Vec for the hash input
    let mut r_msg = Vec::new();
    r_msg.extend_from_slice(a.as_bytes());
    r_msg.extend_from_slice(&V_bytes);
    r_msg.extend_from_slice(&Z);

    let r_hash = hash_i(3, &r_msg);

    // Zeroize sensitive data after use
    Z.zeroize();
    r_msg.zeroize();

    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    if r.ct_eq(&Scalar::ZERO).into() {
        return -1;
    }

    // 5. R = r * B
    let R_point = ED25519_BASEPOINT_POINT * r;
    let R_bytes = R_point.compress().to_bytes();

    // 6. Rv = r * Bv
    let Rv_point = Bv * r;
    let Rv_bytes = Rv_point.compress().to_bytes();

    // 7. h = hash4(A || V || R || Rv || M) (mod q)
    let mut h_msg = Vec::new();
    h_msg.extend_from_slice(&a_bytes);
    h_msg.extend_from_slice(&V_bytes);
    h_msg.extend_from_slice(&R_bytes);
    h_msg.extend_from_slice(&Rv_bytes);
    h_msg.extend_from_slice(M);

    let h_hash = hash_i(4, &h_msg);
    let h = Scalar::from_bytes_mod_order_wide(&h_hash);

    // 8. s = r + (h * a) (mod q)
    let s = r + (h * a);

    // 9. v = hash5(cV) (mod 2^256, which basically means take 32 bytes)
    // cV means V multiplied by cofactor (8)
    let cV_point = V.mul_by_cofactor();
    let cV_bytes = cV_point.compress().to_bytes();

    let v_hash_full = hash_i(5, &cV_bytes);
    let mut v = [0u8; 32];
    v.copy_from_slice(&v_hash_full[0..32]);

    // 10. return (V || h || s), v
    let mut signature = [0u8; 96];
    signature[0..32].copy_from_slice(&V_bytes);
    signature[32..64].copy_from_slice(&h.to_bytes());
    signature[64..96].copy_from_slice(&s.to_bytes());

    // Fixed: Returns 'v' (VRF output) instead of 'V_bytes' (Part of signature)
    unsafe {
        (*output) = VXEdDSAOutput {
            signature: signature,
            vrf: v,
        };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_verify(
    u: &[u8; 32],
    msg_ptr: *const u8,
    msg_len: usize,
    signature: &[u8; 96],
    v_out: *mut [u8; 32],
) -> bool {
    // Reconstruct message slice
    let M = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };

    // --- 1. Parsing and splitting the signature ---
    let V_bytes = &signature[0..32];
    let h_bytes = &signature[32..64];
    let s_bytes = &signature[64..96];

    // Deserialize Scalars.
    // from_canonical_bytes checks if scalar < L (CURVE_Q).
    // If check fails, it returns None, matching TS `if (h >= CURVE_Q...) return false`
    let h = match Option::<Scalar>::from(Scalar::from_canonical_bytes(match h_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    })) {
        Some(s) => s,
        None => return false,
    };

    let s = match Option::<Scalar>::from(Scalar::from_canonical_bytes(match s_bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    })) {
        Some(s) => s,
        None => return false,
    };

    // --- 2. Decompress Points & Check on_curve ---

    // Convert X25519 u-coordinate to Ed25519 Point A
    // convert_mont is expected to return an EdwardsPoint derived from u
    let A = convert_mont(*u);
    let A_bytes = A.compress().to_bytes();

    // Decompress V: Slice -> [u8;32] -> CompressedEdwardsY -> EdwardsPoint
    let V_arr: [u8; 32] = match V_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let V = match CompressedEdwardsY(V_arr).decompress() {
        Some(p) => p,
        None => return false,
    };

    // --- 3. Bv = hash_to_point(A || M) ---
    let mut point_msg = Vec::with_capacity(A_bytes.len() + M.len());
    point_msg.extend_from_slice(&A_bytes);
    point_msg.extend_from_slice(M);

    // We must use the same deprecated map as the Sign function
    #[allow(deprecated)]
    let Bv = EdwardsPoint::nonspec_map_to_curve::<SignalHash2>(&point_msg).mul_by_cofactor();

    // --- 4. Check for identity points ---

    let cA = A.mul_by_cofactor();
    let cV = V.mul_by_cofactor();
    if cA.is_identity() || cV.is_identity() || Bv.is_identity() {
        return false;
    }

    // --- 5. R = sB - hA ---
    let R = (ED25519_BASEPOINT_POINT * s) - (A * h);
    let R_bytes = R.compress().to_bytes();

    // --- 6. Rv = sBv - hV ---
    let Rv = (Bv * s) - (V * h);
    let Rv_bytes = Rv.compress().to_bytes();

    // --- 7. hcheck = hash4(...) ---
    let mut h_msg = Vec::new();
    h_msg.extend_from_slice(&A_bytes);
    h_msg.extend_from_slice(&V_bytes);
    h_msg.extend_from_slice(&R_bytes);
    h_msg.extend_from_slice(&Rv_bytes);
    h_msg.extend_from_slice(M);

    let hcheck_hash = hash_i(4, &h_msg);
    let hcheck = Scalar::from_bytes_mod_order_wide(&hcheck_hash);

    // --- 8. if bytes_equal(h, hcheck) ---
    if h != hcheck {
        return false;
    }

    // --- 9. Success: return v ---

    let v_hash_full = hash_i(5, &cV.compress().to_bytes());

    // Write output to pointer if not null
    if !v_out.is_null() {
        unsafe {
            (*v_out).copy_from_slice(&v_hash_full[0..32]);
        }
    }

    true
}
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jclass, jobject};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genKeyPair(
    mut env: JNIEnv,
    _class: jclass,
) -> jobject {
    let keys = gen_keypair();

    let map_class = env.find_class("java/util/HashMap").unwrap();
    let map = env.new_object(map_class, "()V", &[]).unwrap();

    let secret_array = create_byte_array(&mut env, &keys.secret).unwrap();
    let public_array = create_byte_array(&mut env, &keys.public).unwrap();

    let secret_key = env.new_string("secret").unwrap();
    let public_key = env.new_string("public").unwrap();

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
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_vxeddsaSign(
    mut env: JNIEnv,
    _class: jclass,
    k_byte_array: jbyteArray,
    m_byte_array: jbyteArray,
) -> jobject {
    let k_obj = unsafe { JByteArray::from_raw(k_byte_array) };
    let m_obj = unsafe { JByteArray::from_raw(m_byte_array) };

    let k = env.convert_byte_array(&k_obj).unwrap();
    let m = env.convert_byte_array(&m_obj).unwrap();

    if k.len() != 32 {
        let exception_class = env
            .find_class("java/lang/IllegalArgumentException")
            .unwrap();
        env.throw_new(exception_class, "Secret key must be 32 bytes")
            .unwrap();
        return JObject::null().into_raw();
    }

    let k_arr: [u8; 32] = k.try_into().unwrap();

    let mut output = VXEdDSAOutput {
        signature: [0u8; 96],
        vrf: [0u8; 32],
    };

    let status = vxeddsa_sign(&k_arr, m.as_ptr(), m.len(), &mut output);

    if status != 0 {
        let exception_class = env.find_class("java/lang/RuntimeException").unwrap();
        env.throw_new(exception_class, "VXEdDSA Signing Failed")
            .unwrap();
        return JObject::null().into_raw();
    }

    let map_class = env.find_class("java/util/HashMap").unwrap();
    let map = env.new_object(map_class, "()V", &[]).unwrap();

    let signature_array = create_byte_array(&mut env, &output.signature).unwrap();
    let vrf_array = create_byte_array(&mut env, &output.vrf).unwrap();

    let signature_key = env.new_string("signature").unwrap();
    let vrf_key = env.new_string("vrf").unwrap();

    let signature_key_obj = JObject::from(signature_key);
    let signature_array_obj = unsafe { JObject::from_raw(signature_array) };
    let vrf_key_obj = JObject::from(vrf_key);
    let vrf_array_obj = unsafe { JObject::from_raw(vrf_array) };

    env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&signature_key_obj),
            JValue::Object(&signature_array_obj),
        ],
    )
    .unwrap();

    env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[JValue::Object(&vrf_key_obj), JValue::Object(&vrf_array_obj)],
    )
    .unwrap();

    map.into_raw()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_vxeddsaVerify(
    mut env: JNIEnv,
    _class: jclass,
    u_byte_array: jbyteArray,
    m_byte_array: jbyteArray,
    signature_byte_array: jbyteArray,
) -> jbyteArray {
    let u_obj = unsafe { JByteArray::from_raw(u_byte_array) };
    let m_obj = unsafe { JByteArray::from_raw(m_byte_array) };
    let sig_obj = unsafe { JByteArray::from_raw(signature_byte_array) };

    let u = env.convert_byte_array(&u_obj).unwrap();
    let m = env.convert_byte_array(&m_obj).unwrap();
    let sig = env.convert_byte_array(&sig_obj).unwrap();

    if u.len() != 32 || sig.len() != 96 {
        // Return null or throw logic
        return std::ptr::null_mut();
    }

    let u_arr: [u8; 32] = u.try_into().unwrap();
    // m is Vec<u8>
    let sig_arr: [u8; 96] = sig.try_into().unwrap();

    let mut v_out = [0u8; 32];

    // Call the rust signature we implemented
    let valid = vxeddsa_verify(&u_arr, m.as_ptr(), m.len(), &sig_arr, &mut v_out);

    if valid {
        let out_array = create_byte_array(&mut env, &v_out).unwrap();
        out_array
    } else {
        std::ptr::null_mut()
    }
}
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genPubKey(
    mut env: JNIEnv,
    _class: jclass,
    k_byte_array: jbyteArray,
) -> jbyteArray {
    let k_obj = unsafe { JByteArray::from_raw(k_byte_array) };

    let k = env.convert_byte_array(&k_obj).unwrap();

    if k.len() != 32 {
        // Return null or throw logic
        return std::ptr::null_mut();
    }

    let k_arr: [u8; 32] = k.try_into().unwrap();

    let mut k_out = [0u8; 32];

    // Call the rust signature we implemented
    gen_pubkey(&k_arr, &mut k_out);

    create_byte_array(&mut env, &k_out).unwrap()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_genSecret(
    mut env: JNIEnv,
    _class: jclass,
) -> jbyteArray {
    let mut secret = [0u8; 32];
    gen_secret(&mut secret);
    create_byte_array(&mut env, &secret).unwrap()
}
