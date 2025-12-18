#![allow(non_snake_case)]
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::OsRng;
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    hashes::hashi,
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
/// # Arguments
///
/// * `k` - The 32-byte private key seed. Note that this is the raw seed, not the clamped scalar.
/// * `M` - A reference to the 32-byte message to be signed.
///
/// # Returns
///
/// A VXEdDSAOutput struct containing:
/// 1. sign: The **Signature** (96 bytes): Concatenation of `V || h || s`.
/// 2. vrf: The **VRF Output** (32 bytes): The value `v`, which serves as the verifiable random output.
///
/// # Panics
///
/// This function will panic if the calculated scalar `r` happens to be zero, which is a
/// statistically negligible event.
#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_sign(k: &[u8; 32], M: &[u8; 32]) -> VXEdDSAOutput {
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
    let Bv = EdwardsPoint::nonspec_map_to_curve::<Sha512>(&point_msg).mul_by_cofactor();

    // 3. V = a * Bv
    let V = Bv * a;
    let V_bytes = V.compress().to_bytes();

    // 4. r = hash3(a || V || Z) (mod q)
    // We concatenate bytes into a Vec for the hash input
    let mut r_msg = Vec::new();
    r_msg.extend_from_slice(a.as_bytes());
    r_msg.extend_from_slice(&V_bytes);
    use rand_core::RngCore;
    let mut z = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut z);

    let mut r_msg = Vec::new();
    r_msg.extend_from_slice(a.as_bytes());
    r_msg.extend_from_slice(&V_bytes);
    r_msg.extend_from_slice(&z);

    let r_hash = hashi(3, &r_msg);

    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    if r == Scalar::ZERO {
        panic!("Scalar r is zero. Cannot create signature.");
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

    let h_hash = hashi(4, &h_msg);
    let h = Scalar::from_bytes_mod_order_wide(&h_hash);

    // 8. s = r + (h * a) (mod q)
    let s = r + (h * a);

    // 9. v = hash5(cV) (mod 2^256, which basically means take 32 bytes)
    // cV means V multiplied by cofactor (8)
    let cV_point = V.mul_by_cofactor();
    let cV_bytes = cV_point.compress().to_bytes();

    let v_hash_full = hashi(5, &cV_bytes);
    let mut v = [0u8; 32];
    v.copy_from_slice(&v_hash_full[0..32]);

    // 10. return (V || h || s), v
    let mut signature = [0u8; 96];
    signature[0..32].copy_from_slice(&V_bytes);
    signature[32..64].copy_from_slice(&h.to_bytes());
    signature[64..96].copy_from_slice(&s.to_bytes());

    // Fixed: Returns 'v' (VRF output) instead of 'V_bytes' (Part of signature)
    VXEdDSAOutput {
        signature: signature,
        vrf: v,
    }
}

// pub fn vxeddsa_sign(k: [u8; 32], M: &[u8; 32]) -> ([u8; 96], [u8; 32]) {
//     let (a, A) = calculate_key_pair(k);
//
//     let a_bytes = A.compress().to_bytes();
//     let mut point_msg = Vec::with_capacity(a_bytes.iter().len() + M.len());
//     point_msg.extend_from_slice(&a_bytes);
//     point_msg.extend_from_slice(M);
//
//     // We are using the Elligator2 according to the VXEdDSA protocol
//     // It was deprecated back in 2023 in favour of RFC 9380
//     // It's still secure cryptographically (atleast for now)
//     // We currently plan to follow signal and their implementation
//     #[allow(deprecated)]
//     // Map to curve (Elligator 2) and clear cofactor (multiply by 8)
//     let Bv = EdwardsPoint::nonspec_map_to_curve::<Sha512>(&point_msg).mul_by_cofactor();
//
//     // 3. V = a * Bv
//     let V = Bv * a;
//     let V_bytes = V.compress().to_bytes();
//
//     use rand_core::RngCore;
//     let mut z = [0u8; 32];
//     let mut rng = OsRng;
//     rng.fill_bytes(&mut z);
//
//     // 4. r = hash3(a || V || Z) (mod q)
//     // We concatenate bytes into a Vec for the hash input
//     let mut r_msg = Vec::new();
//     r_msg.extend_from_slice(a.as_bytes());
//     r_msg.extend_from_slice(&V_bytes);
//     r_msg.extend_from_slice(&z);
//
//     let r_hash = hashi(3, &r_msg);
//
//     let r = Scalar::from_bytes_mod_order_wide(&r_hash);
//
//     if r == Scalar::ZERO {
//         panic!("Scalar r is zero. Cannot create signature.");
//     }
//
//     // 5. R = r * B
//     let R_point = ED25519_BASEPOINT_POINT * r;
//     let R_bytes = R_point.compress().to_bytes();
//
//     // 6. Rv = r * Bv
//     let Rv_point = Bv * r;
//     let Rv_bytes = Rv_point.compress().to_bytes();
//
//     // 7. h = hash4(A || V || R || Rv || M) (mod q)
//     let mut h_msg = Vec::new();
//     h_msg.extend_from_slice(&a_bytes);
//     h_msg.extend_from_slice(&V_bytes);
//     h_msg.extend_from_slice(&R_bytes);
//     h_msg.extend_from_slice(&Rv_bytes);
//     h_msg.extend_from_slice(M);
//
//     let h_hash = hashi(4, &h_msg);
//     let h = Scalar::from_bytes_mod_order_wide(&h_hash);
//
//     // 8. s = r + (h * a) (mod q)
//     let s = r + (h * a);
//
//     // 9. v = hash5(cV) (mod 2^256, which basically means take 32 bytes)
//     // cV means V multiplied by cofactor (8)
//     let cV_point = V.mul_by_cofactor();
//     let cV_bytes = cV_point.compress().to_bytes();
//
//     let v_hash_full = hashi(5, &cV_bytes);
//     let mut v = [0u8; 32];
//     v.copy_from_slice(&v_hash_full[0..32]);
//
//     // 10. return (V || h || s), v
//     let mut signature = [0u8; 96];
//     signature[0..32].copy_from_slice(&V_bytes);
//     signature[32..64].copy_from_slice(&h.to_bytes());
//     signature[64..96].copy_from_slice(&s.to_bytes());
//
//     // Fixed: Returns 'v' (VRF output) instead of 'V_bytes' (Part of signature)
//     (signature, v)
// }

/// Verifies a VXEdDSA signature and derives the VRF output.
///
/// Checks that the provided signature is valid for the given public key `u` and message `M`.
/// If valid, it returns the VRF output `v`.
///
/// # Arguments
///
/// * `u` - The X25519 public key (Montgomery u-coordinate) as a 32-byte array.
/// * `M` - A reference to the message bytes.
/// * `signature` - The 96-byte signature array (containing `V`, `h`, and `s`).
///
/// # Returns
///
/// * `Some([u8; 32])` - The VRF output `v` if the signature is valid.
/// * `None` - If the signature is invalid, the point `u` is invalid, or any identity checks fail.
#[unsafe(no_mangle)]
pub extern "C" fn vxeddsa_verify(
    u: &[u8; 32],
    M: &[u8; 32],
    signature: &[u8; 96],
    v_out: *mut [u8; 32],
) -> bool {
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
    let Bv = EdwardsPoint::nonspec_map_to_curve::<Sha512>(&point_msg).mul_by_cofactor();

    // --- 4. Check for identity points ---
    if A.is_identity() || V.is_identity() || Bv.is_identity() {
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

    let hcheck_hash = hashi(4, &h_msg);
    let hcheck = Scalar::from_bytes_mod_order_wide(&hcheck_hash);

    // --- 8. if bytes_equal(h, hcheck) ---
    if h != hcheck {
        return false;
    }

    // --- 9. Success: return v ---
    // cV means V multiplied by cofactor (8)
    let cV_point = V.mul_by_cofactor();
    let cV_bytes = cV_point.compress().to_bytes();

    let v_hash_full = hashi(5, &cV_bytes);

    // Write output to pointer if not null
    if !v_out.is_null() {
        unsafe {
            (*v_out).copy_from_slice(&v_hash_full[0..32]);
        }
    }

    true
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

