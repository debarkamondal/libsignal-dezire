//! FFI and JNI bindings for X3DH.
//!
//! This module provides C-compatible FFI wrappers and Android JNI bindings
//! that call the memory-safe native Rust API in [`crate::x3dh`].

use crate::x3dh::{
    OneTimePreKey, PreKeyBundle, SignedPreKey, X3DHError, X3DHInitResult, x3dh_initiator,
    x3dh_responder,
};

// ============================================================================
// C FFI Types
// ============================================================================

/// Structure for returning multiple values from x3dh_initiator (C-compatible).
#[repr(C)]
pub struct X3DHInitOutput {
    pub shared_secret: [u8; 32],
    pub ephemeral_public: [u8; 32],
    pub status: i32, // 0 = Success, -1 = Invalid Signature, -2 = Invalid Key
}

impl X3DHInitOutput {
    fn from_result(result: Result<X3DHInitResult, X3DHError>) -> Self {
        match result {
            Ok(r) => X3DHInitOutput {
                shared_secret: r.shared_secret,
                ephemeral_public: r.ephemeral_public,
                status: 0,
            },
            Err(X3DHError::InvalidSignature) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 32],
                status: -1,
            },
            Err(X3DHError::InvalidKey) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 32],
                status: -2,
            },
            Err(X3DHError::MissingOneTimeKey) => X3DHInitOutput {
                shared_secret: [0u8; 32],
                ephemeral_public: [0u8; 32],
                status: -3,
            },
        }
    }
}

// ============================================================================
// C FFI Functions
// ============================================================================

/// Alice (Initiator) performs the X3DH key agreement.
///
/// This is the `extern "C"` entry point that wraps the native Rust API.
///
/// # Safety
/// * `identity_private`, `bob_identity_public`, `bob_spk_public`, `bob_spk_signature` must point to valid memory of the correct size (see types).
/// * `output` must point to a writable `X3DHInitOutput` struct.
/// * If `has_opk` is true, `bob_opk_public` must point to a valid 32-byte array.
/// * All pointers must be properly aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x3dh_initiator_ffi(
    identity_private: &[u8; 32],
    bob_identity_public: &[u8; 32],
    bob_spk_id: u32,
    bob_spk_public: &[u8; 32],
    bob_spk_signature: &[u8; 96],
    bob_opk_id: u32,
    bob_opk_public: *const u8,
    has_opk: bool,
    output: *mut X3DHInitOutput,
) {
    // Build the PreKeyBundle from raw inputs
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

    let bundle = PreKeyBundle {
        identity_key: *bob_identity_public,
        signed_prekey,
        one_time_prekey,
    };

    // Call the native Rust API
    let result = x3dh_initiator(identity_private, &bundle);

    // Write output
    unsafe {
        *output = X3DHInitOutput::from_result(result);
    }
}

/// Bob (Responder) performs the X3DH key agreement.
///
/// This is the `extern "C"` entry point that wraps the native Rust API.
///
/// # Safety
/// * `identity_private`, `signed_prekey_private` must point to valid 32-byte arrays.
/// * `alice_identity_public`, `alice_ephemeral_public` must point to valid 32-byte arrays.
/// * `shared_secret_out` must point to a writable 32-byte array.
/// * If `has_opk` is true, `one_time_prekey_private` must point to a valid 32-byte array.
/// * All pointers must be properly aligned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x3dh_responder_ffi(
    identity_private: &[u8; 32],
    signed_prekey_private: &[u8; 32],
    one_time_prekey_private: *const u8,
    has_opk: bool,
    alice_identity_public: &[u8; 32],
    alice_ephemeral_public: &[u8; 32],
    shared_secret_out: *mut [u8; 32],
) -> i32 {
    // Convert optional OPK pointer to Option<&[u8; 32]>
    let opk_private = if has_opk && !one_time_prekey_private.is_null() {
        unsafe { Some(&*(one_time_prekey_private as *const [u8; 32])) }
    } else {
        None
    };

    // Call the native Rust API
    let result = x3dh_responder(
        identity_private,
        signed_prekey_private,
        opk_private,
        alice_identity_public,
        alice_ephemeral_public,
    );

    match result {
        Ok(shared_secret) => {
            unsafe {
                *shared_secret_out = shared_secret;
            }
            0
        }
        Err(X3DHError::InvalidKey) => {
            unsafe {
                *shared_secret_out = [0u8; 32];
            }
            -1
        }
        Err(_) => {
            unsafe {
                *shared_secret_out = [0u8; 32];
            }
            -2
        }
    }
}

// ============================================================================
// JNI Bindings (Android Only)
// ============================================================================

#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::objects::{JByteArray, JObject, JValue};
#[cfg(target_os = "android")]
use jni::sys::{jbyteArray, jclass, jint, jobject};

#[cfg(target_os = "android")]
fn create_byte_array(env: &mut JNIEnv, bytes: &[u8]) -> jni::errors::Result<jbyteArray> {
    let array = env.byte_array_from_slice(bytes)?;
    Ok(array.into_raw())
}

#[cfg(target_os = "android")]
fn get_byte_array(env: &mut JNIEnv, arr: jbyteArray) -> Option<Vec<u8>> {
    if arr.is_null() {
        return None;
    }
    let obj = unsafe { JByteArray::from_raw(arr) };
    env.convert_byte_array(&obj).ok()
}

/// JNI binding for X3DH initiator.
///
/// Calls the native Rust API via the FFI wrapper.
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
    bob_opk_public_arr: jbyteArray,
) -> jobject {
    // Extract byte arrays
    let id_priv = match get_byte_array(&mut env, identity_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_id_pub = match get_byte_array(&mut env, bob_identity_public_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_spk_pub = match get_byte_array(&mut env, bob_spk_public_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_spk_sig = match get_byte_array(&mut env, bob_spk_signature_arr) {
        Some(v) if v.len() == 96 => v,
        _ => return JObject::null().into_raw(),
    };
    let bob_opk_pub = get_byte_array(&mut env, bob_opk_public_arr);

    // Convert to fixed arrays
    let id_priv_fixed: [u8; 32] = id_priv.try_into().unwrap();
    let bob_id_pub_fixed: [u8; 32] = bob_id_pub.try_into().unwrap();
    let bob_spk_pub_fixed: [u8; 32] = bob_spk_pub.try_into().unwrap();
    let bob_spk_sig_fixed: [u8; 96] = bob_spk_sig.try_into().unwrap();

    // Build PreKeyBundle and call native API directly
    let signed_prekey = SignedPreKey {
        id: bob_spk_id as u32,
        public_key: bob_spk_pub_fixed,
        signature: bob_spk_sig_fixed,
    };

    let one_time_prekey = bob_opk_pub.and_then(|opk_vec| {
        if opk_vec.len() == 32 {
            Some(OneTimePreKey {
                id: bob_opk_id as u32,
                public_key: opk_vec.try_into().unwrap(),
            })
        } else {
            None
        }
    });

    let bundle = PreKeyBundle {
        identity_key: bob_id_pub_fixed,
        signed_prekey,
        one_time_prekey,
    };

    // Call native Rust API
    let result = match x3dh_initiator(&id_priv_fixed, &bundle) {
        Ok(r) => r,
        Err(_) => return JObject::null().into_raw(),
    };

    // Return HashMap { "shared_secret": byte[], "ephemeral_public": byte[] }
    let map_class = match env.find_class("java/util/HashMap") {
        Ok(c) => c,
        Err(_) => return JObject::null().into_raw(),
    };
    let map = match env.new_object(map_class, "()V", &[]) {
        Ok(m) => m,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_array = match create_byte_array(&mut env, &result.shared_secret) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_array = match create_byte_array(&mut env, &result.ephemeral_public) {
        Ok(a) => a,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_key = match env.new_string("shared_secret") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };
    let public_key = match env.new_string("ephemeral_public") {
        Ok(s) => s,
        Err(_) => return JObject::null().into_raw(),
    };

    let secret_key_obj = JObject::from(secret_key);
    let secret_array_obj = unsafe { JObject::from_raw(secret_array) };
    let public_key_obj = JObject::from(public_key);
    let public_array_obj = unsafe { JObject::from_raw(public_array) };

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&secret_key_obj),
            JValue::Object(&secret_array_obj),
        ],
    );

    let _ = env.call_method(
        &map,
        "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        &[
            JValue::Object(&public_key_obj),
            JValue::Object(&public_array_obj),
        ],
    );

    map.into_raw()
}

/// JNI binding for X3DH responder.
///
/// Calls the native Rust API directly.
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_expo_modules_libsignaldezire_LibsignalDezireModule_x3dhResponder(
    mut env: JNIEnv,
    _class: jclass,
    identity_private_arr: jbyteArray,
    signed_prekey_private_arr: jbyteArray,
    one_time_prekey_private_arr: jbyteArray,
    alice_identity_public_arr: jbyteArray,
    alice_ephemeral_public_arr: jbyteArray,
) -> jbyteArray {
    // Extract byte arrays
    let id_priv = match get_byte_array(&mut env, identity_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let spk_priv = match get_byte_array(&mut env, signed_prekey_private_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let alice_id_pub = match get_byte_array(&mut env, alice_identity_public_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let alice_ek_pub = match get_byte_array(&mut env, alice_ephemeral_public_arr) {
        Some(v) if v.len() == 32 => v,
        _ => return std::ptr::null_mut(),
    };
    let opk_priv = get_byte_array(&mut env, one_time_prekey_private_arr);

    // Convert to fixed arrays
    let id_priv_fixed: [u8; 32] = id_priv.try_into().unwrap();
    let spk_priv_fixed: [u8; 32] = spk_priv.try_into().unwrap();
    let alice_id_pub_fixed: [u8; 32] = alice_id_pub.try_into().unwrap();
    let alice_ek_pub_fixed: [u8; 32] = alice_ek_pub.try_into().unwrap();

    let opk_priv_opt: Option<[u8; 32]> = opk_priv.and_then(|v| {
        if v.len() == 32 {
            Some(v.try_into().unwrap())
        } else {
            None
        }
    });

    // Call native Rust API directly
    let result = x3dh_responder(
        &id_priv_fixed,
        &spk_priv_fixed,
        opk_priv_opt.as_ref(),
        &alice_id_pub_fixed,
        &alice_ek_pub_fixed,
    );

    match result {
        Ok(shared_secret) => {
            create_byte_array(&mut env, &shared_secret).unwrap_or(std::ptr::null_mut())
        }
        Err(_) => std::ptr::null_mut(),
    }
}
