//! FFI module - C and JNI bindings for cryptographic operations.
//!
//! This module provides FFI-safe wrappers around the native Rust APIs to support
//! integration with other languages, specifically C/C++ (iOS) and Java/Kotlin (Android).
//!
//! ## Submodules
//!
//! * `vxeddsa`: C and JNI bindings for VXEdDSA signing/validation.
//! * `x3dh`: C and JNI bindings for X3DH key agreement.
//! * `utils`: Helper functions exposed via FFI.
//!
//! ## Safety
//!
//! All `extern "C"` functions in this module are unsafe because they dereference raw pointers.
//! The caller is responsible for ensuring:
//! * Pointers are valid and properly aligned.
//! * Memory is allocated and freed correctly.
//! * Initialized data structures match the C representation.

pub mod ratchet;
pub mod utils;
pub mod vxeddsa;
pub mod x3dh;
