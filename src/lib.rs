//! # Signal Protocol Rust Library
//!
//! This library provides a Rust implementation of the Signal Protocol's VXEdDSA signing scheme
//! and other related cryptographic primitives. It is designed to be used as a core library
//! for Signal client implementations.
//!
//! ## Modules
//!
//! * `vxeddsa` - Implementation of the VXEdDSA signing scheme.
//! * `utils` - Utility functions for curve operations and key conversions.
//! * `hashes` - Cryptographic hash function abstractions.

pub mod hashes;
pub mod utils;
pub mod vxeddsa;
