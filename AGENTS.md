# Agentic Development Guide for libsignal-dezire

This document provides instructions, standards, and workflows for AI agents and developers working on the `libsignal-dezire` repository. This is a cryptographic library implementing the Signal Protocol; correctness, security, and performance are paramount.

## 1. Environment & Commands

The project uses standard Rust tooling (`cargo`).

### Build
- **Check (Fast):** `cargo check`
- **Build (Dev):** `cargo build`
- **Build (Release):** `cargo build --release`
- **Clean:** `cargo clean`

### Testing
- **Run All Tests:** `cargo test`
- **Run Specific Test:** `cargo test <test_name>`
  - *Example:* `cargo test test_ratchet_basic_flow`
- **Run Tests with Output:** `cargo test -- --nocapture`
- **Run Ignored Tests:** `cargo test -- --ignored`

### Code Quality
- **Format:** `cargo fmt` (Always run this before committing)
- **Lint:** `cargo clippy -- -D warnings` (Ensure no warnings)
- **Documentation:** `cargo doc --open`

## 2. Project Structure

- **`src/`**: Source code.
  - `lib.rs`: Crate root, module exports.
  - `ratchet.rs`: Double Ratchet implementation.
  - `x3dh.rs`: Extended Triple Diffie-Hellman.
  - `vxeddsa.rs`: VXEdDSA signatures.
  - `ffi/`: Foreign Function Interface (C/JNI).
- **`tests/`**: Integration tests.
  - `ratchet_test.rs`: Tests for the ratchet module.
  - `e2e_*.rs`: End-to-end scenarios.

## 3. Code Style & Conventions

### General Rust Style
- **Formatting:** Strictly follow `rustfmt` defaults (4 spaces indent).
- **Naming:**
  - Structs/Enums: `PascalCase`
  - Functions/Variables/Modules: `snake_case`
  - Constants: `SCREAMING_SNAKE_CASE`
- **Imports:** Group imports at the top of the file.
  ```rust
  // Std
  use std::collections::HashMap;

  // External crates
  use aes_gcm::Aes256Gcm;
  use zeroize::Zeroize;

  // Internal modules
  use crate::ratchet::RatchetState;
  ```

### Types & Error Handling
- **Custom Errors:** Use specific error enums (e.g., `RatchetError`) rather than generic `Box<dyn Error>`.
- **Result Return:** Most public functions should return `Result<T, ErrorEnum>`.
- **Unwrap/Expect:**
  - **Forbidden** in library code (`src/`). Use `?` operator or handle errors gracefully.
  - **Allowed** in tests (`tests/` and `#[cfg(test)]`) for brevity.

### Documentation
- **Module Level:** Use `//!` at the top of files to describe the module's purpose and spec references.
- **Public API:** Use `///` doc comments for all public structs, enums, and functions.
- **Examples:** Include code examples in doc comments where complex usage is involved.

## 4. Security & Cryptography Mandates

**CRITICAL:** This is a security-sensitive codebase.

1.  **Zeroization:**
    -   All structs containing private keys or sensitive state MUST derive `Zeroize` and `ZeroizeOnDrop`.
    -   Explicitly call `.zeroize()` on temporary sensitive variables (buffers, intermediate keys) before they go out of scope if `ZeroizeOnDrop` cannot be used.

2.  **Constant-Time Operations:**
    -   NEVER compare secrets or tags using `==`.
    -   Use `subtle::ConstantTimeEq` (e.g., `ct_eq`) for checking MACs, signatures, or secrets.
    -   Avoid branching on secret data.

3.  **Randomness:**
    -   Use `rand_core::OsRng` (cryptographically secure RNG) for key generation.
    -   Do not use weak RNGs like `rand::thread_rng` for crypto material.

4.  **Dependencies:**
    -   Vet new dependencies carefully.
    -   Prefer established crypto crates (`dalek`, `RustCrypto` organization) over obscure ones.

## 5. Testing Guidelines

-   **Unit Tests:** Place in the same file as the code in a `#[cfg(test)] mod tests { ... }` block.
-   **Integration Tests:** Place in `tests/*.rs`. These simulate real usage via the public API.
-   **Edge Cases:** Explicitly test for:
    -   Replay attacks (duplicate messages).
    -   Out-of-order message delivery.
    -   Malformed headers/inputs.
    -   Limit exhaustion (e.g., `MAX_SKIP` limits).

## 6. Workflow for Agents

When implementing features or fixing bugs:

1.  **Analyze Context:** Read related files first (e.g., if touching `ratchet.rs`, also read `tests/ratchet_test.rs`).
2.  **Plan:** Outline the changes. Check if they impact the state machine or crypto properties.
3.  **Implement:** Write code adhering to the style above.
4.  **Verify:**
    -   Create or update a test case covering the change.
    -   Run `cargo test <your_new_test_name>` to verify.
    -   Run `cargo clippy` to ensure no linting errors.
    -   Run `cargo fmt` to fix formatting.
5.  **Review:** Double-check strictly for security violations (leaking secrets via logs, timing side-channels).

## 7. Troubleshooting

-   **"Borrow checker errors with Zeroize":** Ensure you aren't trying to use a value after it has been dropped/zeroized.
-   **"Linker errors":** If modifying FFI, ensure C dependencies or correct target architectures are set.
-   **"Crypto test failures":** Check vector endianness (Signal often uses Big Endian for network, Little Endian for curve math).

---
*Generated for AI Agent usage within libsignal-dezire.*
