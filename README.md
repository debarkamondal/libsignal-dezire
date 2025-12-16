# libsignal-dezire

A Rust implementation of the VXEdDSA signing scheme by Signal, designed for high-performance and secure cryptographic operations. This library also provides C-compatible FFI bindings for integration with other languages.

## Features

- **VXEdDSA Signing & Verification**: Secure deterministic signatures with verifiable randomness.
- **X25519 & Ed25519 Interop**: Utilities to convert between Montgomery and Edwards curve points.
- **FFI Support**: `extern "C"` functions for key generation and secret management, suitable for calling from C/C++, iOS (Swift), and Android (Kotlin/JNI).

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
libsignal-dezire = { git = "https://github.com/debarkamondal/libsignal-dezire" }
```

*Note: As this is a specific implementation, please check the version compatibility.*

## Usage

### Rust Example

```rust
use libsignal_dezire::vxeddsa::{vxeddsa_sign, vxeddsa_verify};
use libsignal_dezire::utils::calculate_key_pair;
use rand_core::{OsRng, RngCore};

fn main() {
    // 1. Generate a random private key seed
    let mut seed_k = [0u8; 32];
    OsRng.fill_bytes(&mut seed_k);

    // 2. Define a message to sign
    let message = b"Hello, VXEdDSA!";
    let mut msg_bytes = [0u8; 32];
    // In a real app, hash the message to 32 bytes
    msg_bytes[0..message.len()].copy_from_slice(message);

    // 3. Sign
    let (signature, vrf_output) = vxeddsa_sign(seed_k, &msg_bytes);

    // 4. Verify
    // Derive public key for verification
    let (_, public_point) = calculate_key_pair(seed_k);
    let public_u = public_point.to_montgomery().to_bytes();

    let verified_vrf = vxeddsa_verify(public_u, &msg_bytes, &signature);

    assert_eq!(verified_vrf.unwrap(), vrf_output);
    println!("Signature verified successfully!");
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-v3 License - see the [LICENSE](LICENSE) file for details.
