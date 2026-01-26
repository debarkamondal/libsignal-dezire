# libsignal-dezire

A pure Rust implementation of the Signal Protocol, providing end-to-end encryption for messaging applications.

## Features

- **VXEdDSA** - Verifiable XEdDSA signatures with VRF output
- **X3DH** - Extended Triple Diffie-Hellman key agreement
- **Double Ratchet** - Session encryption with forward secrecy
- **FFI/JNI** - C and Android bindings included

## Installation

```toml
[dependencies]
libsignal-dezire = "0.1.143"
```

## Quick Start

### Key Exchange (X3DH)

```rust
use libsignal_dezire::x3dh::{x3dh_initiator, x3dh_responder, PreKeyBundle};
use libsignal_dezire::vxeddsa::{gen_keypair, vxeddsa_sign};
use libsignal_dezire::utils::encode_public_key;

// Bob publishes a prekey bundle
let bob_identity = gen_keypair();
let bob_spk = gen_keypair();
let encoded_spk = encode_public_key(&bob_spk.public);
let sig = vxeddsa_sign(&bob_identity.secret, &encoded_spk).unwrap();

let bundle = PreKeyBundle {
    identity_key: bob_identity.public,
    signed_prekey: SignedPreKey { id: 1, public_key: bob_spk.public, signature: sig.signature },
    one_time_prekey: None,
};

// Alice initiates
let alice_identity = gen_keypair();
let result = x3dh_initiator(&alice_identity.secret, &bundle).unwrap();
// result.shared_secret, result.ephemeral_public

// Bob responds
let bob_sk = x3dh_responder(
    &bob_identity.secret,
    &bob_spk.secret,
    None,
    &alice_identity.public,
    &result.ephemeral_public,
).unwrap();

assert_eq!(result.shared_secret, bob_sk);
```

### Session Encryption (Double Ratchet)

```rust
use libsignal_dezire::ratchet::{init_sender_state, init_receiver_state, encrypt, decrypt};

// Initialize from X3DH shared secret
let mut alice = init_sender_state(shared_secret, bob_dh_public).unwrap();
let mut bob = init_receiver_state(shared_secret, bob_keypair);

// Encrypt
let (header, ciphertext) = encrypt(&mut alice, b"Hello Bob!", b"").unwrap();

// Decrypt
let plaintext = decrypt(&mut bob, &header, &ciphertext, b"").unwrap();
```

### Associated Data

Construct AD for AEAD when sending the initial message:

```rust
use libsignal_dezire::utils::encode_public_key;

let ad = [
    encode_public_key(&alice_identity_public),
    encode_public_key(&bob_identity_public),
].concat();  // 66 bytes
```

## FFI

For C/iOS integration, include `libsignal-dezire.h`. For Android, use the JNI bindings.

```c
#include "libsignal-dezire.h"

X3DHInitOutput output;
x3dh_initiator_ffi(identity_private, &bundle, &output);
```

## Security

- ✅ [Security Audited](AUDIT.md)
- ✅ Constant-time operations
- ✅ Memory zeroization via `zeroize` crate
- ✅ Low-order point rejection

## License

AGPL-v3 - see [LICENSE](LICENSE)
