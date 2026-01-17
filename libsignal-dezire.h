#ifndef LIBSIGNAL_DEZIRE_H
#define LIBSIGNAL_DEZIRE_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// ============================================================================
// VXEdDSA FFI
// ============================================================================

/**
 * Genrates VXEdDSA compatible keypair
 * # Returns
 *
 * A tuple `([u8; 32], [u8; 32])` containing:
 * 1. The Montgomary Private Key
 * 2. The Montgomary Public Key
 *
 */
typedef struct KeyPair {
  uint8_t secret[32];
  uint8_t public_[32];
} KeyPair;

typedef struct VXEdDSAOutput {
  uint8_t signature[96];
  uint8_t vrf[32];
} VXEdDSAOutput;

struct KeyPair gen_keypair_ffi(void);

void gen_pubkey_ffi(const uint8_t *k, uint8_t *pubkey);

void gen_secret_ffi(uint8_t *out);

/**
 * Computes a VXEdDSA signature and generates the associated VRF output.
 *
 * This function implements the signing logic specified in the VXEdDSA protocol (Signal).
 * It produces a deterministic signature and a proof of randomness (v).
 *
 * # Arguments
 *
 * * `k` - The 32-byte Montgomary private key. Note that this is the raw seed, not the clamped scalar.
 * * `msg_ptr` - A reference to the message buffer.
 * * `msg_len` - The length of the message.
 * * `output` - Pointer to write the output struct to.
 *
 * # Returns
 *
 * 0 on success, -1 on error.
 */
int32_t vxeddsa_sign_ffi(const uint8_t *k,
                         const uint8_t *msg_ptr,
                         size_t msg_len,
                         struct VXEdDSAOutput *output);

/**
 * Verifies a VXEdDSA signature.
 *
 * # Arguments
 * * `u` - The public key (32 bytes).
 * * `msg_ptr` - Message buffer.
 * * `msg_len` - Message length.
 * * `signature` - Signature (96 bytes).
 * * `v_out` - Optional pointer to write VRF output (32 bytes) if not NULL.
 *
 * # Returns
 * true if valid, false otherwise.
 */
bool vxeddsa_verify_ffi(const uint8_t *u,
                        const uint8_t *msg_ptr,
                        size_t msg_len,
                        const uint8_t *signature,
                        uint8_t *v_out);

// ============================================================================
// X3DH FFI
// ============================================================================

typedef struct X3DHInitOutput {
    uint8_t shared_secret[32];
    uint8_t ephemeral_public[32];
    int32_t status; // 0 = Success, -1 = Invalid Signature, -2 = Invalid Key, -3 = Missing OneTimeKey
} X3DHInitOutput;

/**
 * Alice (Initiator) performs the X3DH key agreement.
 *
 * # Arguments
 * * `identity_private` - Alice's identity private key (32 bytes).
 * * `bob_identity_public` - Bob's identity public key (32 bytes).
 * * `bob_spk_id` - Bob's Signed PreKey ID.
 * * `bob_spk_public` - Bob's Signed PreKey public key (32 bytes).
 * * `bob_spk_signature` - Bob's Signed PreKey signature (96 bytes).
 * * `bob_opk_id` - Bob's One-Time PreKey ID.
 * * `bob_opk_public` - Bob's One-Time PreKey public key (optional, can be NULL/unused if has_opk=false).
 * * `has_opk` - Whether a One-Time PreKey is present.
 * * `output` - Pointer to write the result struct.
 *
 * # Returns
 * Status code (same as output->status).
 */
int32_t x3dh_initiator_ffi(
    const uint8_t *identity_private,
    const uint8_t *bob_identity_public,
    uint32_t bob_spk_id,
    const uint8_t *bob_spk_public,
    const uint8_t *bob_spk_signature,
    uint32_t bob_opk_id,
    const uint8_t *bob_opk_public,
    bool has_opk,
    struct X3DHInitOutput *output
);

/**
 * Bob (Responder) performs the X3DH key agreement.
 *
 * # Arguments
 * * `identity_private` - Bob's identity private key (32 bytes).
 * * `signed_prekey_private` - Bob's signed prekey private key (32 bytes).
 * * `one_time_prekey_private` - Bob's one-time prekey private key (optional, can be NULL if has_opk=false).
 * * `has_opk` - Whether a One-Time PreKey is used.
 * * `alice_identity_public` - Alice's identity public key (32 bytes).
 * * `alice_ephemeral_public` - Alice's ephemeral public key (32 bytes).
 * * `shared_secret_out` - Buffer to write the 32-byte shared secret.
 *
 * # Returns
 * 0 on success, < 0 on error.
 */
int32_t x3dh_responder_ffi(
    const uint8_t *identity_private,
    const uint8_t *signed_prekey_private,
    const uint8_t *one_time_prekey_private,
    bool has_opk,
    const uint8_t *alice_identity_public,
    const uint8_t *alice_ephemeral_public,
    uint8_t *shared_secret_out
);

// ============================================================================
// Ratchet FFI
// ============================================================================

typedef struct RatchetState RatchetState;

typedef struct RatchetEncryptResult {
  uint8_t *header;
  size_t header_len;
  uint8_t *ciphertext;
  size_t ciphertext_len;
  int32_t status;
} RatchetEncryptResult;

typedef struct RatchetDecryptResult {
  uint8_t *plaintext;
  size_t plaintext_len;
  int32_t status;
} RatchetDecryptResult;

void ratchet_free_result_buffers(uint8_t *header, size_t header_len, uint8_t *ciphertext, size_t ciphertext_len);

void ratchet_free_byte_buffer(uint8_t *buffer, size_t len);

RatchetState *ratchet_init_sender_ffi(const uint8_t sk[32], const uint8_t receiver_dh_public[32]);

RatchetState *ratchet_init_receiver_ffi(const uint8_t sk[32], const uint8_t receiver_dh_private[32], const uint8_t receiver_dh_public[32]);

void ratchet_free_ffi(RatchetState *state);

int32_t ratchet_encrypt_ffi(RatchetState *state, const uint8_t *plaintext, size_t plaintext_len, const uint8_t *ad, size_t ad_len, RatchetEncryptResult *output);

int32_t ratchet_decrypt_ffi(RatchetState *state, const uint8_t *header, size_t header_len, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *ad, size_t ad_len, RatchetDecryptResult *output);

#endif /* LIBSIGNAL_DEZIRE_H */
