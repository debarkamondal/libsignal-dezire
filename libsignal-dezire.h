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
    int32_t status; // 0 = Success, -1 = Invalid Signature, -2 = Invalid Key, -3 = Missing OTK
} X3DHInitOutput;

typedef struct X3DHResponderOutput {
    uint8_t shared_secret[32];
    int32_t status; // 0 = Success, -1 = Invalid Key, -2 = Other Error
} X3DHResponderOutput;

typedef struct X3DHBundleInput {
    uint8_t identity_public[32];
    uint32_t spk_id;
    uint8_t spk_public[32];
    uint8_t spk_signature[96];
    uint32_t opk_id;          // ignored if has_opk = false
    uint8_t opk_public[32];   // ignored if has_opk = false
    bool has_opk;
} X3DHBundleInput;

typedef struct X3DHResponderInput {
    uint8_t identity_private[32];
    uint8_t spk_private[32];
    uint8_t opk_private[32];  // ignored if has_opk = false
    bool has_opk;
} X3DHResponderInput;

typedef struct X3DHAliceKeys {
    uint8_t identity_public[32];
    uint8_t ephemeral_public[32];
} X3DHAliceKeys;

/**
 * Alice (Initiator) performs the X3DH key agreement.
 *
 * # Arguments
 * * `identity_private` - Alice's identity private key (32 bytes).
 * * `bundle` - Pointer to Bob's PreKey bundle input struct.
 * * `output` - Pointer to write the result struct. Check output->status for result.
 */
void x3dh_initiator_ffi(
    const uint8_t *identity_private,
    const X3DHBundleInput *bundle,
    X3DHInitOutput *output
);

/**
 * Bob (Responder) performs the X3DH key agreement.
 *
 * # Arguments
 * * `responder` - Pointer to Bob's responder keys input struct.
 * * `alice` - Pointer to Alice's keys struct.
 * * `output` - Pointer to write the result struct. Check output->status for result.
 */
void x3dh_responder_ffi(
    const X3DHResponderInput *responder,
    const X3DHAliceKeys *alice,
    X3DHResponderOutput *output
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

// ============================================================================
// Utils FFI
// ============================================================================

/**
 * Encodes a public key by prepending 0x05 (Curve25519) to the 32-byte key.
 *
 * # Arguments
 * * `key` - The 32-byte public key to encode.
 * * `out` - Buffer to write the 33-byte encoded key (must be pre-allocated).
 */
void encode_public_key_ffi(const uint8_t key[32], uint8_t *out);

#endif /* LIBSIGNAL_DEZIRE_H */
