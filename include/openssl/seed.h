// Copyright 2024 The BoringSSL / korecrypto Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// SEED is a Korean national standard block cipher (KS X 1213-1 / RFC 4269) and
// a KCMVP validation-target algorithm. It has a 128-bit block and a 128-bit
// key.

#ifndef OPENSSL_HEADER_SEED_H
#define OPENSSL_HEADER_SEED_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// SEED_BLOCK_SIZE is the block size, in bytes, of the SEED cipher.
#define SEED_BLOCK_SIZE 16

// SEED_KEY_LENGTH is the key size, in bytes, of the SEED cipher.
#define SEED_KEY_LENGTH 16

// SEED_KEY holds an expanded SEED key schedule (16 rounds, two words each).
typedef struct seed_key_st {
  uint32_t rk[32];
} SEED_KEY;

// SEED_set_key expands the 16-byte |key| into |seed_key|. It returns zero on
// success. The same schedule is used for encryption and decryption.
OPENSSL_EXPORT int SEED_set_key(const uint8_t key[SEED_KEY_LENGTH],
                                SEED_KEY *seed_key);

// SEED_encrypt_block encrypts the single 16-byte block |in| to |out|.
OPENSSL_EXPORT void SEED_encrypt_block(const uint8_t in[SEED_BLOCK_SIZE],
                                       uint8_t out[SEED_BLOCK_SIZE],
                                       const SEED_KEY *key);

// SEED_decrypt_block decrypts the single 16-byte block |in| to |out|.
OPENSSL_EXPORT void SEED_decrypt_block(const uint8_t in[SEED_BLOCK_SIZE],
                                       uint8_t out[SEED_BLOCK_SIZE],
                                       const SEED_KEY *key);


// EVP cipher getters.

OPENSSL_EXPORT const EVP_CIPHER *EVP_seed_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_seed_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_seed_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_seed_gcm(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SEED_H
