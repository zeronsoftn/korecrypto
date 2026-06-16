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

// ARIA is a Korean national standard block cipher (KS X 1213, RFC 5794) and a
// KCMVP validation-target algorithm. It has a 128-bit block and supports
// 128-, 192-, and 256-bit keys.

#ifndef OPENSSL_HEADER_ARIA_H
#define OPENSSL_HEADER_ARIA_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// ARIA_BLOCK_SIZE is the block size, in bytes, of the ARIA cipher.
#define ARIA_BLOCK_SIZE 16

// ARIA_MAXNR is the maximum number of ARIA rounds (256-bit keys).
#define ARIA_MAXNR 16

// ARIA_KEY holds an expanded ARIA key schedule. ARIA decryption reuses the
// encryption round function with a transformed key schedule, so the same
// |ARIA_encrypt_block| routine serves both directions depending on whether the
// schedule was produced by |ARIA_set_encrypt_key| or |ARIA_set_decrypt_key|.
typedef struct aria_key_st {
  uint8_t rk[ARIA_MAXNR + 1][ARIA_BLOCK_SIZE];
  unsigned rounds;
} ARIA_KEY;

// ARIA_set_encrypt_key configures |aria_key| to encrypt with |key|, which is
// |bits| bits long. |bits| must be 128, 192, or 256. It returns zero on success
// and a negative number on error.
OPENSSL_EXPORT int ARIA_set_encrypt_key(const uint8_t *key, unsigned bits,
                                        ARIA_KEY *aria_key);

// ARIA_set_decrypt_key configures |aria_key| to decrypt with |key|, which is
// |bits| bits long. |bits| must be 128, 192, or 256. It returns zero on success
// and a negative number on error.
OPENSSL_EXPORT int ARIA_set_decrypt_key(const uint8_t *key, unsigned bits,
                                        ARIA_KEY *aria_key);

// ARIA_encrypt_block applies the ARIA round function to the single 16-byte
// block |in|, writing the result to |out|, using the schedule in |key|. When
// |key| was produced by |ARIA_set_decrypt_key| this performs decryption.
OPENSSL_EXPORT void ARIA_encrypt_block(const uint8_t in[ARIA_BLOCK_SIZE],
                                       uint8_t out[ARIA_BLOCK_SIZE],
                                       const ARIA_KEY *key);


// EVP cipher getters. These mirror the corresponding |EVP_aes_*| accessors.

OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_128_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_128_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_128_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_192_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_192_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_192_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_256_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_256_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_256_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_128_gcm(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_192_gcm(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_aria_256_gcm(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_ARIA_H
