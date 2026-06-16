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

// LEA is a Korean national standard lightweight block cipher (KS X 3246,
// ISO/IEC 29192-2) and a KCMVP validation-target algorithm. It has a 128-bit
// block and supports 128-, 192-, and 256-bit keys. LEA is an ARX cipher;
// unlike ARIA, encryption and decryption use distinct round functions over the
// same key schedule.

#ifndef OPENSSL_HEADER_LEA_H
#define OPENSSL_HEADER_LEA_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// LEA_BLOCK_SIZE is the block size, in bytes, of the LEA cipher.
#define LEA_BLOCK_SIZE 16

// LEA_MAX_ROUNDS is the number of rounds for 256-bit keys (the maximum).
#define LEA_MAX_ROUNDS 32

// LEA_KEY holds an expanded LEA key schedule (six 32-bit round-key words per
// round). The same schedule is used for both encryption and decryption.
typedef struct lea_key_st {
  uint32_t rk[LEA_MAX_ROUNDS][6];
  unsigned rounds;
} LEA_KEY;

// LEA_set_key expands |key|, which is |bits| bits long (128, 192, or 256), into
// |lea_key|. It returns zero on success and a negative number on error.
OPENSSL_EXPORT int LEA_set_key(const uint8_t *key, unsigned bits,
                               LEA_KEY *lea_key);

// LEA_encrypt_block encrypts the single 16-byte block |in| to |out|.
OPENSSL_EXPORT void LEA_encrypt_block(const uint8_t in[LEA_BLOCK_SIZE],
                                      uint8_t out[LEA_BLOCK_SIZE],
                                      const LEA_KEY *key);

// LEA_decrypt_block decrypts the single 16-byte block |in| to |out|.
OPENSSL_EXPORT void LEA_decrypt_block(const uint8_t in[LEA_BLOCK_SIZE],
                                      uint8_t out[LEA_BLOCK_SIZE],
                                      const LEA_KEY *key);


// EVP cipher getters, mirroring the |EVP_aes_*| / |EVP_aria_*| accessors.

OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_128_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_128_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_128_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_128_gcm(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_192_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_192_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_192_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_192_gcm(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_256_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_256_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_256_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_lea_256_gcm(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_LEA_H
