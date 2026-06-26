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

// HIGHT is a Korean national standard lightweight block cipher (KS X 1213-2)
// and a KCMVP validation-target algorithm. It has a 64-bit block and a 128-bit
// key. Because the block is 64 bits, only ECB/CBC/CTR are provided (GCM/CCM
// require a 128-bit block).

#ifndef OPENSSL_HEADER_HIGHT_H
#define OPENSSL_HEADER_HIGHT_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// HIGHT_BLOCK_SIZE is the block size, in bytes, of the HIGHT cipher.
#define HIGHT_BLOCK_SIZE 8

// HIGHT_KEY_LENGTH is the key size, in bytes, of the HIGHT cipher.
#define HIGHT_KEY_LENGTH 16

// HIGHT_KEY holds an expanded HIGHT key schedule: 8 whitening keys followed by
// 128 round-key bytes.
typedef struct hight_key_st {
  uint8_t rk[136];
} HIGHT_KEY;

// HIGHT_set_key expands the 16-byte |key| into |hight_key|. It returns zero on
// success.
OPENSSL_EXPORT int HIGHT_set_key(const uint8_t key[HIGHT_KEY_LENGTH],
                                 HIGHT_KEY *hight_key);

// HIGHT_encrypt_block encrypts the single 8-byte block |in| to |out|.
OPENSSL_EXPORT void HIGHT_encrypt_block(const uint8_t in[HIGHT_BLOCK_SIZE],
                                        uint8_t out[HIGHT_BLOCK_SIZE],
                                        const HIGHT_KEY *key);

// HIGHT_decrypt_block decrypts the single 8-byte block |in| to |out|.
OPENSSL_EXPORT void HIGHT_decrypt_block(const uint8_t in[HIGHT_BLOCK_SIZE],
                                        uint8_t out[HIGHT_BLOCK_SIZE],
                                        const HIGHT_KEY *key);


// EVP cipher getters.

OPENSSL_EXPORT const EVP_CIPHER *EVP_hight_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_hight_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_hight_ctr(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_HIGHT_H
