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

// Hash_DRBG and HMAC_DRBG (SP 800-108... SP 800-90A) deterministic random bit
// generators, KCMVP validation-target algorithms. The caller supplies the
// entropy input (and nonce); these implementations do not gather entropy
// themselves. CTR_DRBG is provided separately by BoringSSL (ctrdrbg.h).

#ifndef OPENSSL_HEADER_DRBG_KCMVP_H
#define OPENSSL_HEADER_DRBG_KCMVP_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// HASH_DRBG_MAX_SEEDLEN is the seed length in bytes for the 888-bit seedlen
// family (SHA-384/512, LSH-512).
#define HASH_DRBG_MAX_SEEDLEN 111

// HASH_DRBG holds Hash_DRBG state. Treat the fields as opaque.
typedef struct hash_drbg_st {
  const EVP_MD *md;
  size_t seedlen;  // bytes
  uint8_t v[HASH_DRBG_MAX_SEEDLEN];
  uint8_t c[HASH_DRBG_MAX_SEEDLEN];
  uint64_t reseed_counter;
} HASH_DRBG;

// HMAC_DRBG holds HMAC_DRBG state. Treat the fields as opaque.
typedef struct hmac_drbg_st {
  const EVP_MD *md;
  size_t outlen;  // bytes
  uint8_t k[64];
  uint8_t v[64];
  uint64_t reseed_counter;
} HMAC_DRBG;

// HASH_DRBG_init instantiates |drbg| with the given |md|, entropy, nonce, and
// optional personalization string. It returns one on success and zero on error.
OPENSSL_EXPORT int HASH_DRBG_init(HASH_DRBG *drbg, const EVP_MD *md,
                                  const uint8_t *entropy, size_t entropy_len,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *perso, size_t perso_len);

// HASH_DRBG_reseed reseeds |drbg| with fresh entropy and optional additional
// input. It returns one on success and zero on error.
OPENSSL_EXPORT int HASH_DRBG_reseed(HASH_DRBG *drbg, const uint8_t *entropy,
                                    size_t entropy_len, const uint8_t *addtl,
                                    size_t addtl_len);

// HASH_DRBG_generate writes |out_len| pseudorandom bytes to |out| with optional
// additional input. It returns one on success and zero on error.
OPENSSL_EXPORT int HASH_DRBG_generate(HASH_DRBG *drbg, uint8_t *out,
                                      size_t out_len, const uint8_t *addtl,
                                      size_t addtl_len);

// HMAC_DRBG_init, HMAC_DRBG_reseed, HMAC_DRBG_generate are the HMAC_DRBG
// analogues of the Hash_DRBG functions above.
OPENSSL_EXPORT int HMAC_DRBG_init(HMAC_DRBG *drbg, const EVP_MD *md,
                                  const uint8_t *entropy, size_t entropy_len,
                                  const uint8_t *nonce, size_t nonce_len,
                                  const uint8_t *perso, size_t perso_len);
OPENSSL_EXPORT int HMAC_DRBG_reseed(HMAC_DRBG *drbg, const uint8_t *entropy,
                                    size_t entropy_len, const uint8_t *addtl,
                                    size_t addtl_len);
OPENSSL_EXPORT int HMAC_DRBG_generate(HMAC_DRBG *drbg, uint8_t *out,
                                      size_t out_len, const uint8_t *addtl,
                                      size_t addtl_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_DRBG_KCMVP_H
