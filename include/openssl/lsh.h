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

// LSH is a Korean national standard hash function (KS X 3262) and a KCMVP
// validation-target algorithm. It has two families: LSH-256 (32-bit words,
// 128-byte block) producing up to 256-bit digests, and LSH-512 (64-bit words,
// 256-byte block) producing up to 512-bit digests.

#ifndef OPENSSL_HEADER_LSH_H
#define OPENSSL_HEADER_LSH_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// EVP_MD getters for the KCMVP LSH variants.

OPENSSL_EXPORT const EVP_MD *EVP_lsh256_224(void);
OPENSSL_EXPORT const EVP_MD *EVP_lsh256_256(void);
OPENSSL_EXPORT const EVP_MD *EVP_lsh512_224(void);
OPENSSL_EXPORT const EVP_MD *EVP_lsh512_256(void);
OPENSSL_EXPORT const EVP_MD *EVP_lsh512_384(void);
OPENSSL_EXPORT const EVP_MD *EVP_lsh512_512(void);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_LSH_H
