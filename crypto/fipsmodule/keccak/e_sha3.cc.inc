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

// EVP_MD wrappers exposing SHA-3 (FIPS 202), a KCMVP validation-target hash,
// over the existing BCM Keccak implementation (keccak.cc.inc, included just
// before this file in bcm.cc).

#include <openssl/digest.h>
#include <openssl/nid.h>

#include "../../internal.h"
#include "../delocate.h"
#include "../digest/internal.h"
#include "internal.h"


using namespace bssl;

static void sha3_224_init(EVP_MD_CTX *ctx) {
  BORINGSSL_keccak_init(
      reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data), boringssl_sha3_224);
}
static void sha3_256_init(EVP_MD_CTX *ctx) {
  BORINGSSL_keccak_init(
      reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data), boringssl_sha3_256);
}
static void sha3_384_init(EVP_MD_CTX *ctx) {
  BORINGSSL_keccak_init(
      reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data), boringssl_sha3_384);
}
static void sha3_512_init(EVP_MD_CTX *ctx) {
  BORINGSSL_keccak_init(
      reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data), boringssl_sha3_512);
}

static void sha3_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  BORINGSSL_keccak_absorb(reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data),
                          reinterpret_cast<const uint8_t *>(data), count);
}

static void sha3_final(EVP_MD_CTX *ctx, uint8_t *out) {
  auto *kctx = reinterpret_cast<BORINGSSL_keccak_st *>(ctx->md_data);
  // For a fixed-output configuration the digest is produced by a single
  // squeeze of the required length.
  BORINGSSL_keccak_squeeze(kctx, out, kctx->required_out_len);
}

#define DEFINE_SHA3_MD(name, nid_val, md_sz, init_fn, blk)         \
  DEFINE_METHOD_FUNCTION(EVP_MD, name) {                           \
    out->type = (nid_val);                                        \
    out->md_size = (md_sz);                                       \
    out->flags = 0;                                              \
    out->init = (init_fn);                                       \
    out->update = sha3_update;                                   \
    out->final = sha3_final;                                     \
    out->block_size = (blk);                                     \
    out->ctx_size = sizeof(BORINGSSL_keccak_st);                 \
  }

// block_size is the SHA-3 rate in bytes (200 - 2*md_size).
DEFINE_SHA3_MD(EVP_sha3_224, NID_sha3_224, 28, sha3_224_init, 144)
DEFINE_SHA3_MD(EVP_sha3_256, NID_sha3_256, 32, sha3_256_init, 136)
DEFINE_SHA3_MD(EVP_sha3_384, NID_sha3_384, 48, sha3_384_init, 104)
DEFINE_SHA3_MD(EVP_sha3_512, NID_sha3_512, 64, sha3_512_init, 72)
