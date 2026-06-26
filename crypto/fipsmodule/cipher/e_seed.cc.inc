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

// EVP bindings for SEED: ECB/CBC/CTR/GCM (EVP_CIPHER) and CCM (EVP_AEAD),
// following the same construction as the ARIA bindings in e_aria.cc.inc.

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/seed.h>
#include <openssl/span.h>

#include <string.h>

#include "../../internal.h"
#include "../aes/internal.h"
#include "../bcm_interface.h"
#include "../delocate.h"
#include "../service_indicator/internal.h"
#include "internal.h"

using namespace bssl;

typedef struct {
  SEED_KEY ks;
} EVP_SEED_KEY;

static int seed_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc) {
  EVP_SEED_KEY *dat = reinterpret_cast<EVP_SEED_KEY *>(ctx->cipher_data);
  if (SEED_set_key(key, &dat->ks) < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }
  return 1;
}

static int seed_ecb_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_SEED_KEY *dat = reinterpret_cast<EVP_SEED_KEY *>(ctx->cipher_data);
  for (size_t i = 0; i + SEED_BLOCK_SIZE <= len; i += SEED_BLOCK_SIZE) {
    if (ctx->encrypt) {
      SEED_encrypt_block(in + i, out + i, &dat->ks);
    } else {
      SEED_decrypt_block(in + i, out + i, &dat->ks);
    }
  }
  return 1;
}

static int seed_cbc_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_SEED_KEY *dat = reinterpret_cast<EVP_SEED_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;

  if (ctx->encrypt) {
    for (size_t i = 0; i + SEED_BLOCK_SIZE <= len; i += SEED_BLOCK_SIZE) {
      for (size_t j = 0; j < SEED_BLOCK_SIZE; j++) {
        iv[j] ^= in[i + j];
      }
      SEED_encrypt_block(iv, out + i, &dat->ks);
      memcpy(iv, out + i, SEED_BLOCK_SIZE);
    }
  } else {
    uint8_t tmp[SEED_BLOCK_SIZE];
    for (size_t i = 0; i + SEED_BLOCK_SIZE <= len; i += SEED_BLOCK_SIZE) {
      memcpy(tmp, in + i, SEED_BLOCK_SIZE);
      SEED_decrypt_block(tmp, out + i, &dat->ks);
      for (size_t j = 0; j < SEED_BLOCK_SIZE; j++) {
        out[i + j] ^= iv[j];
      }
      memcpy(iv, tmp, SEED_BLOCK_SIZE);
    }
    OPENSSL_cleanse(tmp, sizeof(tmp));
  }
  return 1;
}

static int seed_ctr_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_SEED_KEY *dat = reinterpret_cast<EVP_SEED_KEY *>(ctx->cipher_data);
  unsigned num = ctx->num;

  for (size_t i = 0; i < len; i++) {
    if (num == 0) {
      SEED_encrypt_block(ctx->iv, ctx->buf, &dat->ks);
      for (int j = SEED_BLOCK_SIZE - 1; j >= 0; j--) {
        if (++ctx->iv[j] != 0) {
          break;
        }
      }
    }
    out[i] = in[i] ^ ctx->buf[num];
    num = (num + 1) % SEED_BLOCK_SIZE;
  }

  ctx->num = num;
  return 1;
}

// ---------------------------------------------------------------------------
// SEED-GCM (and GMAC).
// ---------------------------------------------------------------------------

#define SEED_GCM_NONCE_LENGTH 12

typedef struct {
  SEED_KEY ks;
  u128 Htable[16];
  gmult_func gmult;
  ghash_func ghash;
  uint8_t Yi[16];
  uint8_t EKi[16];
  uint8_t EK0[16];
  uint8_t Xi[16];
  uint64_t aad_len;
  uint64_t msg_len;
  unsigned mres;
  unsigned ares;
  int key_set;
  int iv_set;
  uint8_t *iv;
  int ivlen;
  int taglen;
  int iv_gen;
} EVP_SEED_GCM_CTX;

static void seed_gcm_setup_key(EVP_SEED_GCM_CTX *gctx) {
  uint8_t h[16] = {0};
  SEED_encrypt_block(h, h, &gctx->ks);
  CRYPTO_ghash_init(&gctx->gmult, &gctx->ghash, gctx->Htable, h);
  OPENSSL_cleanse(h, sizeof(h));
}

static inline void seed_gcm_ctr32_inc(uint8_t Yi[16]) {
  uint32_t ctr = CRYPTO_load_u32_be(Yi + 12);
  CRYPTO_store_u32_be(Yi + 12, ctr + 1);
}

static void seed_gcm_set_iv(EVP_SEED_GCM_CTX *gctx, const uint8_t *iv,
                            size_t iv_len) {
  OPENSSL_memset(gctx->Yi, 0, sizeof(gctx->Yi));
  OPENSSL_memset(gctx->Xi, 0, sizeof(gctx->Xi));
  gctx->aad_len = 0;
  gctx->msg_len = 0;
  gctx->ares = 0;
  gctx->mres = 0;

  if (iv_len == 12) {
    OPENSSL_memcpy(gctx->Yi, iv, 12);
    gctx->Yi[15] = 1;
  } else {
    uint64_t len0 = iv_len;
    while (iv_len >= 16) {
      CRYPTO_xor16(gctx->Yi, gctx->Yi, iv);
      gctx->gmult(gctx->Yi, gctx->Htable);
      iv += 16;
      iv_len -= 16;
    }
    if (iv_len) {
      for (size_t i = 0; i < iv_len; i++) {
        gctx->Yi[i] ^= iv[i];
      }
      gctx->gmult(gctx->Yi, gctx->Htable);
    }
    uint8_t len_block[16];
    OPENSSL_memset(len_block, 0, 8);
    CRYPTO_store_u64_be(len_block + 8, len0 << 3);
    CRYPTO_xor16(gctx->Yi, gctx->Yi, len_block);
    gctx->gmult(gctx->Yi, gctx->Htable);
  }

  SEED_encrypt_block(gctx->Yi, gctx->EK0, &gctx->ks);
  seed_gcm_ctr32_inc(gctx->Yi);
}

static void seed_gcm_aad(EVP_SEED_GCM_CTX *gctx, const uint8_t *aad,
                         size_t len) {
  gctx->aad_len += len;
  unsigned n = gctx->ares;
  for (size_t i = 0; i < len; i++) {
    gctx->Xi[n] ^= aad[i];
    n = (n + 1) % 16;
    if (n == 0) {
      gctx->gmult(gctx->Xi, gctx->Htable);
    }
  }
  gctx->ares = n;
}

static void seed_gcm_crypt(EVP_SEED_GCM_CTX *gctx, uint8_t *out,
                           const uint8_t *in, size_t len, int encrypt) {
  if (gctx->ares) {
    gctx->gmult(gctx->Xi, gctx->Htable);
    gctx->ares = 0;
  }
  gctx->msg_len += len;
  unsigned n = gctx->mres;
  for (size_t i = 0; i < len; i++) {
    if (n == 0) {
      SEED_encrypt_block(gctx->Yi, gctx->EKi, &gctx->ks);
      seed_gcm_ctr32_inc(gctx->Yi);
    }
    uint8_t c = in[i];
    uint8_t o = c ^ gctx->EKi[n];
    out[i] = o;
    gctx->Xi[n] ^= encrypt ? o : c;
    n = (n + 1) % 16;
    if (n == 0) {
      gctx->gmult(gctx->Xi, gctx->Htable);
    }
  }
  gctx->mres = n;
}

static void seed_gcm_finalize(EVP_SEED_GCM_CTX *gctx) {
  if (gctx->mres || gctx->ares) {
    gctx->gmult(gctx->Xi, gctx->Htable);
  }
  uint8_t len_block[16];
  CRYPTO_store_u64_be(len_block, gctx->aad_len << 3);
  CRYPTO_store_u64_be(len_block + 8, gctx->msg_len << 3);
  CRYPTO_xor16(gctx->Xi, gctx->Xi, len_block);
  gctx->gmult(gctx->Xi, gctx->Htable);
  CRYPTO_xor16(gctx->Xi, gctx->Xi, gctx->EK0);
}

static int seed_gcm_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                             const uint8_t *iv, int enc) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(ctx->cipher_data);
  if (!iv && !key) {
    return 1;
  }
  if (key) {
    if (SEED_set_key(key, &gctx->ks) < 0) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
      return 0;
    }
    seed_gcm_setup_key(gctx);
    if (iv == nullptr && gctx->iv_set) {
      iv = gctx->iv;
    }
    if (iv) {
      seed_gcm_set_iv(gctx, iv, gctx->ivlen);
      gctx->iv_set = 1;
    }
    gctx->key_set = 1;
  } else {
    if (gctx->key_set) {
      seed_gcm_set_iv(gctx, iv, gctx->ivlen);
    } else {
      OPENSSL_memcpy(gctx->iv, iv, gctx->ivlen);
    }
    gctx->iv_set = 1;
    gctx->iv_gen = 0;
  }
  return 1;
}

static void seed_gcm_cleanup(EVP_CIPHER_CTX *c) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(c->cipher_data);
  OPENSSL_cleanse(&gctx->ks, sizeof(gctx->ks));
  OPENSSL_cleanse(gctx->Xi, sizeof(gctx->Xi));
  OPENSSL_cleanse(gctx->EKi, sizeof(gctx->EKi));
  OPENSSL_cleanse(gctx->EK0, sizeof(gctx->EK0));
  if (gctx->iv != c->iv) {
    OPENSSL_free(gctx->iv);
  }
}

static int seed_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(c->cipher_data);
  switch (type) {
    case EVP_CTRL_INIT:
      gctx->key_set = 0;
      gctx->iv_set = 0;
      gctx->ivlen = c->cipher->iv_len;
      gctx->iv = c->iv;
      gctx->taglen = -1;
      gctx->iv_gen = 0;
      return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
      if (arg <= 0) {
        return 0;
      }
      if (arg == gctx->ivlen) {
        return 1;
      }
      gctx->iv_set = 0;
      gctx->iv_gen = 0;
      if (arg <= EVP_MAX_IV_LENGTH) {
        if (gctx->iv != c->iv) {
          OPENSSL_free(gctx->iv);
          gctx->iv = c->iv;
        }
      } else if (arg > gctx->ivlen) {
        uint8_t *new_iv = static_cast<uint8_t *>(OPENSSL_malloc(arg));
        if (new_iv == nullptr) {
          return 0;
        }
        if (gctx->iv != c->iv) {
          OPENSSL_free(gctx->iv);
        }
        gctx->iv = new_iv;
      }
      gctx->ivlen = arg;
      return 1;

    case EVP_CTRL_GET_IVLEN:
      *(int *)ptr = gctx->ivlen;
      return 1;

    case EVP_CTRL_AEAD_SET_TAG:
      if (arg <= 0 || arg > 16 || c->encrypt) {
        return 0;
      }
      OPENSSL_memcpy(c->buf, ptr, arg);
      gctx->taglen = arg;
      return 1;

    case EVP_CTRL_AEAD_GET_TAG:
      if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0) {
        return 0;
      }
      OPENSSL_memcpy(ptr, c->buf, arg);
      return 1;

    case EVP_CTRL_COPY: {
      EVP_CIPHER_CTX *out = reinterpret_cast<EVP_CIPHER_CTX *>(ptr);
      EVP_SEED_GCM_CTX *gctx_out =
          reinterpret_cast<EVP_SEED_GCM_CTX *>(out->cipher_data);
      if (gctx->iv == c->iv) {
        gctx_out->iv = out->iv;
      } else {
        gctx_out->iv =
            reinterpret_cast<uint8_t *>(OPENSSL_memdup(gctx->iv, gctx->ivlen));
        if (!gctx_out->iv) {
          return 0;
        }
      }
      return 1;
    }

    default:
      return -1;
  }
}

static int seed_gcm_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(ctx->cipher_data);
  if (!gctx->key_set || !gctx->iv_set) {
    return 0;
  }
  seed_gcm_crypt(gctx, out, in, len, ctx->encrypt);
  return 1;
}

static int seed_gcm_cipher_final(EVP_CIPHER_CTX *ctx) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(ctx->cipher_data);
  if (!gctx->key_set || !gctx->iv_set) {
    return 0;
  }
  if (!ctx->encrypt) {
    if (gctx->taglen < 0) {
      return 0;
    }
    seed_gcm_finalize(gctx);
    if (CRYPTO_memcmp(gctx->Xi, ctx->buf, gctx->taglen) != 0) {
      return 0;
    }
    gctx->iv_set = 0;
    return 1;
  }
  seed_gcm_finalize(gctx);
  OPENSSL_memcpy(ctx->buf, gctx->Xi, 16);
  gctx->taglen = 16;
  gctx->iv_set = 0;
  return 1;
}

static int seed_gcm_update_aad(EVP_CIPHER_CTX *ctx, const uint8_t *in,
                               size_t len) {
  EVP_SEED_GCM_CTX *gctx =
      reinterpret_cast<EVP_SEED_GCM_CTX *>(ctx->cipher_data);
  if (!gctx->key_set || !gctx->iv_set) {
    return 0;
  }
  seed_gcm_aad(gctx, in, len);
  return 1;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_seed_ecb) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_seed_ecb;
  out->block_size = 16;
  out->key_len = 16;
  out->iv_len = 0;
  out->ctx_size = sizeof(EVP_SEED_KEY);
  out->flags = EVP_CIPH_ECB_MODE;
  out->init = seed_init_key;
  out->cipher_update = seed_ecb_cipher_update;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_seed_cbc) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_seed_cbc;
  out->block_size = 16;
  out->key_len = 16;
  out->iv_len = 16;
  out->ctx_size = sizeof(EVP_SEED_KEY);
  out->flags = EVP_CIPH_CBC_MODE;
  out->init = seed_init_key;
  out->cipher_update = seed_cbc_cipher_update;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_seed_ctr) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_seed_ctr;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = 16;
  out->ctx_size = sizeof(EVP_SEED_KEY);
  out->flags = EVP_CIPH_CTR_MODE;
  out->init = seed_init_key;
  out->cipher_update = seed_ctr_cipher_update;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_seed_gcm) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_seed_gcm;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = SEED_GCM_NONCE_LENGTH;
  out->ctx_size = sizeof(EVP_SEED_GCM_CTX);
  out->flags = EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY |
               EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT |
               EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER;
  out->init = seed_gcm_init_key;
  out->cipher_update = seed_gcm_cipher_update;
  out->cipher_final = seed_gcm_cipher_final;
  out->update_aad = seed_gcm_update_aad;
  out->cleanup = seed_gcm_cleanup;
  out->ctrl = seed_gcm_ctrl;
}

// ---------------------------------------------------------------------------
// SEED-CCM AEAD (M=16, L=3), reusing the CCM128 core from e_aesccm.cc.inc.
// ---------------------------------------------------------------------------

static void seed_block128(const uint8_t in[16], uint8_t out[16],
                          const AES_KEY *key) {
  SEED_encrypt_block(in, out, reinterpret_cast<const SEED_KEY *>(key));
}

static void seed_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                      size_t blocks, const AES_KEY *key,
                                      const uint8_t ivec[16]) {
  const SEED_KEY *sk = reinterpret_cast<const SEED_KEY *>(key);
  uint8_t ctr[16];
  OPENSSL_memcpy(ctr, ivec, 16);
  uint32_t c = CRYPTO_load_u32_be(ctr + 12);
  uint8_t ks[16];
  while (blocks--) {
    SEED_encrypt_block(ctr, ks, sk);
    CRYPTO_xor16(out, in, ks);
    in += 16;
    out += 16;
    c++;
    CRYPTO_store_u32_be(ctr + 12, c);
  }
  OPENSSL_cleanse(ks, sizeof(ks));
}

namespace {
struct aead_seed_ccm_ctx {
  SEED_KEY ks;
  struct ccm128_context ccm;
};
}  // namespace

static_assert(sizeof(((EVP_AEAD_CTX *)nullptr)->state) >=
                  sizeof(struct aead_seed_ccm_ctx),
              "AEAD state is too small");
static_assert(alignof(union evp_aead_ctx_st_state) >=
                  alignof(struct aead_seed_ccm_ctx),
              "AEAD state has insufficient alignment");

static int aead_seed_ccm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                              size_t key_len, size_t tag_len, unsigned M,
                              unsigned L) {
  if (key_len != EVP_AEAD_key_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0;
  }
  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = M;
  }
  if (tag_len != M) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  auto *ccm_ctx = reinterpret_cast<struct aead_seed_ccm_ctx *>(&ctx->state);
  if (SEED_set_key(key, &ccm_ctx->ks) < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }
  ctx->tag_len = tag_len;
  if (!CRYPTO_ccm128_init(&ccm_ctx->ccm,
                          reinterpret_cast<const AES_KEY *>(&ccm_ctx->ks),
                          seed_block128, seed_ctr32_encrypt_blocks, M, L)) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

static int aead_seed_ccm_16_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                 size_t key_len, size_t tag_len) {
  return aead_seed_ccm_init(ctx, key, key_len, tag_len, 16, 3);
}

static void aead_seed_ccm_cleanup(EVP_AEAD_CTX *ctx) {
  auto *ccm_ctx = reinterpret_cast<struct aead_seed_ccm_ctx *>(&ctx->state);
  OPENSSL_cleanse(&ccm_ctx->ks, sizeof(ccm_ctx->ks));
}

static int aead_seed_ccm_sealv(const EVP_AEAD_CTX *ctx,
                               Span<const CRYPTO_IOVEC> iovecs,
                               Span<uint8_t> out_tag, size_t *out_tag_len,
                               Span<const uint8_t> nonce,
                               Span<const CRYPTO_IVEC> aadvecs) {
  const auto *ccm_ctx =
      reinterpret_cast<const struct aead_seed_ccm_ctx *>(&ctx->state);

  if (bssl::iovec::TotalLength(iovecs) >
      CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  if (out_tag.size() < ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  if (nonce.size() != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (!CRYPTO_ccm128_encrypt(&ccm_ctx->ccm,
                             reinterpret_cast<const AES_KEY *>(&ccm_ctx->ks),
                             iovecs, out_tag.first(ctx->tag_len), nonce,
                             aadvecs)) {
    return 0;
  }
  *out_tag_len = ctx->tag_len;
  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

static int aead_seed_ccm_openv_detached(const EVP_AEAD_CTX *ctx,
                                        Span<const CRYPTO_IOVEC> iovecs,
                                        Span<const uint8_t> nonce,
                                        Span<const uint8_t> in_tag,
                                        Span<const CRYPTO_IVEC> aadvecs) {
  const auto *ccm_ctx =
      reinterpret_cast<const struct aead_seed_ccm_ctx *>(&ctx->state);

  if (bssl::iovec::TotalLength(iovecs) >
      CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  if (nonce.size() != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }
  if (in_tag.size() != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  uint8_t tag[EVP_AEAD_AES_CCM_MAX_TAG_LEN];
  if (!CRYPTO_ccm128_decrypt(&ccm_ctx->ccm,
                             reinterpret_cast<const AES_KEY *>(&ccm_ctx->ks),
                             iovecs, Span(tag).first(ctx->tag_len), nonce,
                             aadvecs)) {
    return 0;
  }
  if (CRYPTO_memcmp(tag, in_tag.data(), ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }
  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_seed_ccm) {
  memset(out, 0, sizeof(EVP_AEAD));
  out->key_len = 16;
  out->nonce_len = 12;
  out->overhead = 16;
  out->max_tag_len = 16;
  out->init = aead_seed_ccm_16_init;
  out->cleanup = aead_seed_ccm_cleanup;
  out->sealv = aead_seed_ccm_sealv;
  out->openv_detached = aead_seed_ccm_openv_detached;
}
