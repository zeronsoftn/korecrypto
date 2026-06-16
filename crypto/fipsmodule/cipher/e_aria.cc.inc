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

// EVP_CIPHER bindings for ARIA (ECB/CBC/CTR), built on |ARIA_encrypt_block|
// from aria/aria.cc.inc. The mode logic is kept self-contained so ARIA does
// not depend on the AES-specific mode helpers.

#include <openssl/aria.h>
#include <openssl/cipher.h>
#include <openssl/nid.h>

#include <string.h>

#include "../delocate.h"
#include "internal.h"


typedef struct {
  ARIA_KEY ks;
} EVP_ARIA_KEY;

static int aria_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                         const uint8_t *iv, int enc) {
  EVP_ARIA_KEY *dat = reinterpret_cast<EVP_ARIA_KEY *>(ctx->cipher_data);
  const int mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  int ret;
  // ECB and CBC decryption require the inverse key schedule. CTR is built on
  // the encryption direction only.
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    ret = ARIA_set_decrypt_key(key, ctx->key_len * 8, &dat->ks);
  } else {
    ret = ARIA_set_encrypt_key(key, ctx->key_len * 8, &dat->ks);
  }
  if (ret < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }
  return 1;
}

static int aria_ecb_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_ARIA_KEY *dat = reinterpret_cast<EVP_ARIA_KEY *>(ctx->cipher_data);
  for (size_t i = 0; i + ARIA_BLOCK_SIZE <= len; i += ARIA_BLOCK_SIZE) {
    ARIA_encrypt_block(in + i, out + i, &dat->ks);
  }
  return 1;
}

static int aria_cbc_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_ARIA_KEY *dat = reinterpret_cast<EVP_ARIA_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;

  if (ctx->encrypt) {
    for (size_t i = 0; i + ARIA_BLOCK_SIZE <= len; i += ARIA_BLOCK_SIZE) {
      for (size_t j = 0; j < ARIA_BLOCK_SIZE; j++) {
        iv[j] ^= in[i + j];
      }
      ARIA_encrypt_block(iv, out + i, &dat->ks);
      memcpy(iv, out + i, ARIA_BLOCK_SIZE);
    }
  } else {
    uint8_t tmp[ARIA_BLOCK_SIZE];
    for (size_t i = 0; i + ARIA_BLOCK_SIZE <= len; i += ARIA_BLOCK_SIZE) {
      // Copy the ciphertext block first so in-place operation (in == out) is
      // safe and the IV chaining value is preserved.
      memcpy(tmp, in + i, ARIA_BLOCK_SIZE);
      ARIA_encrypt_block(tmp, out + i, &dat->ks);
      for (size_t j = 0; j < ARIA_BLOCK_SIZE; j++) {
        out[i + j] ^= iv[j];
      }
      memcpy(iv, tmp, ARIA_BLOCK_SIZE);
    }
    OPENSSL_cleanse(tmp, sizeof(tmp));
  }
  return 1;
}

static int aria_ctr_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                  const uint8_t *in, size_t len) {
  EVP_ARIA_KEY *dat = reinterpret_cast<EVP_ARIA_KEY *>(ctx->cipher_data);
  unsigned num = ctx->num;

  for (size_t i = 0; i < len; i++) {
    if (num == 0) {
      // Generate the next keystream block and increment the 128-bit big-endian
      // counter.
      ARIA_encrypt_block(ctx->iv, ctx->buf, &dat->ks);
      for (int j = ARIA_BLOCK_SIZE - 1; j >= 0; j--) {
        if (++ctx->iv[j] != 0) {
          break;
        }
      }
    }
    out[i] = in[i] ^ ctx->buf[num];
    num = (num + 1) % ARIA_BLOCK_SIZE;
  }

  ctx->num = num;
  return 1;
}

#define DEFINE_ARIA_CIPHER(name, nid_val, klen, ivlen, blocksize, mode, \
                           update_fn)                                   \
  DEFINE_METHOD_FUNCTION(EVP_CIPHER, name) {                            \
    memset(out, 0, sizeof(EVP_CIPHER));                                 \
    out->nid = (nid_val);                                              \
    out->block_size = (blocksize);                                     \
    out->key_len = (klen);                                             \
    out->iv_len = (ivlen);                                             \
    out->ctx_size = sizeof(EVP_ARIA_KEY);                              \
    out->flags = (mode);                                               \
    out->init = aria_init_key;                                         \
    out->cipher_update = (update_fn);                                  \
  }

DEFINE_ARIA_CIPHER(EVP_aria_128_ecb, NID_aria_128_ecb, 16, 0, 16,
                   EVP_CIPH_ECB_MODE, aria_ecb_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_128_cbc, NID_aria_128_cbc, 16, 16, 16,
                   EVP_CIPH_CBC_MODE, aria_cbc_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_128_ctr, NID_aria_128_ctr, 16, 16, 1,
                   EVP_CIPH_CTR_MODE, aria_ctr_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_192_ecb, NID_aria_192_ecb, 24, 0, 16,
                   EVP_CIPH_ECB_MODE, aria_ecb_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_192_cbc, NID_aria_192_cbc, 24, 16, 16,
                   EVP_CIPH_CBC_MODE, aria_cbc_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_192_ctr, NID_aria_192_ctr, 24, 16, 1,
                   EVP_CIPH_CTR_MODE, aria_ctr_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_256_ecb, NID_aria_256_ecb, 32, 0, 16,
                   EVP_CIPH_ECB_MODE, aria_ecb_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_256_cbc, NID_aria_256_cbc, 32, 16, 16,
                   EVP_CIPH_CBC_MODE, aria_cbc_cipher_update)
DEFINE_ARIA_CIPHER(EVP_aria_256_ctr, NID_aria_256_ctr, 32, 16, 1,
                   EVP_CIPH_CTR_MODE, aria_ctr_cipher_update)
