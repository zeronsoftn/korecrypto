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

// EVP bindings for HIGHT: ECB/CBC/CTR. HIGHT has a 64-bit block, so AEAD modes
// (GCM/CCM), which require a 128-bit block, are not provided.

#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/hight.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include <string.h>

#include "../../internal.h"
#include "../delocate.h"
#include "internal.h"


typedef struct {
  HIGHT_KEY ks;
} EVP_HIGHT_KEY;

static int hight_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                          const uint8_t *iv, int enc) {
  EVP_HIGHT_KEY *dat = reinterpret_cast<EVP_HIGHT_KEY *>(ctx->cipher_data);
  if (HIGHT_set_key(key, &dat->ks) < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }
  return 1;
}

static int hight_ecb_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                   const uint8_t *in, size_t len) {
  EVP_HIGHT_KEY *dat = reinterpret_cast<EVP_HIGHT_KEY *>(ctx->cipher_data);
  for (size_t i = 0; i + HIGHT_BLOCK_SIZE <= len; i += HIGHT_BLOCK_SIZE) {
    if (ctx->encrypt) {
      HIGHT_encrypt_block(in + i, out + i, &dat->ks);
    } else {
      HIGHT_decrypt_block(in + i, out + i, &dat->ks);
    }
  }
  return 1;
}

static int hight_cbc_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                   const uint8_t *in, size_t len) {
  EVP_HIGHT_KEY *dat = reinterpret_cast<EVP_HIGHT_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;

  if (ctx->encrypt) {
    for (size_t i = 0; i + HIGHT_BLOCK_SIZE <= len; i += HIGHT_BLOCK_SIZE) {
      for (size_t j = 0; j < HIGHT_BLOCK_SIZE; j++) {
        iv[j] ^= in[i + j];
      }
      HIGHT_encrypt_block(iv, out + i, &dat->ks);
      memcpy(iv, out + i, HIGHT_BLOCK_SIZE);
    }
  } else {
    uint8_t tmp[HIGHT_BLOCK_SIZE];
    for (size_t i = 0; i + HIGHT_BLOCK_SIZE <= len; i += HIGHT_BLOCK_SIZE) {
      memcpy(tmp, in + i, HIGHT_BLOCK_SIZE);
      HIGHT_decrypt_block(tmp, out + i, &dat->ks);
      for (size_t j = 0; j < HIGHT_BLOCK_SIZE; j++) {
        out[i + j] ^= iv[j];
      }
      memcpy(iv, tmp, HIGHT_BLOCK_SIZE);
    }
    OPENSSL_cleanse(tmp, sizeof(tmp));
  }
  return 1;
}

static int hight_ctr_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                   const uint8_t *in, size_t len) {
  EVP_HIGHT_KEY *dat = reinterpret_cast<EVP_HIGHT_KEY *>(ctx->cipher_data);
  unsigned num = ctx->num;

  for (size_t i = 0; i < len; i++) {
    if (num == 0) {
      HIGHT_encrypt_block(ctx->iv, ctx->buf, &dat->ks);
      for (int j = HIGHT_BLOCK_SIZE - 1; j >= 0; j--) {
        if (++ctx->iv[j] != 0) {
          break;
        }
      }
    }
    out[i] = in[i] ^ ctx->buf[num];
    num = (num + 1) % HIGHT_BLOCK_SIZE;
  }

  ctx->num = num;
  return 1;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_hight_ecb) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_hight_ecb;
  out->block_size = 8;
  out->key_len = 16;
  out->iv_len = 0;
  out->ctx_size = sizeof(EVP_HIGHT_KEY);
  out->flags = EVP_CIPH_ECB_MODE;
  out->init = hight_init_key;
  out->cipher_update = hight_ecb_cipher_update;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_hight_cbc) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_hight_cbc;
  out->block_size = 8;
  out->key_len = 16;
  out->iv_len = 8;
  out->ctx_size = sizeof(EVP_HIGHT_KEY);
  out->flags = EVP_CIPH_CBC_MODE;
  out->init = hight_init_key;
  out->cipher_update = hight_cbc_cipher_update;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_hight_ctr) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_hight_ctr;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = 8;
  out->ctx_size = sizeof(EVP_HIGHT_KEY);
  out->flags = EVP_CIPH_CTR_MODE;
  out->init = hight_init_key;
  out->cipher_update = hight_ctr_cipher_update;
}
