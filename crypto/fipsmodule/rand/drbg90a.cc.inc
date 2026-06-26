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

// Hash_DRBG and HMAC_DRBG (SP 800-90A), KCMVP validation-target DRBGs built on
// the BCM digest and HMAC primitives. Verified against NIST CAVP vectors.

#include <openssl/drbg_kcmvp.h>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>

#include <string.h>

#include "../../internal.h"


namespace {

// be_add computes a = (a + b) mod 2^(8*a_len), with |b| right-aligned in |a|.
void be_add(uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
  unsigned carry = 0;
  for (size_t i = 0; i < a_len; i++) {
    size_t ai = a_len - 1 - i;
    unsigned bv = (i < b_len) ? b[b_len - 1 - i] : 0;
    unsigned s = (unsigned)a[ai] + bv + carry;
    a[ai] = (uint8_t)s;
    carry = s >> 8;
  }
}

// be_add_u64 adds the integer |v| to the big-endian value |a|.
void be_add_u64(uint8_t *a, size_t a_len, uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; i++) {
    b[7 - i] = (uint8_t)(v >> (8 * i));
  }
  be_add(a, a_len, b, sizeof(b));
}

// Hash over a leading byte (when |with_lead|) followed by up to two segments.
int hash_segments(const EVP_MD *md, uint8_t *out, unsigned *out_len,
                  int with_lead, uint8_t lead, const uint8_t *s1, size_t l1,
                  const uint8_t *s2, size_t l2) {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  int ok = EVP_DigestInit_ex(&ctx, md, nullptr) &&
           (!with_lead || EVP_DigestUpdate(&ctx, &lead, 1)) &&
           (l1 == 0 || EVP_DigestUpdate(&ctx, s1, l1)) &&
           (l2 == 0 || EVP_DigestUpdate(&ctx, s2, l2)) &&
           EVP_DigestFinal_ex(&ctx, out, out_len);
  EVP_MD_CTX_cleanup(&ctx);
  return ok;
}

// hash_df implements the SP 800-90A Hash_df derivation function, deriving
// |out_len| bytes from (0x?? || input) where the optional leading byte is
// |lead| when |with_lead| is set.
int hash_df(const EVP_MD *md, uint8_t *out, size_t out_len, int with_lead,
            uint8_t lead, const uint8_t *input, size_t input_len) {
  uint8_t counter = 1;
  uint8_t len_be[4];
  CRYPTO_store_u32_be(len_be, (uint32_t)(out_len * 8));
  size_t done = 0;
  uint8_t block[EVP_MAX_MD_SIZE];
  unsigned block_len = 0;
  while (done < out_len) {
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    int ok = EVP_DigestInit_ex(&ctx, md, nullptr) &&
             EVP_DigestUpdate(&ctx, &counter, 1) &&
             EVP_DigestUpdate(&ctx, len_be, 4) &&
             (!with_lead || EVP_DigestUpdate(&ctx, &lead, 1)) &&
             (input_len == 0 || EVP_DigestUpdate(&ctx, input, input_len)) &&
             EVP_DigestFinal_ex(&ctx, block, &block_len);
    EVP_MD_CTX_cleanup(&ctx);
    if (!ok) {
      return 0;
    }
    size_t take = out_len - done < block_len ? out_len - done : block_len;
    OPENSSL_memcpy(out + done, block, take);
    done += take;
    counter++;
  }
  OPENSSL_cleanse(block, sizeof(block));
  return 1;
}

size_t hash_drbg_seedlen(const EVP_MD *md) {
  // SP 800-90A: seedlen = 440 bits for hashlen <= 256, else 888 bits.
  return EVP_MD_size(md) <= 32 ? 55 : 111;
}

}  // namespace

extern "C" {

int HASH_DRBG_init(HASH_DRBG *drbg, const EVP_MD *md, const uint8_t *entropy,
                   size_t entropy_len, const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *perso, size_t perso_len) {
  drbg->md = md;
  drbg->seedlen = hash_drbg_seedlen(md);

  // seed_material = entropy || nonce || perso
  size_t sm_len = entropy_len + nonce_len + perso_len;
  uint8_t *sm = reinterpret_cast<uint8_t *>(OPENSSL_malloc(sm_len ? sm_len : 1));
  if (sm == nullptr) {
    return 0;
  }
  OPENSSL_memcpy(sm, entropy, entropy_len);
  OPENSSL_memcpy(sm + entropy_len, nonce, nonce_len);
  OPENSSL_memcpy(sm + entropy_len + nonce_len, perso, perso_len);

  int ok = hash_df(md, drbg->v, drbg->seedlen, /*with_lead=*/0, 0, sm, sm_len) &&
           // C = Hash_df(0x00 || V)
           hash_df(md, drbg->c, drbg->seedlen, /*with_lead=*/1, 0x00, drbg->v,
                   drbg->seedlen);
  drbg->reseed_counter = 1;
  OPENSSL_cleanse(sm, sm_len);
  OPENSSL_free(sm);
  return ok;
}

int HASH_DRBG_reseed(HASH_DRBG *drbg, const uint8_t *entropy,
                     size_t entropy_len, const uint8_t *addtl,
                     size_t addtl_len) {
  // seed_material = 0x01 || V || entropy || addtl
  size_t sm_len = 1 + drbg->seedlen + entropy_len + addtl_len;
  uint8_t *sm = reinterpret_cast<uint8_t *>(OPENSSL_malloc(sm_len));
  if (sm == nullptr) {
    return 0;
  }
  sm[0] = 0x01;
  OPENSSL_memcpy(sm + 1, drbg->v, drbg->seedlen);
  OPENSSL_memcpy(sm + 1 + drbg->seedlen, entropy, entropy_len);
  OPENSSL_memcpy(sm + 1 + drbg->seedlen + entropy_len, addtl, addtl_len);

  int ok = hash_df(drbg->md, drbg->v, drbg->seedlen, 0, 0, sm, sm_len) &&
           hash_df(drbg->md, drbg->c, drbg->seedlen, 1, 0x00, drbg->v,
                   drbg->seedlen);
  drbg->reseed_counter = 1;
  OPENSSL_cleanse(sm, sm_len);
  OPENSSL_free(sm);
  return ok;
}

int HASH_DRBG_generate(HASH_DRBG *drbg, uint8_t *out, size_t out_len,
                       const uint8_t *addtl, size_t addtl_len) {
  const EVP_MD *md = drbg->md;
  const size_t sl = drbg->seedlen;
  uint8_t tmp[EVP_MAX_MD_SIZE];
  unsigned tmp_len = 0;

  if (addtl_len > 0) {
    // w = Hash(0x02 || V || addtl); V = (V + w) mod 2^seedlen
    if (!hash_segments(md, tmp, &tmp_len, 1, 0x02, drbg->v, sl, addtl,
                       addtl_len)) {
      return 0;
    }
    be_add(drbg->v, sl, tmp, tmp_len);
  }

  // Hashgen: iterate Hash over data = V, V+1, V+2, ...
  uint8_t data[HASH_DRBG_MAX_SEEDLEN];
  OPENSSL_memcpy(data, drbg->v, sl);
  size_t done = 0;
  uint8_t block[EVP_MAX_MD_SIZE];
  unsigned block_len = 0;
  const uint8_t one = 1;
  while (done < out_len) {
    if (!hash_segments(md, block, &block_len, 0, 0, data, sl, nullptr, 0)) {
      return 0;
    }
    size_t take = out_len - done < block_len ? out_len - done : block_len;
    OPENSSL_memcpy(out + done, block, take);
    done += take;
    be_add(data, sl, &one, 1);
  }

  // H = Hash(0x03 || V); V = (V + H + C + reseed_counter) mod 2^seedlen
  if (!hash_segments(md, tmp, &tmp_len, 1, 0x03, drbg->v, sl, nullptr, 0)) {
    return 0;
  }
  be_add(drbg->v, sl, tmp, tmp_len);
  be_add(drbg->v, sl, drbg->c, sl);
  be_add_u64(drbg->v, sl, drbg->reseed_counter);
  drbg->reseed_counter++;

  OPENSSL_cleanse(data, sizeof(data));
  OPENSSL_cleanse(block, sizeof(block));
  OPENSSL_cleanse(tmp, sizeof(tmp));
  return 1;
}

}  // extern "C"

// ---------------------------------------------------------------------------
// HMAC_DRBG
// ---------------------------------------------------------------------------

namespace {

int hmac_one(const EVP_MD *md, const uint8_t *key, size_t key_len,
             const uint8_t *data, size_t data_len, uint8_t *out) {
  unsigned out_len = 0;
  return HMAC(md, key, key_len, data, data_len, out, &out_len) != nullptr;
}

// hmac_drbg_update implements the SP 800-90A HMAC_DRBG Update with up to two
// provided-data segments (the concatenation is the provided_data).
int hmac_drbg_update(HMAC_DRBG *drbg, const uint8_t *p1, size_t l1,
                     const uint8_t *p2, size_t l2) {
  const EVP_MD *md = drbg->md;
  const size_t n = drbg->outlen;
  size_t plen = l1 + l2;

  // K = HMAC(K, V || 0x00 || provided_data)
  size_t buf_len = n + 1 + plen;
  uint8_t *buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(buf_len));
  if (buf == nullptr) {
    return 0;
  }
  OPENSSL_memcpy(buf, drbg->v, n);
  buf[n] = 0x00;
  if (l1) {
    OPENSSL_memcpy(buf + n + 1, p1, l1);
  }
  if (l2) {
    OPENSSL_memcpy(buf + n + 1 + l1, p2, l2);
  }
  int ok = hmac_one(md, drbg->k, n, buf, buf_len, drbg->k) &&
           hmac_one(md, drbg->k, n, drbg->v, n, drbg->v);

  if (ok && plen != 0) {
    // K = HMAC(K, V || 0x01 || provided_data); V = HMAC(K, V)
    buf[n] = 0x01;
    OPENSSL_memcpy(buf, drbg->v, n);
    ok = hmac_one(md, drbg->k, n, buf, buf_len, drbg->k) &&
         hmac_one(md, drbg->k, n, drbg->v, n, drbg->v);
  }

  OPENSSL_cleanse(buf, buf_len);
  OPENSSL_free(buf);
  return ok;
}

}  // namespace

extern "C" {

int HMAC_DRBG_init(HMAC_DRBG *drbg, const EVP_MD *md, const uint8_t *entropy,
                   size_t entropy_len, const uint8_t *nonce, size_t nonce_len,
                   const uint8_t *perso, size_t perso_len) {
  drbg->md = md;
  drbg->outlen = EVP_MD_size(md);
  const size_t n = drbg->outlen;
  OPENSSL_memset(drbg->k, 0x00, n);
  OPENSSL_memset(drbg->v, 0x01, n);

  // provided_data = entropy || nonce || perso
  size_t sm_len = entropy_len + nonce_len + perso_len;
  uint8_t *sm = reinterpret_cast<uint8_t *>(OPENSSL_malloc(sm_len ? sm_len : 1));
  if (sm == nullptr) {
    return 0;
  }
  OPENSSL_memcpy(sm, entropy, entropy_len);
  OPENSSL_memcpy(sm + entropy_len, nonce, nonce_len);
  OPENSSL_memcpy(sm + entropy_len + nonce_len, perso, perso_len);

  int ok = hmac_drbg_update(drbg, sm, sm_len, nullptr, 0);
  drbg->reseed_counter = 1;
  OPENSSL_cleanse(sm, sm_len);
  OPENSSL_free(sm);
  return ok;
}

int HMAC_DRBG_reseed(HMAC_DRBG *drbg, const uint8_t *entropy,
                     size_t entropy_len, const uint8_t *addtl,
                     size_t addtl_len) {
  int ok = hmac_drbg_update(drbg, entropy, entropy_len, addtl, addtl_len);
  drbg->reseed_counter = 1;
  return ok;
}

int HMAC_DRBG_generate(HMAC_DRBG *drbg, uint8_t *out, size_t out_len,
                       const uint8_t *addtl, size_t addtl_len) {
  const EVP_MD *md = drbg->md;
  const size_t n = drbg->outlen;

  if (addtl_len > 0) {
    if (!hmac_drbg_update(drbg, addtl, addtl_len, nullptr, 0)) {
      return 0;
    }
  }

  size_t done = 0;
  while (done < out_len) {
    if (!hmac_one(md, drbg->k, n, drbg->v, n, drbg->v)) {
      return 0;
    }
    size_t take = out_len - done < n ? out_len - done : n;
    OPENSSL_memcpy(out + done, drbg->v, take);
    done += take;
  }

  int ok = hmac_drbg_update(drbg, addtl, addtl_len, nullptr, 0);
  drbg->reseed_counter++;
  return ok;
}

}  // extern "C"
