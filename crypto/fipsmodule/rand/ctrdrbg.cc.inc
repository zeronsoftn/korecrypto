// Copyright 2017 The BoringSSL Authors
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

#include <openssl/ctrdrbg.h>

#include <assert.h>

#include <openssl/aria.h>
#include <openssl/hight.h>
#include <openssl/lea.h>
#include <openssl/mem.h>
#include <openssl/seed.h>
#include <algorithm>

#include "../../mem_internal.h"
#include "../aes/internal.h"
#include "../service_indicator/internal.h"
#include "internal.h"


using namespace bssl;

// Section references in this file refer to SP 800-90Ar1:
// http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf

// Also see table 3.
constexpr uint64_t kMaxReseedCount = UINT64_C(1) << 48;

// Implements the BCC function as described in Section 10.3.3.
static void bcc(uint8_t out[AES_BLOCK_SIZE], const AES_KEY *aes_key,
                const uint8_t *data, size_t data_len) {
  // 1. chaining_value = 0^outlen.
  uint8_t *chaining_value = out;
  OPENSSL_memset(chaining_value, 0, AES_BLOCK_SIZE);

  // 2. n = len (data)/outlen.
  BSSL_CHECK(data_len % AES_BLOCK_SIZE == 0);
  const size_t n = data_len / AES_BLOCK_SIZE;

  for (size_t i = 0; i < n; i++) {
    const uint8_t *block = data + (i * AES_BLOCK_SIZE);
    uint8_t input_block[AES_BLOCK_SIZE];

    // 4.1: input_block = chaining_value ⊕ block_i.
    CRYPTO_xor16(input_block, chaining_value, block);

    // 4.2: chaining_value = Block_Encrypt (Key, input_block).
    BCM_aes_encrypt(input_block, chaining_value, aes_key);
  }

  // 5. output_block = chaining_value.
}

// Implements the derivation function as described in Section 10.3.2.
static int block_cipher_df(uint8_t *out, size_t out_len, const uint8_t *input,
                           size_t input_len) {
  // Constants for AES-256
  constexpr size_t kAESKeyLen = 32;
  constexpr size_t kAESOutLen = AES_BLOCK_SIZE;
  constexpr size_t kMaxNumBits = 512;

  if (out_len > kMaxNumBits / 8 || input_len > (1u << 30)) {
    return 0;
  }

  // 4. S = L || N || input_string || 0x80.
  const size_t s_rawlen = sizeof(uint32_t) + sizeof(uint32_t) + input_len + 1;
  // S is padded up to a block size.
  const size_t s_len = (s_rawlen + kAESOutLen - 1) & ~(kAESOutLen - 1);
  uint8_t iv_plus_s[/* space used below */ kAESOutLen + 4 + 4 +
                    CTR_DRBG_MAX_ENTROPY_LEN + CTR_DRBG_NONCE_LEN +
                    CTR_DRBG_SEED_LEN + 1 +
                    /* padding */ 7];
  if (kAESOutLen + s_len > sizeof(iv_plus_s)) {
    return 0;
  }
  OPENSSL_memset(iv_plus_s, 0, sizeof(iv_plus_s));
  uint8_t *s_ptr = iv_plus_s + kAESOutLen;
  // 2. L = len (input_string)/8.
  CRYPTO_store_u32_be(s_ptr, (uint32_t)input_len);
  s_ptr += sizeof(uint32_t);
  // 3. N = number_of_bits_to_return/8.
  CRYPTO_store_u32_be(s_ptr, (uint32_t)out_len);
  s_ptr += sizeof(uint32_t);
  OPENSSL_memcpy(s_ptr, input, input_len);
  s_ptr += input_len;
  *s_ptr = 0x80;

  uint8_t temp[kAESKeyLen + kAESOutLen];
  size_t temp_len = 0;

  // 8. K = leftmost (0x00010203...1D1E1F, keylen).
  static const uint8_t kInitialKey[kAESKeyLen] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  AES_KEY aes_key;
  bcm_status status =
      BCM_aes_set_encrypt_key(kInitialKey, 8 * sizeof(kInitialKey), &aes_key);
  BSSL_CHECK(status != bcm_status::failure);

  // 7. i = 0.
  uint32_t i = 0;
  while (temp_len < sizeof(temp)) {
    // 9.1 IV = i || 0^(outlen - len(i)).
    CRYPTO_store_u32_be(iv_plus_s, i);

    // 9.2 temp = temp || BCC (K, (IV || S)).
    bcc(temp + temp_len, &aes_key, iv_plus_s, kAESOutLen + s_len);
    temp_len += kAESOutLen;

    // 9.3 i = i + 1.
    i++;
  }

  // 10. K = leftmost (temp, keylen).
  uint8_t *const k = temp;

  // 11. X = select (temp, keylen+1, keylen+outlen).
  uint8_t *const x = temp + kAESKeyLen;

  // 12. temp = the Null string.
  temp_len = 0;

  // Create an AES key schedule for the final encryption steps.
  status = BCM_aes_set_encrypt_key(k, kAESKeyLen * 8, &aes_key);
  BSSL_CHECK(status != bcm_status::failure);

  // 13. While len (temp) < number_of_bits_to_return, do:
  while (temp_len < out_len) {
    // 13.1 X = Block_Encrypt (K, X).
    BCM_aes_encrypt(x, x, &aes_key);

    // 13.2 temp = temp || X.
    size_t to_copy = std::min(kAESOutLen, out_len - temp_len);
    OPENSSL_memcpy(out + temp_len, x, to_copy);
    temp_len += to_copy;
  }

  return 1;
}

// ===================== KCMVP 일반 블록암호 CTR_DRBG =======================
//
// 기본 경로(위)는 AES-256 고정·고속(aes_ctr_set_key/block128_f). 아래는 KCMVP
// 시험용으로 블록암호·키 길이·df 를 구성 가능한 경로다(drbg->generic==1).
// 매 블록 키스케줄을 생성하므로(시험 생성기 용도) 단순·정확성 우선.

// kdrbg_block 은 한 블록을 암호화한다.
static int kdrbg_block(int cipher, const uint8_t *key, size_t keylen,
                       const uint8_t *in, uint8_t *out) {
  unsigned bits = (unsigned)(keylen * 8);
  switch (cipher) {
    case CTR_DRBG_KCMVP_AES: {
      AES_KEY k;
      if (BCM_aes_set_encrypt_key(key, bits, &k) == bcm_status::failure) {
        return 0;
      }
      BCM_aes_encrypt(in, out, &k);
      return 1;
    }
    case CTR_DRBG_KCMVP_ARIA: {
      ARIA_KEY k;
      if (ARIA_set_encrypt_key(key, bits, &k) != 0) {
        return 0;
      }
      ARIA_encrypt_block(in, out, &k);
      return 1;
    }
    case CTR_DRBG_KCMVP_LEA: {
      LEA_KEY k;
      if (LEA_set_key(key, bits, &k) != 0) {
        return 0;
      }
      LEA_encrypt_block(in, out, &k);
      return 1;
    }
    case CTR_DRBG_KCMVP_SEED: {
      SEED_KEY k;
      if (SEED_set_key(key, &k) != 0) {
        return 0;
      }
      SEED_encrypt_block(in, out, &k);
      return 1;
    }
    case CTR_DRBG_KCMVP_HIGHT: {
      HIGHT_KEY k;
      if (HIGHT_set_key(key, &k) != 0) {
        return 0;
      }
      HIGHT_encrypt_block(in, out, &k);
      return 1;
    }
  }
  return 0;
}

// kdrbg_inc 는 블록 길이 빅엔디안 카운터를 1 증가(전체 블록 캐리).
static void kdrbg_inc(uint8_t *v, size_t n) {
  for (size_t i = n; i > 0; i--) {
    if (++v[i - 1] != 0) {
      break;
    }
  }
}

// CTR_DRBG_Update(generic): data(==seedlen, 또는 nullptr) 로 (Key,V) 갱신.
static int ctr_drbg_update_generic(CTR_DRBG_STATE *drbg, const uint8_t *data) {
  const size_t kl = drbg->kcmvp_keylen, bl = drbg->kcmvp_blocklen, sl = kl + bl;
  uint8_t temp[48];
  size_t tlen = 0;
  while (tlen < sl) {
    kdrbg_inc(drbg->counter, bl);
    uint8_t blk[16];
    if (!kdrbg_block(drbg->kcmvp_cipher, drbg->kcmvp_key, kl, drbg->counter,
                     blk)) {
      return 0;
    }
    size_t take = sl - tlen < bl ? sl - tlen : bl;
    OPENSSL_memcpy(temp + tlen, blk, take);
    tlen += take;
  }
  if (data != nullptr) {
    for (size_t i = 0; i < sl; i++) {
      temp[i] ^= data[i];
    }
  }
  OPENSSL_memcpy(drbg->kcmvp_key, temp, kl);
  OPENSSL_memcpy(drbg->counter, temp + kl, bl);
  return 1;
}

// kdrbg_bcc: 블록암호 CBC-MAC.
static int kdrbg_bcc(int cipher, const uint8_t *key, size_t kl, size_t bl,
                     const uint8_t *data, size_t data_len, uint8_t *out) {
  OPENSSL_memset(out, 0, bl);
  for (size_t off = 0; off < data_len; off += bl) {
    uint8_t in[16];
    for (size_t i = 0; i < bl; i++) {
      in[i] = out[i] ^ data[off + i];
    }
    if (!kdrbg_block(cipher, key, kl, in, out)) {
      return 0;
    }
  }
  return 1;
}

// kdrbg_df: SP 800-90A 10.3.2 블록암호 유도함수(generic).
static int kdrbg_df(int cipher, size_t kl, size_t bl, const uint8_t *input,
                    size_t input_len, uint8_t *out, size_t out_len) {
  const size_t s_unpadded = 8 + input_len + 1;
  const size_t s_len = ((s_unpadded + bl - 1) / bl) * bl;
  uint8_t *S = reinterpret_cast<uint8_t *>(OPENSSL_malloc(s_len));
  uint8_t *buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(bl + s_len));
  int ret = 0;
  if (S == nullptr || buf == nullptr) {
    goto done;
  }
  OPENSSL_memset(S, 0, s_len);
  CRYPTO_store_u32_be(S, (uint32_t)input_len);
  CRYPTO_store_u32_be(S + 4, (uint32_t)out_len);
  if (input_len > 0) {
    OPENSSL_memcpy(S + 8, input, input_len);
  }
  S[8 + input_len] = 0x80;
  {
    uint8_t dfkey[32];
    for (size_t i = 0; i < kl; i++) {
      dfkey[i] = (uint8_t)i;
    }
    uint8_t temp[48];
    size_t tlen = 0;
    uint32_t i = 0;
    while (tlen < kl + bl) {
      OPENSSL_memset(buf, 0, bl);
      CRYPTO_store_u32_be(buf, i);
      OPENSSL_memcpy(buf + bl, S, s_len);
      uint8_t mac[16];
      if (!kdrbg_bcc(cipher, dfkey, kl, bl, buf, bl + s_len, mac)) {
        goto done;
      }
      size_t take = (kl + bl - tlen < bl) ? (kl + bl - tlen) : bl;
      OPENSSL_memcpy(temp + tlen, mac, take);
      tlen += take;
      i++;
    }
    uint8_t K[32], X[16];
    OPENSSL_memcpy(K, temp, kl);
    OPENSSL_memcpy(X, temp + kl, bl);
    size_t done_len = 0;
    while (done_len < out_len) {
      uint8_t tmp[16];
      if (!kdrbg_block(cipher, K, kl, X, tmp)) {
        goto done;
      }
      OPENSSL_memcpy(X, tmp, bl);
      size_t take = (out_len - done_len < bl) ? (out_len - done_len) : bl;
      OPENSSL_memcpy(out + done_len, X, take);
      done_len += take;
    }
    ret = 1;
  }
done:
  if (S != nullptr) {
    OPENSSL_free(S);
  }
  if (buf != nullptr) {
    OPENSSL_free(buf);
  }
  return ret;
}

static int ctr_drbg_reseed_generic(CTR_DRBG_STATE *drbg, const uint8_t *entropy,
                                   size_t entropy_len, const uint8_t *addtl,
                                   size_t addtl_len) {
  const size_t bl = drbg->kcmvp_blocklen, sl = drbg->kcmvp_keylen + bl;
  uint8_t seed[48];
  if (drbg->df) {
    size_t ml = entropy_len + addtl_len;
    uint8_t *m = reinterpret_cast<uint8_t *>(OPENSSL_malloc(ml ? ml : 1));
    if (m == nullptr) {
      return 0;
    }
    OPENSSL_memcpy(m, entropy, entropy_len);
    if (addtl_len) {
      OPENSSL_memcpy(m + entropy_len, addtl, addtl_len);
    }
    int ok = kdrbg_df(drbg->kcmvp_cipher, drbg->kcmvp_keylen, bl, m, ml, seed,
                      sl);
    OPENSSL_free(m);
    if (!ok) {
      return 0;
    }
  } else {
    if (entropy_len != sl) {
      return 0;
    }
    OPENSSL_memcpy(seed, entropy, sl);
    for (size_t i = 0; i < addtl_len && i < sl; i++) {
      seed[i] ^= addtl[i];
    }
  }
  int ok = ctr_drbg_update_generic(drbg, seed);
  OPENSSL_cleanse(seed, sizeof(seed));
  drbg->reseed_counter = 1;
  return ok;
}

static int ctr_drbg_generate_generic(CTR_DRBG_STATE *drbg, uint8_t *out,
                                     size_t out_len, const uint8_t *addtl,
                                     size_t addtl_len) {
  const size_t bl = drbg->kcmvp_blocklen, sl = drbg->kcmvp_keylen + bl;
  uint8_t add[48];
  int have_add = 0;
  if (addtl != nullptr && addtl_len > 0) {
    have_add = 1;
    if (drbg->df) {
      if (!kdrbg_df(drbg->kcmvp_cipher, drbg->kcmvp_keylen, bl, addtl, addtl_len,
                    add, sl)) {
        return 0;
      }
    } else {
      OPENSSL_memset(add, 0, sl);
      for (size_t i = 0; i < addtl_len && i < sl; i++) {
        add[i] = addtl[i];
      }
    }
    if (!ctr_drbg_update_generic(drbg, add)) {
      return 0;
    }
  }
  size_t done = 0;
  while (done < out_len) {
    kdrbg_inc(drbg->counter, bl);
    uint8_t blk[16];
    if (!kdrbg_block(drbg->kcmvp_cipher, drbg->kcmvp_key, drbg->kcmvp_keylen,
                     drbg->counter, blk)) {
      return 0;
    }
    size_t take = out_len - done < bl ? out_len - done : bl;
    OPENSSL_memcpy(out + done, blk, take);
    done += take;
  }
  int ok = ctr_drbg_update_generic(drbg, have_add ? add : nullptr);
  OPENSSL_cleanse(add, sizeof(add));
  drbg->reseed_counter++;
  return ok;
}

CTR_DRBG_STATE *CTR_DRBG_new_ex(int cipher, size_t keylen, int df,
                                const uint8_t *entropy, size_t entropy_len,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *perso, size_t perso_len) {
  CTR_DRBG_STATE *drbg = New<CTR_DRBG_STATE>();
  if (drbg == nullptr) {
    return nullptr;
  }
  drbg->generic = 1;
  drbg->kcmvp_cipher = cipher;
  drbg->kcmvp_keylen = keylen;
  drbg->kcmvp_blocklen = (cipher == CTR_DRBG_KCMVP_HIGHT) ? 8 : 16;
  drbg->df = df;
  const size_t bl = drbg->kcmvp_blocklen, sl = keylen + bl;
  if (keylen > 32 || sl > 48) {
    CTR_DRBG_free(drbg);
    return nullptr;
  }
  OPENSSL_memset(drbg->kcmvp_key, 0, sizeof(drbg->kcmvp_key));
  OPENSSL_memset(drbg->counter, 0, sizeof(drbg->counter));

  uint8_t seed[48];
  int ok;
  if (df) {
    size_t ml = entropy_len + nonce_len + perso_len;
    uint8_t *m = reinterpret_cast<uint8_t *>(OPENSSL_malloc(ml ? ml : 1));
    if (m == nullptr) {
      CTR_DRBG_free(drbg);
      return nullptr;
    }
    size_t o = 0;
    OPENSSL_memcpy(m + o, entropy, entropy_len);
    o += entropy_len;
    if (nonce_len) {
      OPENSSL_memcpy(m + o, nonce, nonce_len);
      o += nonce_len;
    }
    if (perso_len) {
      OPENSSL_memcpy(m + o, perso, perso_len);
    }
    ok = kdrbg_df(cipher, keylen, bl, m, ml, seed, sl);
    OPENSSL_free(m);
  } else {
    if (entropy_len + nonce_len != sl) {
      CTR_DRBG_free(drbg);
      return nullptr;
    }
    OPENSSL_memcpy(seed, entropy, entropy_len);
    if (nonce_len) {
      OPENSSL_memcpy(seed + entropy_len, nonce, nonce_len);
    }
    for (size_t i = 0; i < perso_len && i < sl; i++) {
      seed[i] ^= perso[i];
    }
    ok = 1;
  }
  if (!ok || !ctr_drbg_update_generic(drbg, seed)) {
    OPENSSL_cleanse(seed, sizeof(seed));
    CTR_DRBG_free(drbg);
    return nullptr;
  }
  OPENSSL_cleanse(seed, sizeof(seed));
  drbg->reseed_counter = 1;
  return drbg;
}

CTR_DRBG_STATE *CTR_DRBG_new(const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                             const uint8_t *personalization,
                             size_t personalization_len) {
  CTR_DRBG_STATE *drbg = New<CTR_DRBG_STATE>();
  if (drbg == nullptr ||
      !CTR_DRBG_init(drbg, /*df=*/false, entropy, CTR_DRBG_ENTROPY_LEN,
                     /*nonce=*/nullptr, personalization, personalization_len)) {
    CTR_DRBG_free(drbg);
    return nullptr;
  }

  return drbg;
}

CTR_DRBG_STATE *CTR_DRBG_new_df(const uint8_t *entropy, size_t entropy_len,
                                const uint8_t nonce[CTR_DRBG_NONCE_LEN],
                                const uint8_t *personalization,
                                size_t personalization_len) {
  CTR_DRBG_STATE *drbg = New<CTR_DRBG_STATE>();
  if (drbg == nullptr ||
      !CTR_DRBG_init(drbg, /*df=*/true, entropy, entropy_len, nonce,
                     personalization, personalization_len)) {
    CTR_DRBG_free(drbg);
    return nullptr;
  }

  return drbg;
}

void CTR_DRBG_free(CTR_DRBG_STATE *state) { Delete(state); }

int bssl::CTR_DRBG_init(CTR_DRBG_STATE *drbg, int df, const uint8_t *entropy,
                        size_t entropy_len,
                        const uint8_t nonce[CTR_DRBG_NONCE_LEN],
                        const uint8_t *personalization,
                        size_t personalization_len) {
  // Section 10.2.1.3.1 and 10.2.1.3.2
  if (personalization_len > CTR_DRBG_SEED_LEN ||
      (!df && entropy_len != CTR_DRBG_ENTROPY_LEN) ||
      (df && (entropy_len < CTR_DRBG_MIN_ENTROPY_LEN ||
              entropy_len > CTR_DRBG_MAX_ENTROPY_LEN)) ||  //
      (df != (nonce != nullptr))) {
    return 0;
  }

  uint8_t seed_material[CTR_DRBG_SEED_LEN];
  if (df) {
    uint8_t pre_seed_material[CTR_DRBG_MAX_ENTROPY_LEN + CTR_DRBG_NONCE_LEN +
                              CTR_DRBG_SEED_LEN];
    OPENSSL_memcpy(pre_seed_material, entropy, entropy_len);
    OPENSSL_memcpy(pre_seed_material + entropy_len, nonce, CTR_DRBG_NONCE_LEN);
    OPENSSL_memcpy(pre_seed_material + entropy_len + CTR_DRBG_NONCE_LEN,
                   personalization, personalization_len);
    const size_t pre_seed_material_length =
        entropy_len + CTR_DRBG_NONCE_LEN + personalization_len;

    if (!block_cipher_df(seed_material, sizeof(seed_material),
                         pre_seed_material, pre_seed_material_length)) {
      return 0;
    }
  } else {
    OPENSSL_memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);
    for (size_t i = 0; i < personalization_len; i++) {
      seed_material[i] ^= personalization[i];
    }
  }

  // Section 10.2.1.2

  // kInitMask is the result of encrypting blocks with big-endian value 1, 2
  // and 3 with the all-zero AES-256 key.
  static const uint8_t kInitMask[CTR_DRBG_SEED_LEN] = {
      0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1,
      0xc4, 0xcb, 0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
      0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18, 0x72, 0x60, 0x03, 0xca,
      0x37, 0xa6, 0x2a, 0x74, 0xd1, 0xa2, 0xf5, 0x8e, 0x75, 0x06, 0x35, 0x8e,
  };

  for (size_t i = 0; i < sizeof(kInitMask); i++) {
    seed_material[i] ^= kInitMask[i];
  }

  drbg->df = df;
  drbg->generic = 0;  // AES-256 고속경로.
  drbg->ctr =
      aes_ctr_set_key(&drbg->ks, nullptr, &drbg->block, seed_material, 32);
  OPENSSL_memcpy(drbg->counter, seed_material + 32, 16);
  drbg->reseed_counter = 1;

  return 1;
}

static_assert(CTR_DRBG_SEED_LEN % AES_BLOCK_SIZE == 0,
              "not a multiple of AES block size");

// ctr_inc adds `n` to the last four bytes of `drbg->counter`, treated as a
// big-endian number.
static void ctr32_add(CTR_DRBG_STATE *drbg, uint32_t n) {
  uint32_t ctr = CRYPTO_load_u32_be(drbg->counter + 12);
  CRYPTO_store_u32_be(drbg->counter + 12, ctr + n);
}

static int ctr_drbg_update(CTR_DRBG_STATE *drbg,
                           const uint8_t data[CTR_DRBG_SEED_LEN]) {
  uint8_t temp[CTR_DRBG_SEED_LEN];
  for (size_t i = 0; i < CTR_DRBG_SEED_LEN; i += AES_BLOCK_SIZE) {
    ctr32_add(drbg, 1);
    drbg->block(drbg->counter, temp + i, &drbg->ks);
  }

  for (size_t i = 0; i < CTR_DRBG_SEED_LEN; i++) {
    temp[i] ^= data[i];
  }

  drbg->ctr = aes_ctr_set_key(&drbg->ks, nullptr, &drbg->block, temp, 32);
  OPENSSL_memcpy(drbg->counter, temp + 32, 16);

  return 1;
}

int CTR_DRBG_reseed(CTR_DRBG_STATE *drbg,
                    const uint8_t entropy[CTR_DRBG_ENTROPY_LEN],
                    const uint8_t *additional_data,
                    size_t additional_data_len) {
  return CTR_DRBG_reseed_ex(drbg, entropy, CTR_DRBG_ENTROPY_LEN,
                            additional_data, additional_data_len);
}

int CTR_DRBG_reseed_ex(CTR_DRBG_STATE *drbg, const uint8_t *entropy,
                       size_t entropy_len, const uint8_t *additional_data,
                       size_t additional_data_len) {
  if (drbg->generic) {
    return ctr_drbg_reseed_generic(drbg, entropy, entropy_len, additional_data,
                                   additional_data_len);
  }
  if (additional_data_len > CTR_DRBG_SEED_LEN ||
      (drbg->df && (entropy_len > CTR_DRBG_MAX_ENTROPY_LEN ||
                    entropy_len < CTR_DRBG_MIN_ENTROPY_LEN)) ||
      (!drbg->df && entropy_len != CTR_DRBG_ENTROPY_LEN)) {
    return 0;
  }

  uint8_t seed_material[CTR_DRBG_SEED_LEN];
  if (drbg->df) {
    // Section 10.2.1.4.2
    uint8_t pre_seed_material[CTR_DRBG_MAX_ENTROPY_LEN + CTR_DRBG_SEED_LEN];
    static_assert(CTR_DRBG_MAX_ENTROPY_LEN <= sizeof(pre_seed_material));
    OPENSSL_memcpy(pre_seed_material, entropy, entropy_len);
    OPENSSL_memcpy(pre_seed_material + entropy_len, additional_data,
                   additional_data_len);
    const size_t pre_seed_material_len = entropy_len + additional_data_len;

    if (!block_cipher_df(seed_material, sizeof(seed_material),
                         pre_seed_material, pre_seed_material_len)) {
      return 0;
    }
  } else {
    // Section 10.2.1.4
    static_assert(CTR_DRBG_ENTROPY_LEN == sizeof(seed_material));
    OPENSSL_memcpy(seed_material, entropy, CTR_DRBG_ENTROPY_LEN);
    if (additional_data_len > 0) {
      for (size_t i = 0; i < additional_data_len; i++) {
        seed_material[i] ^= additional_data[i];
      }
    }
  }

  if (!ctr_drbg_update(drbg, seed_material)) {
    return 0;
  }

  drbg->reseed_counter = 1;

  return 1;
}

int CTR_DRBG_generate(CTR_DRBG_STATE *drbg, uint8_t *out, size_t out_len,
                      const uint8_t *additional_data,
                      size_t additional_data_len) {
  // See 9.3.1
  if (out_len > CTR_DRBG_MAX_GENERATE_LENGTH) {
    return 0;
  }

  if (drbg->generic) {
    return ctr_drbg_generate_generic(drbg, out, out_len, additional_data,
                                     additional_data_len);
  }

  // See 10.2.1.5.1
  if (drbg->reseed_counter > kMaxReseedCount) {
    return 0;
  }

  uint8_t processed_additional_data[CTR_DRBG_SEED_LEN];
  OPENSSL_memset(processed_additional_data, 0,
                 sizeof(processed_additional_data));
  if (additional_data_len != 0) {
    if (drbg->df) {
      if (!block_cipher_df(processed_additional_data,
                           sizeof(processed_additional_data), additional_data,
                           additional_data_len)) {
        return 0;
      }
    } else {
      if (additional_data_len > sizeof(processed_additional_data)) {
        return 0;
      }
      OPENSSL_memcpy(processed_additional_data, additional_data,
                     additional_data_len);
    }
    if (!ctr_drbg_update(drbg, processed_additional_data)) {
      return 0;
    }
  }

  // kChunkSize is used to interact better with the cache. Since the AES-CTR
  // code assumes that it's encrypting rather than just writing keystream, the
  // buffer has to be zeroed first. Without chunking, large reads would zero
  // the whole buffer, flushing the L1 cache, and then do another pass (missing
  // the cache every time) to “encrypt” it. The code can avoid this by
  // chunking.
  constexpr size_t kChunkSize = 8 * 1024;

  while (out_len >= AES_BLOCK_SIZE) {
    size_t todo = kChunkSize;
    if (todo > out_len) {
      todo = out_len;
    }

    todo &= ~(AES_BLOCK_SIZE - 1);
    const size_t num_blocks = todo / AES_BLOCK_SIZE;

    OPENSSL_memset(out, 0, todo);
    ctr32_add(drbg, 1);
    drbg->ctr(out, out, num_blocks, &drbg->ks, drbg->counter);
    ctr32_add(drbg, (uint32_t)(num_blocks - 1));

    out += todo;
    out_len -= todo;
  }

  if (out_len > 0) {
    uint8_t block[AES_BLOCK_SIZE];
    ctr32_add(drbg, 1);
    drbg->block(drbg->counter, block, &drbg->ks);

    OPENSSL_memcpy(out, block, out_len);
  }

  if (!ctr_drbg_update(drbg, processed_additional_data)) {
    return 0;
  }

  drbg->reseed_counter++;
  FIPS_service_indicator_update_state();
  return 1;
}

void CTR_DRBG_clear(CTR_DRBG_STATE *drbg) {
  OPENSSL_cleanse(drbg, sizeof(CTR_DRBG_STATE));
}
