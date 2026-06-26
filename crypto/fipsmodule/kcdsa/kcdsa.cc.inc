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

// KCDSA (TTAK.KO-12.0001) — KCMVP 검증대상 전자서명.
//
// 서명 (개인키 x, 공개키 y = G^{x^{-1} mod Q} mod P):
//   1. k 를 [1, Q-1] 에서 선택
//   2. W = G^k mod P,  R = Hash(W)                 (W 는 |P|바이트 빅엔디안)
//   3. Z = y mod 2^512 (64바이트 빅엔디안),  H = Hash(Z || M)
//   4. E = (R xor H) mod Q
//   5. S = x·(k - E) mod Q
//   서명 = R || S  (각 |Q|바이트)
// 검증:
//   E' = (R' xor H') mod Q,  W' = y^{S'}·G^{E'} mod P,  Hash(W') == R' 확인

#include <openssl/kcdsa.h>

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "../../internal.h"

// KCDSA 의 Z = y mod 2^512 블록 길이(바이트).
#define KCDSA_Z_LEN 64

struct kcdsa_key_st {
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *g;
  BIGNUM *x;  // 개인키
  BIGNUM *y;  // 공개키
};

extern "C" {

KCDSA_KEY *KCDSA_KEY_new(void) {
  return reinterpret_cast<KCDSA_KEY *>(OPENSSL_zalloc(sizeof(KCDSA_KEY)));
}

void KCDSA_KEY_free(KCDSA_KEY *key) {
  if (key == nullptr) {
    return;
  }
  BN_free(key->p);
  BN_free(key->q);
  BN_free(key->g);
  BN_clear_free(key->x);
  BN_free(key->y);
  OPENSSL_free(key);
}

int KCDSA_KEY_set_params(KCDSA_KEY *key, const uint8_t *p, size_t p_len,
                         const uint8_t *q, size_t q_len, const uint8_t *g,
                         size_t g_len) {
  BIGNUM *bp = BN_bin2bn(p, p_len, nullptr);
  BIGNUM *bq = BN_bin2bn(q, q_len, nullptr);
  BIGNUM *bg = BN_bin2bn(g, g_len, nullptr);
  if (bp == nullptr || bq == nullptr || bg == nullptr) {
    BN_free(bp);
    BN_free(bq);
    BN_free(bg);
    return 0;
  }
  BN_free(key->p);
  BN_free(key->q);
  BN_free(key->g);
  key->p = bp;
  key->q = bq;
  key->g = bg;
  return 1;
}

int KCDSA_KEY_set_private(KCDSA_KEY *key, const uint8_t *x, size_t x_len) {
  if (key->p == nullptr || key->q == nullptr || key->g == nullptr) {
    return 0;
  }
  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x_inv = BN_new();
  BIGNUM *y = BN_new();
  if (ctx == nullptr || x_inv == nullptr || y == nullptr) {
    goto err;
  }
  BN_clear_free(key->x);
  key->x = BN_bin2bn(x, x_len, nullptr);
  if (key->x == nullptr) {
    goto err;
  }
  if (BN_is_zero(key->x) || BN_cmp(key->x, key->q) >= 0) {
    goto err;
  }
  // y = G^{x^{-1} mod Q} mod P
  if (BN_mod_inverse(x_inv, key->x, key->q, ctx) == nullptr ||
      !BN_mod_exp(y, key->g, x_inv, key->p, ctx)) {
    goto err;
  }
  BN_free(key->y);
  key->y = y;
  y = nullptr;
  ret = 1;

err:
  BN_free(x_inv);
  BN_free(y);
  BN_CTX_free(ctx);
  return ret;
}

int KCDSA_KEY_set_public(KCDSA_KEY *key, const uint8_t *y, size_t y_len) {
  BIGNUM *by = BN_bin2bn(y, y_len, nullptr);
  if (by == nullptr) {
    return 0;
  }
  BN_free(key->y);
  key->y = by;
  return 1;
}

int KCDSA_KEY_get_public(const KCDSA_KEY *key, uint8_t *out, size_t max_out,
                         size_t *out_len) {
  if (key->y == nullptr) {
    return 0;
  }
  size_t n = BN_num_bytes(key->y);
  if (n > max_out) {
    return 0;
  }
  *out_len = n;
  return BN_bn2bin_padded(out, n, key->y);
}

size_t KCDSA_sig_len(const KCDSA_KEY *key) {
  if (key->q == nullptr) {
    return 0;
  }
  return 2 * BN_num_bytes(key->q);
}

// kcdsa_bn_out 은 |bn| 을 빅엔디안으로 |out| 에 기록하고 길이를 반환한다.
static int kcdsa_bn_out(const BIGNUM *bn, uint8_t *out, size_t max_out,
                        size_t *out_len) {
  if (bn == nullptr) {
    return 0;
  }
  size_t n = BN_num_bytes(bn);
  if (n > max_out) {
    return 0;
  }
  *out_len = n;
  return BN_bn2bin_padded(out, n, bn);
}

int KCDSA_KEY_get_params(const KCDSA_KEY *key, uint8_t *p, size_t p_max,
                         size_t *p_len, uint8_t *q, size_t q_max, size_t *q_len,
                         uint8_t *g, size_t g_max, size_t *g_len) {
  return kcdsa_bn_out(key->p, p, p_max, p_len) &&
         kcdsa_bn_out(key->q, q, q_max, q_len) &&
         kcdsa_bn_out(key->g, g, g_max, g_len);
}

int KCDSA_KEY_get_private(const KCDSA_KEY *key, uint8_t *out, size_t max_out,
                          size_t *out_len) {
  return kcdsa_bn_out(key->x, out, max_out, out_len);
}

}  // extern "C"

namespace {

int kcdsa_hash(const EVP_MD *md, const uint8_t *in, size_t in_len,
               uint8_t *out) {
  unsigned out_len = 0;
  return EVP_Digest(in, in_len, out, &out_len, md, nullptr) &&
         out_len == EVP_MD_size(md);
}

// kcdsa_compute_h 는 H = Hash(Z || M) 를 계산한다. Z 는 y mod 2^512 를 64바이트
// 빅엔디안으로 표현한 값이다.
int kcdsa_compute_h(const KCDSA_KEY *key, const EVP_MD *md, const uint8_t *msg,
                    size_t msg_len, uint8_t *h) {
  int ret = 0;
  size_t p_bytes = BN_num_bytes(key->p);
  uint8_t *y_buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(p_bytes));
  uint8_t *buf =
      reinterpret_cast<uint8_t *>(OPENSSL_malloc(KCDSA_Z_LEN + msg_len));
  if (y_buf == nullptr || buf == nullptr) {
    goto err;
  }
  if (!BN_bn2bin_padded(y_buf, p_bytes, key->y)) {
    goto err;
  }
  // Z = y mod 2^512 = y 빅엔디안 표현의 하위 64바이트.
  OPENSSL_memset(buf, 0, KCDSA_Z_LEN);
  if (p_bytes >= KCDSA_Z_LEN) {
    OPENSSL_memcpy(buf, y_buf + (p_bytes - KCDSA_Z_LEN), KCDSA_Z_LEN);
  } else {
    OPENSSL_memcpy(buf + (KCDSA_Z_LEN - p_bytes), y_buf, p_bytes);
  }
  if (msg_len > 0) {
    OPENSSL_memcpy(buf + KCDSA_Z_LEN, msg, msg_len);
  }
  ret = kcdsa_hash(md, buf, KCDSA_Z_LEN + msg_len, h);

err:
  OPENSSL_free(y_buf);
  OPENSSL_free(buf);
  return ret;
}

}  // namespace

extern "C" {

int KCDSA_sign(const KCDSA_KEY *key, const EVP_MD *md, const uint8_t *msg,
               size_t msg_len, const uint8_t *k_in, size_t k_in_len,
               uint8_t *sig, size_t *sig_len) {
  if (key == nullptr || key->p == nullptr || key->x == nullptr ||
      key->y == nullptr) {
    return 0;
  }
  size_t q_bytes = BN_num_bytes(key->q);
  size_t md_len = EVP_MD_size(md);
  // 다이제스트 길이는 |Q| 이상이어야 한다(같으면 절단 없음, 크면 절단).
  if (q_bytes == 0 || md_len > 64 || md_len < q_bytes) {
    return 0;
  }
  size_t count = md_len - q_bytes;

  int ret = 0;
  size_t p_bytes = BN_num_bytes(key->p);
  uint8_t r[64], h[64], k_rand[64], e_buf[64];
  uint8_t *w_buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(p_bytes));
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *k = BN_new();
  BIGNUM *w = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *s = BN_new();
  BIGNUM *k_e = BN_new();
  BIGNUM *r_bn = BN_new();
  if (w_buf == nullptr || ctx == nullptr || k == nullptr || w == nullptr ||
      e == nullptr || s == nullptr || k_e == nullptr || r_bn == nullptr) {
    goto err;
  }

  // step 1. 난수 k 선택 (KAT 용 입력이 있으면 사용)
  if (k_in != nullptr) {
    if (BN_bin2bn(k_in, k_in_len, k) == nullptr) {
      goto err;
    }
  } else {
    if (!RAND_bytes(k_rand, q_bytes) || BN_bin2bn(k_rand, q_bytes, k) == nullptr) {
      goto err;
    }
  }
  if (!BN_nnmod(k, k, key->q, ctx)) {
    goto err;
  }

  // step 2. W = G^k mod P,  R = Hash(W)
  if (!BN_mod_exp(w, key->g, k, key->p, ctx) ||
      !BN_bn2bin_padded(w_buf, p_bytes, w) ||
      !kcdsa_hash(md, w_buf, p_bytes, r)) {
    goto err;
  }

  // step 3. H = Hash(Z || M)
  if (!kcdsa_compute_h(key, md, msg, msg_len, h)) {
    goto err;
  }

  // R = Hash(W) 의 하위 |Q|바이트를 서명 앞부분에 저장.
  OPENSSL_memcpy(sig, r + count, q_bytes);

  // step 4. E = (R xor H) mod Q. 절단 시 H 의 하위 |Q|바이트(h[count..]) 사용.
  for (size_t i = 0; i < q_bytes; i++) {
    e_buf[i] = r[count + i] ^ h[count + i];
  }
  if (BN_bin2bn(e_buf, q_bytes, r_bn) == nullptr ||
      !BN_nnmod(e, r_bn, key->q, ctx)) {
    goto err;
  }

  // step 5. S = x·(k - E) mod Q
  if (!BN_mod_sub(k_e, k, e, key->q, ctx) ||
      !BN_mod_mul(s, key->x, k_e, key->q, ctx)) {
    goto err;
  }
  if (!BN_bn2bin_padded(sig + q_bytes, q_bytes, s)) {
    goto err;
  }
  *sig_len = 2 * q_bytes;
  ret = 1;

err:
  OPENSSL_free(w_buf);
  BN_free(k);
  BN_free(w);
  BN_free(e);
  BN_free(s);
  BN_free(k_e);
  BN_free(r_bn);
  BN_CTX_free(ctx);
  return ret;
}

int KCDSA_verify(const KCDSA_KEY *key, const EVP_MD *md, const uint8_t *msg,
                 size_t msg_len, const uint8_t *sig, size_t sig_len) {
  if (key == nullptr || key->p == nullptr || key->y == nullptr) {
    return 0;
  }
  size_t q_bytes = BN_num_bytes(key->q);
  size_t md_len = EVP_MD_size(md);
  // 다이제스트 길이는 |Q| 이상이어야 한다(같으면 절단 없음, 크면 절단).
  if (q_bytes == 0 || md_len > 64 || md_len < q_bytes || sig_len != 2 * q_bytes) {
    return 0;
  }
  size_t count = md_len - q_bytes;  // |Q|<해시 시 해시 상위 절단 길이

  int ret = 0;
  size_t p_bytes = BN_num_bytes(key->p);
  uint8_t h[64], r_check[64], e_buf[64];
  const uint8_t *R = sig;
  const uint8_t *S = sig + q_bytes;
  uint8_t *w_buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(p_bytes));
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e = BN_new();
  BIGNUM *s = BN_new();
  BIGNUM *r_bn = BN_new();
  BIGNUM *w = BN_new();
  BIGNUM *t1 = BN_new();
  BIGNUM *t2 = BN_new();
  if (w_buf == nullptr || ctx == nullptr || e == nullptr || s == nullptr ||
      r_bn == nullptr || w == nullptr || t1 == nullptr || t2 == nullptr) {
    goto err;
  }

  // 0 < S < Q 확인
  if (BN_bin2bn(S, q_bytes, s) == nullptr || BN_is_zero(s) ||
      BN_cmp(s, key->q) >= 0) {
    goto err;
  }

  // H' = Hash(Z || M)
  if (!kcdsa_compute_h(key, md, msg, msg_len, h)) {
    goto err;
  }

  // E' = (R' xor H') mod Q. 절단 시 H' 의 하위 |Q|바이트(h[count..])를 사용.
  for (size_t i = 0; i < q_bytes; i++) {
    e_buf[i] = R[i] ^ h[count + i];
  }
  if (BN_bin2bn(e_buf, q_bytes, r_bn) == nullptr ||
      !BN_nnmod(e, r_bn, key->q, ctx)) {
    goto err;
  }

  // W' = y^{S'}·G^{E'} mod P
  if (!BN_mod_exp(t1, key->y, s, key->p, ctx) ||
      !BN_mod_exp(t2, key->g, e, key->p, ctx) ||
      !BN_mod_mul(w, t1, t2, key->p, ctx) ||
      !BN_bn2bin_padded(w_buf, p_bytes, w) ||
      !kcdsa_hash(md, w_buf, p_bytes, r_check)) {
    goto err;
  }

  // Hash(W') 의 하위 |Q|바이트 == R' 확인 (상수시간 비교)
  ret = CRYPTO_memcmp(r_check + count, R, q_bytes) == 0;

err:
  OPENSSL_free(w_buf);
  BN_free(e);
  BN_free(s);
  BN_free(r_bn);
  BN_free(w);
  BN_free(t1);
  BN_free(t2);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"

namespace {

// kcdsa_md_for_len 은 |Q| 바이트 길이에 맞는 해시(SHA-224/256)를 반환한다.
const EVP_MD *kcdsa_md_for_len(size_t q_bytes) {
  if (q_bytes == 28) {
    return EVP_sha224();
  }
  if (q_bytes == 32) {
    return EVP_sha256();
  }
  return nullptr;
}

// kcdsa_pct 는 키쌍 일치시험(PCT)을 수행한다(KCMVP 조건부 자가시험).
int kcdsa_pct(const KCDSA_KEY *key, const EVP_MD *md) {
  static const uint8_t kMsg[] = "KCMVP KCDSA pairwise consistency test";
  uint8_t sig[128];
  size_t sig_len = 0;
  if (!KCDSA_sign(key, md, kMsg, sizeof(kMsg), nullptr, 0, sig, &sig_len)) {
    return 0;
  }
  return KCDSA_verify(key, md, kMsg, sizeof(kMsg), sig, sig_len);
}

}  // namespace

extern "C" {

int KCDSA_KEY_generate(KCDSA_KEY *key) {
  if (key == nullptr || key->p == nullptr || key->q == nullptr ||
      key->g == nullptr) {
    return 0;
  }
  const EVP_MD *md = kcdsa_md_for_len(BN_num_bytes(key->q));
  if (md == nullptr) {
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = BN_new();
  BIGNUM *x_inv = BN_new();
  BIGNUM *y = BN_new();
  if (ctx == nullptr || x == nullptr || x_inv == nullptr || y == nullptr) {
    goto err;
  }

  // 개인키 x 를 [1, Q-1] 에서 무작위 생성하고 y = G^{x^{-1} mod Q} mod P 계산.
  if (!BN_rand_range_ex(x, 1, key->q) ||
      BN_mod_inverse(x_inv, x, key->q, ctx) == nullptr ||
      !BN_mod_exp(y, key->g, x_inv, key->p, ctx)) {
    goto err;
  }
  BN_clear_free(key->x);
  key->x = x;
  x = nullptr;
  BN_free(key->y);
  key->y = y;
  y = nullptr;

  // 키쌍 일치시험(PCT). 실패 시 키를 폐기한다.
  if (!kcdsa_pct(key, md)) {
    BN_clear_free(key->x);
    key->x = nullptr;
    BN_free(key->y);
    key->y = nullptr;
    goto err;
  }
  ret = 1;

err:
  BN_clear_free(x);
  BN_free(x_inv);
  BN_free(y);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"

namespace {

// kcdsa_ppgf 는 TTAK.KO-12.0001 의 일방향 함수 PPGF 를 구현한다.
// 출력 dst 는 ceil(out_bits/8) 바이트(빅엔디안). Count(1바이트)=0,1,.. 마다
// digest = Hash(src || Count) 를 출력 버퍼의 끝(최하위)부터 앞쪽으로 채우고,
// 마지막에 최상위 바이트를 out_bits 에 맞게 마스크한다.
int kcdsa_ppgf(const EVP_MD *md, const uint8_t *src, size_t src_len,
               uint8_t *dst, size_t out_bits) {
  size_t dlen = EVP_MD_size(md);
  size_t total = (out_bits + 7) / 8;
  uint8_t *buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(src_len + 1));
  if (buf == nullptr) {
    return 0;
  }
  OPENSSL_memcpy(buf, src, src_len);

  int ok = 1;
  size_t i = total;
  uint8_t count = 0;
  uint8_t digest[EVP_MAX_MD_SIZE];
  for (;;) {
    buf[src_len] = count++;
    unsigned dl = 0;
    if (!EVP_Digest(buf, src_len + 1, digest, &dl, md, nullptr)) {
      ok = 0;
      break;
    }
    if (i >= dlen) {
      i -= dlen;
      OPENSSL_memcpy(dst + i, digest, dlen);
      if (i == 0) {
        break;
      }
    } else {
      OPENSSL_memcpy(dst, digest + dlen - i, i);
      break;
    }
  }
  OPENSSL_free(buf);
  if (!ok) {
    return 0;
  }
  unsigned r = out_bits & 7;
  if (r) {
    dst[0] &= static_cast<uint8_t>((1u << r) - 1);
  }
  return 1;
}

}  // namespace

extern "C" {

int KCDSA_generate_parameters(KCDSA_KEY *key, int p_bits, int q_bits,
                              uint8_t *seed_out, size_t *seed_len,
                              uint32_t *count_out, uint8_t *j_out,
                              size_t *j_len, uint8_t *h_out, size_t *h_len) {
  if (key == nullptr || p_bits < 2048 || p_bits > 3072 || (p_bits % 256) != 0 ||
      (q_bits != 224 && q_bits != 256)) {
    return 0;
  }
  const EVP_MD *md = kcdsa_md_for_len(q_bits / 8);
  if (md == nullptr) {
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *J = BN_new();
  BIGNUM *Q = BN_new();
  BIGNUM *P = BN_new();
  BIGNUM *two_j = BN_new();
  BIGNUM *h = BN_new();
  BIGNUM *G = BN_new();
  const size_t seed_bytes = q_bits / 8;
  const size_t u_bytes = (p_bits - q_bits) / 8;  // OS2BN 이 읽는 J 후보 길이
  uint8_t *seed = reinterpret_cast<uint8_t *>(OPENSSL_malloc(seed_bytes + 4));
  uint8_t *ubuf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(u_bytes));
  uint8_t *qbuf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(seed_bytes));
  if (ctx == nullptr || J == nullptr || Q == nullptr || P == nullptr ||
      two_j == nullptr || h == nullptr || G == nullptr || seed == nullptr ||
      ubuf == nullptr || qbuf == nullptr) {
    goto err;
  }

  for (;;) {  // 소수 쌍 (J, Q, P) 탐색 — 실패 시 새 Seed
    // Step 1. Seed = |Q|/8 랜덤 바이트
    if (!RAND_bytes(seed, seed_bytes)) {
      goto err;
    }
    // Step 2. U = PPGF(Seed, |P|-|Q|-4)
    if (!kcdsa_ppgf(md, seed, seed_bytes, ubuf, p_bits - q_bits - 4) ||
        BN_bin2bn(ubuf, u_bytes, J) == nullptr) {
      goto err;
    }
    // Step 3. J = 2^{|P|-|Q|-1} | U | 1
    if (!BN_set_bit(J, p_bits - q_bits - 1) || !BN_set_bit(J, 0)) {
      goto err;
    }
    // Step 4. J 가 소수가 아니면 Seed 재생성
    int j_prime = 0;
    if (!BN_primality_test(&j_prime, J, BN_prime_checks_for_generation, ctx, 1,
                           nullptr)) {
      goto err;
    }
    if (!j_prime) {
      continue;
    }

    // Step 5~12. Count 를 증가시키며 Q, P 탐색
    uint32_t count;
    int found = 0;
    for (count = 1; count < (1u << 24); count++) {
      // Seed || Count(4바이트 빅엔디안, 최상위 바이트 0)
      seed[seed_bytes + 0] = 0;
      seed[seed_bytes + 1] = static_cast<uint8_t>((count >> 16) & 0xff);
      seed[seed_bytes + 2] = static_cast<uint8_t>((count >> 8) & 0xff);
      seed[seed_bytes + 3] = static_cast<uint8_t>(count & 0xff);
      // Step 8. U = PPGF(Seed||Count, |Q|)
      if (!kcdsa_ppgf(md, seed, seed_bytes + 4, qbuf, q_bits) ||
          BN_bin2bn(qbuf, seed_bytes, Q) == nullptr) {
        goto err;
      }
      // Step 9. Q = 2^{|Q|-1} | U | 1
      if (!BN_set_bit(Q, q_bits - 1) || !BN_set_bit(Q, 0)) {
        goto err;
      }
      // Step 10. P = 2·J·Q + 1 (J·Q 의 비트 |P|-1 이 1이면 길이 초과 → 다음 Count)
      if (!BN_mul(P, J, Q, ctx)) {
        goto err;
      }
      if (BN_is_bit_set(P, p_bits - 1)) {
        continue;
      }
      if (!BN_lshift1(P, P) || !BN_set_bit(P, 0)) {
        goto err;
      }
      // Step 11. Q 가 소수가 아니면 다음 Count
      int q_prime = 0;
      if (!BN_primality_test(&q_prime, Q, BN_prime_checks_for_generation, ctx,
                             1, nullptr)) {
        goto err;
      }
      if (!q_prime) {
        continue;
      }
      // Step 12. P 가 소수면 채택
      int p_prime = 0;
      if (!BN_primality_test(&p_prime, P, BN_prime_checks_for_generation, ctx,
                             1, nullptr)) {
        goto err;
      }
      if (p_prime) {
        found = 1;
        break;
      }
    }
    if (!found) {
      continue;  // Count 소진 → 새 Seed
    }
    *count_out = count;
    break;
  }

  // 생성원 g 생성: 2J 를 지수로 G = h^{2J} mod P, G != 1 보장
  if (!BN_lshift1(two_j, J)) {
    goto err;
  }
  for (;;) {
    if (!BN_rand(h, p_bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
        !BN_mod_exp(G, h, two_j, P, ctx)) {
      goto err;
    }
    if (!BN_is_one(G)) {
      break;
    }
  }

  // key 에 도메인 파라미터 설정
  BN_free(key->p);
  BN_free(key->q);
  BN_free(key->g);
  key->p = BN_dup(P);
  key->q = BN_dup(Q);
  key->g = BN_dup(G);
  if (key->p == nullptr || key->q == nullptr || key->g == nullptr) {
    goto err;
  }

  // 증거값 출력
  OPENSSL_memcpy(seed_out, seed, seed_bytes);
  *seed_len = seed_bytes;
  *j_len = BN_bn2bin(J, j_out);
  *h_len = BN_bn2bin(h, h_out);
  ret = 1;

err:
  BN_free(J);
  BN_free(Q);
  BN_free(P);
  BN_free(two_j);
  BN_free(h);
  BN_free(G);
  OPENSSL_free(seed);
  OPENSSL_free(ubuf);
  OPENSSL_free(qbuf);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"
