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

// EC-KCDSA (TTAK.KO-12.0015) — KCMVP 검증대상 전자서명.
//
// 서명 (개인키 d, 공개키 Q = d^{-1}·G):
//   1. k 를 [1, n-1] 에서 선택
//   2. (x1, y1) = k·G,  R = Hash(x1)            (x1 은 L바이트 빅엔디안)
//   3. C_Q = X_Q || Y_Q || 0..0 (총 64바이트),  V = Hash(C_Q || M)
//   4. E = (R xor V) mod n
//   5. S = d·(k - E) mod n
//   서명 = R || S  (각 L바이트)
// 검증:
//   E' = (R' xor V') mod n,  (x2, y2) = S'·Q + E'·G,  Hash(x2) == R' 확인

#include <openssl/eckcdsa.h>

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>

#include "../../internal.h"

// EC-KCDSA 해시 입력의 공개키 블록 길이(바이트). 표준상 64로 고정된다.
#define EC_KCDSA_CQ_BLOCK_LEN 64

struct ec_kcdsa_key_st {
  EC_GROUP *group;
  BIGNUM *d;     // 개인키
  EC_POINT *Q;   // 공개키 = d^{-1}·G
};

extern "C" {

EC_KCDSA_KEY *EC_KCDSA_KEY_new(int nid) {
  if (nid != NID_secp224r1 && nid != NID_X9_62_prime256v1) {
    OPENSSL_PUT_ERROR(EC, EC_R_UNKNOWN_GROUP);
    return nullptr;
  }
  EC_KCDSA_KEY *key =
      reinterpret_cast<EC_KCDSA_KEY *>(OPENSSL_zalloc(sizeof(EC_KCDSA_KEY)));
  if (key == nullptr) {
    return nullptr;
  }
  key->group = EC_GROUP_new_by_curve_name(nid);
  if (key->group == nullptr) {
    OPENSSL_free(key);
    return nullptr;
  }
  return key;
}

void EC_KCDSA_KEY_free(EC_KCDSA_KEY *key) {
  if (key == nullptr) {
    return;
  }
  EC_GROUP_free(key->group);
  BN_clear_free(key->d);
  EC_POINT_free(key->Q);
  OPENSSL_free(key);
}

size_t EC_KCDSA_coord_len(const EC_KCDSA_KEY *key) {
  if (key == nullptr || key->group == nullptr) {
    return 0;
  }
  return (EC_GROUP_get_degree(key->group) + 7) / 8;
}

int EC_KCDSA_KEY_set_private(EC_KCDSA_KEY *key, const uint8_t *d,
                             size_t d_len) {
  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *d_inv = BN_new();
  EC_POINT *Q = EC_POINT_new(key->group);
  if (ctx == nullptr || d_inv == nullptr || Q == nullptr) {
    goto err;
  }
  BN_clear_free(key->d);
  key->d = BN_bin2bn(d, d_len, nullptr);
  if (key->d == nullptr) {
    goto err;
  }
  const BIGNUM *order;
  order = EC_GROUP_get0_order(key->group);
  // d 는 [1, n-1] 범위여야 한다.
  if (BN_is_zero(key->d) || BN_cmp(key->d, order) >= 0) {
    OPENSSL_PUT_ERROR(EC, EC_R_INVALID_PRIVATE_KEY);
    goto err;
  }
  // Q = (d^{-1} mod n)·G
  if (BN_mod_inverse(d_inv, key->d, order, ctx) == nullptr ||
      !EC_POINT_mul(key->group, Q, d_inv, nullptr, nullptr, ctx)) {
    goto err;
  }
  EC_POINT_free(key->Q);
  key->Q = Q;
  Q = nullptr;
  ret = 1;

err:
  BN_free(d_inv);
  EC_POINT_free(Q);
  BN_CTX_free(ctx);
  return ret;
}

int EC_KCDSA_KEY_set_public(EC_KCDSA_KEY *key, const uint8_t *qx, size_t qx_len,
                            const uint8_t *qy, size_t qy_len) {
  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = BN_bin2bn(qx, qx_len, nullptr);
  BIGNUM *y = BN_bin2bn(qy, qy_len, nullptr);
  EC_POINT *Q = EC_POINT_new(key->group);
  if (ctx == nullptr || x == nullptr || y == nullptr || Q == nullptr) {
    goto err;
  }
  if (!EC_POINT_set_affine_coordinates_GFp(key->group, Q, x, y, ctx)) {
    goto err;
  }
  EC_POINT_free(key->Q);
  key->Q = Q;
  Q = nullptr;
  ret = 1;

err:
  BN_free(x);
  BN_free(y);
  EC_POINT_free(Q);
  BN_CTX_free(ctx);
  return ret;
}

int EC_KCDSA_KEY_get_public(const EC_KCDSA_KEY *key, uint8_t *qx, uint8_t *qy,
                            size_t coord_len) {
  if (key->Q == nullptr) {
    return 0;
  }
  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  if (ctx == nullptr || x == nullptr || y == nullptr) {
    goto err;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(key->group, key->Q, x, y, ctx) ||
      !BN_bn2bin_padded(qx, coord_len, x) ||
      !BN_bn2bin_padded(qy, coord_len, y)) {
    goto err;
  }
  ret = 1;

err:
  BN_free(x);
  BN_free(y);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"

namespace {

// eckcdsa_hash 는 |md| 로 |in|(|in_len|) 을 한 번에 해시한다.
int eckcdsa_hash(const EVP_MD *md, const uint8_t *in, size_t in_len,
                 uint8_t *out) {
  unsigned out_len = 0;
  return EVP_Digest(in, in_len, out, &out_len, md, nullptr) &&
         out_len == EVP_MD_size(md);
}

// eckcdsa_compute_v 는 V = Hash(X_Q || Y_Q || pad || M) 를 계산한다.
// C_Q 영역은 항상 64바이트(EC_KCDSA_CQ_BLOCK_LEN)로, X_Q/Y_Q 각 L바이트 뒤를
// 0으로 채운다.
int eckcdsa_compute_v(const EC_KCDSA_KEY *key, const EVP_MD *md, size_t L,
                      const uint8_t *msg, size_t msg_len, uint8_t *v) {
  int ret = 0;
  uint8_t qx[64], qy[64];
  uint8_t *buf = reinterpret_cast<uint8_t *>(
      OPENSSL_malloc(EC_KCDSA_CQ_BLOCK_LEN + msg_len));
  if (buf == nullptr) {
    return 0;
  }
  if (!EC_KCDSA_KEY_get_public(key, qx, qy, L)) {
    goto err;
  }
  OPENSSL_memset(buf, 0, EC_KCDSA_CQ_BLOCK_LEN);
  OPENSSL_memcpy(buf, qx, L);
  OPENSSL_memcpy(buf + L, qy, L);
  if (msg_len > 0) {
    OPENSSL_memcpy(buf + EC_KCDSA_CQ_BLOCK_LEN, msg, msg_len);
  }
  ret = eckcdsa_hash(md, buf, EC_KCDSA_CQ_BLOCK_LEN + msg_len, v);

err:
  OPENSSL_free(buf);
  return ret;
}

}  // namespace

extern "C" {

int EC_KCDSA_sign(const EC_KCDSA_KEY *key, const EVP_MD *md, const uint8_t *msg,
                  size_t msg_len, const uint8_t *k_in, size_t k_in_len,
                  uint8_t *sig, size_t *sig_len) {
  if (key == nullptr || key->d == nullptr || key->Q == nullptr) {
    return 0;
  }
  size_t L = EC_KCDSA_coord_len(key);
  // 좌표 길이와 다이제스트 길이가 일치해야 한다(P-224/SHA-224, P-256/SHA-256).
  if (L == 0 || L > 64 || EVP_MD_size(md) != L) {
    OPENSSL_PUT_ERROR(EC, EC_R_INVALID_PRIVATE_KEY);
    return 0;
  }

  int ret = 0;
  uint8_t r[64], v[64], x1_bytes[64];
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *k = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *x1 = BN_new();
  BIGNUM *s = BN_new();
  BIGNUM *k_e = BN_new();
  BIGNUM *r_xor_v = BN_new();
  EC_POINT *kG = EC_POINT_new(key->group);
  uint8_t k_rand[64];
  const BIGNUM *order;
  if (ctx == nullptr || k == nullptr || e == nullptr || x1 == nullptr ||
      s == nullptr || k_e == nullptr || r_xor_v == nullptr || kG == nullptr) {
    goto err;
  }
  order = EC_GROUP_get0_order(key->group);

  // step 1. 난수 k 선택 (KAT 용 입력이 있으면 사용)
  if (k_in != nullptr) {
    if (BN_bin2bn(k_in, k_in_len, k) == nullptr) {
      goto err;
    }
  } else {
    if (!RAND_bytes(k_rand, L)) {
      goto err;
    }
    if (BN_bin2bn(k_rand, L, k) == nullptr) {
      goto err;
    }
  }
  if (!BN_nnmod(k, k, order, ctx)) {
    goto err;
  }

  // step 2. (x1, y1) = k·G,  R = Hash(x1)
  if (!EC_POINT_mul(key->group, kG, k, nullptr, nullptr, ctx) ||
      !EC_POINT_get_affine_coordinates_GFp(key->group, kG, x1, nullptr, ctx) ||
      !BN_bn2bin_padded(x1_bytes, L, x1) ||
      !eckcdsa_hash(md, x1_bytes, L, r)) {
    goto err;
  }

  // step 3. V = Hash(C_Q || M)
  if (!eckcdsa_compute_v(key, md, L, msg, msg_len, v)) {
    goto err;
  }

  // step 4. E = (R xor V) mod n
  for (size_t i = 0; i < L; i++) {
    r[i] ^= v[i];
  }
  if (BN_bin2bn(r, L, r_xor_v) == nullptr ||
      !BN_nnmod(e, r_xor_v, order, ctx)) {
    goto err;
  }
  // R 을 복원해 서명 앞부분에 기록 (r 버퍼는 xor 로 덮였으므로 재계산)
  for (size_t i = 0; i < L; i++) {
    r[i] ^= v[i];
  }

  // step 5. S = d·(k - E) mod n
  if (!BN_mod_sub(k_e, k, e, order, ctx) ||
      !BN_mod_mul(s, key->d, k_e, order, ctx)) {
    goto err;
  }

  OPENSSL_memcpy(sig, r, L);
  if (!BN_bn2bin_padded(sig + L, L, s)) {
    goto err;
  }
  *sig_len = 2 * L;
  ret = 1;

err:
  BN_free(k);
  BN_free(e);
  BN_free(x1);
  BN_free(s);
  BN_free(k_e);
  BN_free(r_xor_v);
  EC_POINT_free(kG);
  BN_CTX_free(ctx);
  return ret;
}

int EC_KCDSA_verify(const EC_KCDSA_KEY *key, const EVP_MD *md,
                    const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                    size_t sig_len) {
  if (key == nullptr || key->Q == nullptr) {
    return 0;
  }
  size_t L = EC_KCDSA_coord_len(key);
  if (L == 0 || L > 64 || EVP_MD_size(md) != L || sig_len != 2 * L) {
    return 0;
  }

  int ret = 0;
  uint8_t v[64], r_check[64], x2_bytes[64];
  const uint8_t *R = sig;
  const uint8_t *S = sig + L;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e = BN_new();
  BIGNUM *s = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *r_xor_v = BN_new();
  EC_POINT *point = EC_POINT_new(key->group);
  const BIGNUM *order;
  if (ctx == nullptr || e == nullptr || s == nullptr || x2 == nullptr ||
      r_xor_v == nullptr || point == nullptr) {
    goto err;
  }
  order = EC_GROUP_get0_order(key->group);

  // 0 < S < n 확인
  if (BN_bin2bn(S, L, s) == nullptr || BN_is_zero(s) ||
      BN_cmp(s, order) >= 0) {
    goto err;
  }

  // V' = Hash(C_Q || M)
  if (!eckcdsa_compute_v(key, md, L, msg, msg_len, v)) {
    goto err;
  }

  // E' = (R' xor V') mod n
  for (size_t i = 0; i < L; i++) {
    v[i] ^= R[i];
  }
  if (BN_bin2bn(v, L, r_xor_v) == nullptr ||
      !BN_nnmod(e, r_xor_v, order, ctx)) {
    goto err;
  }

  // (x2, y2) = S'·Q + E'·G  (EC_POINT_mul: r = G*e + Q*s)
  if (!EC_POINT_mul(key->group, point, e, key->Q, s, ctx) ||
      !EC_POINT_get_affine_coordinates_GFp(key->group, point, x2, nullptr,
                                           ctx) ||
      !BN_bn2bin_padded(x2_bytes, L, x2) ||
      !eckcdsa_hash(md, x2_bytes, L, r_check)) {
    goto err;
  }

  // Hash(x2) == R' 확인 (상수시간 비교)
  ret = CRYPTO_memcmp(r_check, R, L) == 0;

err:
  BN_free(e);
  BN_free(s);
  BN_free(x2);
  BN_free(r_xor_v);
  EC_POINT_free(point);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"

namespace {

// eckcdsa_md_for_len 은 좌표 길이 L 에 맞는 해시(SHA-224/256)를 반환한다.
const EVP_MD *eckcdsa_md_for_len(size_t L) {
  if (L == 28) {
    return EVP_sha224();
  }
  if (L == 32) {
    return EVP_sha256();
  }
  return nullptr;
}

// eckcdsa_pct 는 키쌍 일치시험(PCT)을 수행한다(KCMVP 조건부 자가시험).
// 고정 메시지에 서명한 뒤 검증이 성공해야 한다.
int eckcdsa_pct(const EC_KCDSA_KEY *key, const EVP_MD *md) {
  static const uint8_t kMsg[] = "KCMVP EC-KCDSA pairwise consistency test";
  uint8_t sig[128];
  size_t sig_len = 0;
  if (!EC_KCDSA_sign(key, md, kMsg, sizeof(kMsg), nullptr, 0, sig, &sig_len)) {
    return 0;
  }
  return EC_KCDSA_verify(key, md, kMsg, sizeof(kMsg), sig, sig_len);
}

}  // namespace

extern "C" {

int EC_KCDSA_KEY_generate(EC_KCDSA_KEY *key) {
  if (key == nullptr || key->group == nullptr) {
    return 0;
  }
  size_t L = EC_KCDSA_coord_len(key);
  const EVP_MD *md = eckcdsa_md_for_len(L);
  if (md == nullptr) {
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *d = BN_new();
  BIGNUM *d_inv = BN_new();
  EC_POINT *Q = EC_POINT_new(key->group);
  const BIGNUM *order;
  if (ctx == nullptr || d == nullptr || d_inv == nullptr || Q == nullptr) {
    goto err;
  }
  order = EC_GROUP_get0_order(key->group);

  // 개인키 d 를 [1, n-1] 에서 무작위 생성하고 Q = d^{-1}·G 계산.
  if (!BN_rand_range_ex(d, 1, order) ||
      BN_mod_inverse(d_inv, d, order, ctx) == nullptr ||
      !EC_POINT_mul(key->group, Q, d_inv, nullptr, nullptr, ctx)) {
    goto err;
  }
  BN_clear_free(key->d);
  key->d = d;
  d = nullptr;
  EC_POINT_free(key->Q);
  key->Q = Q;
  Q = nullptr;

  // 키쌍 일치시험(PCT). 실패 시 키를 폐기한다.
  if (!eckcdsa_pct(key, md)) {
    BN_clear_free(key->d);
    key->d = nullptr;
    EC_POINT_free(key->Q);
    key->Q = nullptr;
    goto err;
  }
  ret = 1;

err:
  BN_clear_free(d);
  BN_free(d_inv);
  EC_POINT_free(Q);
  BN_CTX_free(ctx);
  return ret;
}

}  // extern "C"
