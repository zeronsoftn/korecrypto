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

// LEA block cipher (KS X 3246 / ISO 29192-2). Reference scalar implementation;
// all words are little-endian. Verified against the KISA reference vectors.

#include <openssl/lea.h>

#include <string.h>

#include "../../internal.h"


namespace {

// Key-schedule delta constants (KS X 3246).
const uint32_t kLeaDelta[8] = {0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
                               0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957};

// Left rotation amounts applied to T[j] during key expansion.
const unsigned kLeaKeyRot[6] = {1, 3, 6, 11, 13, 17};

inline uint32_t rotl32(uint32_t x, unsigned n) {
  return (x << n) | (x >> (32 - n));
}

inline uint32_t rotr32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32 - n));
}

}  // namespace

extern "C" {

int LEA_set_key(const uint8_t *key, unsigned bits, LEA_KEY *lea_key) {
  unsigned key_words;
  switch (bits) {
    case 128:
      key_words = 4;
      break;
    case 192:
      key_words = 6;
      break;
    case 256:
      key_words = 8;
      break;
    default:
      return -1;
  }
  lea_key->rounds = (bits / 16) + 16;  // 24, 28, or 32.

  uint32_t t[8] = {0};
  for (unsigned i = 0; i < key_words; i++) {
    t[i] = CRYPTO_load_u32_le(key + 4 * i);
  }

  uint32_t(*rk)[6] = lea_key->rk;
  if (bits == 128) {
    for (unsigned i = 0; i < lea_key->rounds; i++) {
      uint32_t d = rotl32(kLeaDelta[i & 3], i & 31);
      rk[i][0] = t[0] = rotl32(t[0] + d, 1);
      rk[i][1] = rk[i][3] = rk[i][5] = t[1] = rotl32(t[1] + rotl32(d, 1), 3);
      rk[i][2] = t[2] = rotl32(t[2] + rotl32(d, 2), 6);
      rk[i][4] = t[3] = rotl32(t[3] + rotl32(d, 3), 11);
    }
  } else if (bits == 192) {
    for (unsigned i = 0; i < lea_key->rounds; i++) {
      uint32_t d = rotl32(kLeaDelta[i % 6], i & 31);
      for (unsigned j = 0; j < 6; j++) {
        rk[i][j] = t[j] = rotl32(t[j] + rotl32(d, j), kLeaKeyRot[j]);
      }
    }
  } else {  // 256
    for (unsigned i = 0; i < lea_key->rounds; i++) {
      uint32_t d = rotl32(kLeaDelta[i & 7], i & 31);
      for (unsigned j = 0; j < 6; j++) {
        unsigned idx = (6 * i + j) & 7;
        rk[i][j] = t[idx] = rotl32(t[idx] + rotl32(d, j), kLeaKeyRot[j]);
      }
    }
  }

  OPENSSL_cleanse(t, sizeof(t));
  return 0;
}

void LEA_encrypt_block(const uint8_t in[LEA_BLOCK_SIZE],
                       uint8_t out[LEA_BLOCK_SIZE], const LEA_KEY *key) {
  uint32_t x0 = CRYPTO_load_u32_le(in + 0);
  uint32_t x1 = CRYPTO_load_u32_le(in + 4);
  uint32_t x2 = CRYPTO_load_u32_le(in + 8);
  uint32_t x3 = CRYPTO_load_u32_le(in + 12);

  for (unsigned i = 0; i < key->rounds; i++) {
    const uint32_t *r = key->rk[i];
    uint32_t n0 = rotl32((x0 ^ r[0]) + (x1 ^ r[1]), 9);
    uint32_t n1 = rotr32((x1 ^ r[2]) + (x2 ^ r[3]), 5);
    uint32_t n2 = rotr32((x2 ^ r[4]) + (x3 ^ r[5]), 3);
    x3 = x0;
    x0 = n0;
    x1 = n1;
    x2 = n2;
  }

  CRYPTO_store_u32_le(out + 0, x0);
  CRYPTO_store_u32_le(out + 4, x1);
  CRYPTO_store_u32_le(out + 8, x2);
  CRYPTO_store_u32_le(out + 12, x3);
}

void LEA_decrypt_block(const uint8_t in[LEA_BLOCK_SIZE],
                       uint8_t out[LEA_BLOCK_SIZE], const LEA_KEY *key) {
  uint32_t x0 = CRYPTO_load_u32_le(in + 0);
  uint32_t x1 = CRYPTO_load_u32_le(in + 4);
  uint32_t x2 = CRYPTO_load_u32_le(in + 8);
  uint32_t x3 = CRYPTO_load_u32_le(in + 12);

  for (int i = (int)key->rounds - 1; i >= 0; i--) {
    const uint32_t *r = key->rk[i];
    uint32_t o0 = x3;
    uint32_t o1 = (rotr32(x0, 9) - (o0 ^ r[0])) ^ r[1];
    uint32_t o2 = (rotl32(x1, 5) - (o1 ^ r[2])) ^ r[3];
    uint32_t o3 = (rotl32(x2, 3) - (o2 ^ r[4])) ^ r[5];
    x0 = o0;
    x1 = o1;
    x2 = o2;
    x3 = o3;
  }

  CRYPTO_store_u32_le(out + 0, x0);
  CRYPTO_store_u32_le(out + 4, x1);
  CRYPTO_store_u32_le(out + 8, x2);
  CRYPTO_store_u32_le(out + 12, x3);
}

}  // extern "C"
