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

// EC-KCDSA (타원곡선 한국형 전자서명, TTAK.KO-12.0015) — KCMVP 검증대상 전자서명.
//
// 도메인 파라미터는 NIST 소수체 곡선(P-224, P-256)을 사용하며, 해시 함수는
// 곡선 비트수와 일치하는 SHA-224/SHA-256를 사용한다. 공개키는 일반적인
// ECDSA와 달리 Q = (d^{-1} mod n)·G 로 정의된다.

#ifndef OPENSSL_HEADER_ECKCDSA_H
#define OPENSSL_HEADER_ECKCDSA_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// EC_KCDSA_KEY 는 EC-KCDSA 키(도메인 파라미터 + 개인키/공개키)를 담는다.
typedef struct ec_kcdsa_key_st EC_KCDSA_KEY;

// EC_KCDSA_KEY_new 는 |nid| 곡선(NID_secp224r1 또는 NID_X9_62_prime256v1)에 대한
// 빈 키 객체를 생성한다. 실패 시 NULL.
OPENSSL_EXPORT EC_KCDSA_KEY *EC_KCDSA_KEY_new(int nid);

// EC_KCDSA_KEY_free 는 |key| 와 그 내부 데이터를 해제한다.
OPENSSL_EXPORT void EC_KCDSA_KEY_free(EC_KCDSA_KEY *key);

// EC_KCDSA_KEY_set_private 는 개인키 d(빅엔디안 |d_len| 바이트)를 설정하고,
// 공개키 Q = (d^{-1} mod n)·G 를 계산한다. 성공 시 1.
OPENSSL_EXPORT int EC_KCDSA_KEY_set_private(EC_KCDSA_KEY *key, const uint8_t *d,
                                            size_t d_len);

// EC_KCDSA_KEY_set_public 는 검증용으로 공개키 좌표(빅엔디안)를 직접 설정한다.
OPENSSL_EXPORT int EC_KCDSA_KEY_set_public(EC_KCDSA_KEY *key, const uint8_t *qx,
                                           size_t qx_len, const uint8_t *qy,
                                           size_t qy_len);

// EC_KCDSA_KEY_get_public 는 공개키 좌표를 각각 |coord_len| 바이트(빅엔디안)로
// 추출한다. |coord_len| 은 곡선 좌표 바이트 길이여야 한다. 성공 시 1.
OPENSSL_EXPORT int EC_KCDSA_KEY_get_public(const EC_KCDSA_KEY *key, uint8_t *qx,
                                           uint8_t *qy, size_t coord_len);

// EC_KCDSA_coord_len 은 곡선의 좌표/서명요소 바이트 길이(L)를 반환한다.
// 서명 길이는 2L 이다.
OPENSSL_EXPORT size_t EC_KCDSA_coord_len(const EC_KCDSA_KEY *key);

// EC_KCDSA_sign 은 |msg| 에 서명한다. |md| 는 SHA-224(P-224)/SHA-256(P-256)로
// 곡선 좌표 길이와 다이제스트 길이가 일치해야 한다. |k| 가 NULL이 아니면 그
// 난수값(빅엔디안, mod n 적용 전)을 서명 난수로 사용하고(KAT 용), NULL이면
// 내부적으로 난수를 생성한다. 서명은 |sig|(R||S, 각 L바이트)에 기록되고
// |*sig_len| 에 길이를 반환한다. 성공 시 1.
OPENSSL_EXPORT int EC_KCDSA_sign(const EC_KCDSA_KEY *key, const EVP_MD *md,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *k, size_t k_len, uint8_t *sig,
                                 size_t *sig_len);

// EC_KCDSA_verify 는 서명을 검증한다. 유효하면 1, 아니면 0.
OPENSSL_EXPORT int EC_KCDSA_verify(const EC_KCDSA_KEY *key, const EVP_MD *md,
                                   const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len);


#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // OPENSSL_HEADER_ECKCDSA_H
