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

// KCDSA (한국형 전자서명, TTAK.KO-12.0001) — KCMVP 검증대상 전자서명.
//
// 이산대수 기반 서명으로, 도메인 파라미터 (P, Q, G) 와 키 쌍 (x, y) 를 가진다.
// 공개키는 y = G^{x^{-1} mod Q} mod P 로 정의된다. 해시는 SHA-224(|Q|=224) 또는
// SHA-256(|Q|=256) 을 사용한다.

#ifndef OPENSSL_HEADER_KCDSA_H
#define OPENSSL_HEADER_KCDSA_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// KCDSA_KEY 는 KCDSA 도메인 파라미터와 키 쌍을 담는다.
typedef struct kcdsa_key_st KCDSA_KEY;

// KCDSA_KEY_new 는 빈 키 객체를 생성한다. 실패 시 NULL.
OPENSSL_EXPORT KCDSA_KEY *KCDSA_KEY_new(void);

// KCDSA_KEY_free 는 |key| 와 그 내부 데이터를 해제한다.
OPENSSL_EXPORT void KCDSA_KEY_free(KCDSA_KEY *key);

// KCDSA_KEY_set_params 는 도메인 파라미터 P, Q, G(각 빅엔디안)를 설정한다.
OPENSSL_EXPORT int KCDSA_KEY_set_params(KCDSA_KEY *key, const uint8_t *p,
                                        size_t p_len, const uint8_t *q,
                                        size_t q_len, const uint8_t *g,
                                        size_t g_len);

// KCDSA_KEY_set_private 는 개인키 x(빅엔디안)를 설정하고 공개키
// y = G^{x^{-1} mod Q} mod P 를 계산한다. 도메인 파라미터가 먼저 설정되어야 한다.
OPENSSL_EXPORT int KCDSA_KEY_set_private(KCDSA_KEY *key, const uint8_t *x,
                                         size_t x_len);

// KCDSA_KEY_set_public 는 검증용으로 공개키 y(빅엔디안)를 직접 설정한다.
OPENSSL_EXPORT int KCDSA_KEY_set_public(KCDSA_KEY *key, const uint8_t *y,
                                        size_t y_len);

// KCDSA_KEY_get_public 는 공개키 y 를 빅엔디안으로 |out|(|max_out| 바이트)에
// 기록하고 |*out_len| 에 길이를 반환한다.
OPENSSL_EXPORT int KCDSA_KEY_get_public(const KCDSA_KEY *key, uint8_t *out,
                                        size_t max_out, size_t *out_len);

// KCDSA_sig_len 은 서명 길이(2*|Q|바이트)를 반환한다. 파라미터 미설정 시 0.
OPENSSL_EXPORT size_t KCDSA_sig_len(const KCDSA_KEY *key);

// KCDSA_sign 은 |msg| 에 서명한다. |md| 다이제스트 길이는 |Q| 바이트 길이와
// 일치해야 한다. |k| 가 NULL이 아니면 그 난수값(빅엔디안)을 서명 난수로
// 사용하고(KAT 용), NULL이면 내부적으로 난수를 생성한다. 서명은 |sig|(R||S,
// 각 |Q|바이트)에 기록되고 |*sig_len| 에 길이를 반환한다. 성공 시 1.
OPENSSL_EXPORT int KCDSA_sign(const KCDSA_KEY *key, const EVP_MD *md,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *k, size_t k_len, uint8_t *sig,
                              size_t *sig_len);

// KCDSA_verify 는 서명을 검증한다. 유효하면 1, 아니면 0.
OPENSSL_EXPORT int KCDSA_verify(const KCDSA_KEY *key, const EVP_MD *md,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);


#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // OPENSSL_HEADER_KCDSA_H
