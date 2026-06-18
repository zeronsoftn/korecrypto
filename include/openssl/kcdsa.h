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

// KCDSA_KEY_generate 는 도메인 파라미터가 설정된 상태에서 개인키 x 를 [1, Q-1]
// 에서 무작위 생성하고 공개키를 계산한 뒤, 키쌍 일치시험(PCT)을 수행한다(KCMVP
// 조건부 자가시험). PCT 실패 시 키를 폐기하고 0 을 반환한다. 성공 시 1.
OPENSSL_EXPORT int KCDSA_KEY_generate(KCDSA_KEY *key);

// KCDSA_KEY_get_public 는 공개키 y 를 빅엔디안으로 |out|(|max_out| 바이트)에
// 기록하고 |*out_len| 에 길이를 반환한다.
OPENSSL_EXPORT int KCDSA_KEY_get_public(const KCDSA_KEY *key, uint8_t *out,
                                        size_t max_out, size_t *out_len);

// KCDSA_sig_len 은 서명 길이(2*|Q|바이트)를 반환한다. 파라미터 미설정 시 0.
OPENSSL_EXPORT size_t KCDSA_sig_len(const KCDSA_KEY *key);

// KCDSA_KEY_get_params 는 도메인 파라미터 P, Q, G 를 빅엔디안으로 각 버퍼에
// 기록하고 길이를 반환한다. 성공 시 1.
OPENSSL_EXPORT int KCDSA_KEY_get_params(const KCDSA_KEY *key, uint8_t *p,
                                        size_t p_max, size_t *p_len, uint8_t *q,
                                        size_t q_max, size_t *q_len, uint8_t *g,
                                        size_t g_max, size_t *g_len);

// KCDSA_KEY_get_private 는 개인키 x 를 빅엔디안으로 기록하고 길이를 반환한다.
OPENSSL_EXPORT int KCDSA_KEY_get_private(const KCDSA_KEY *key, uint8_t *out,
                                         size_t max_out, size_t *out_len);

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

// KCDSA_generate_parameters 는 비트 길이 |P|=p_bits, |Q|=q_bits 의 도메인
// 파라미터 (P, Q, G) 를 TTAK.KO-12.0001 절차로 생성하여 |key| 에 설정한다.
// 생성 증거값도 함께 반환한다(시험벡터 .rsp 출력용):
//   - seed_out/seed_len: 증거 Seed (q_bits/8 바이트)
//   - count_out: 소수 P,Q 를 찾은 Count 값
//   - j_out/j_len: 보조 소수 J (P = 2·J·Q + 1)
//   - h_out/h_len: 생성원 밑 h (G = h^{2J} mod P)
// 각 out 버퍼는 충분히 커야 한다(seed: q_bits/8, j: p_bits/8, h: p_bits/8).
// p_bits 는 2048..3072(256 배수), q_bits 는 224/256 만 허용. 성공 시 1.
OPENSSL_EXPORT int KCDSA_generate_parameters(
    KCDSA_KEY *key, int p_bits, int q_bits, uint8_t *seed_out, size_t *seed_len,
    uint32_t *count_out, uint8_t *j_out, size_t *j_len, uint8_t *h_out,
    size_t *h_len);


#if defined(__cplusplus)
}  // extern "C"
#endif

#endif  // OPENSSL_HEADER_KCDSA_H
