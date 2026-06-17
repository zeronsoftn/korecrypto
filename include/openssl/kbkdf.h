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

// KBKDF is the key-based key derivation function of SP 800-108 (TTAK.KO-12.0272
// in Korea) and a KCMVP validation-target algorithm. The PRF input is encoded
// as in the KISA reference:
//
//   counter mode : [i]_r || Label || 0x00 || Context || [L]
//   feedback mode: K(i-1) || [i]_r || Label || 0x00 || Context || [L]
//
// where [i]_r is the loop counter as |counter_bytes| big-endian bytes, [L] is
// the output length in bits encoded as the minimum number of big-endian bytes,
// and K(0) is the supplied IV (feedback mode).

#ifndef OPENSSL_HEADER_KBKDF_H
#define OPENSSL_HEADER_KBKDF_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


// KBKDF_hmac_counter derives |out_len| bytes into |out| using SP 800-108
// counter mode with an HMAC PRF over |md|. |counter_bytes| (typically 1 or 4)
// is the width of the encoded counter. It returns one on success and zero on
// error.
OPENSSL_EXPORT int KBKDF_hmac_counter(const EVP_MD *md, const uint8_t *ki,
                                      size_t ki_len, unsigned counter_bytes,
                                      const uint8_t *label, size_t label_len,
                                      const uint8_t *context,
                                      size_t context_len, uint8_t *out,
                                      size_t out_len);

// KBKDF_hmac_feedback derives |out_len| bytes into |out| using SP 800-108
// feedback mode (with counter) and an HMAC PRF over |md|. |iv| may be NULL when
// |iv_len| is zero. It returns one on success and zero on error.
OPENSSL_EXPORT int KBKDF_hmac_feedback(const EVP_MD *md, const uint8_t *ki,
                                       size_t ki_len, unsigned counter_bytes,
                                       const uint8_t *label, size_t label_len,
                                       const uint8_t *context,
                                       size_t context_len, const uint8_t *iv,
                                       size_t iv_len, uint8_t *out,
                                       size_t out_len);

// KBKDF_hmac_double_pipeline derives |out_len| bytes into |out| using SP 800-108
// double-pipeline mode and an HMAC PRF over |md|. |counter_bytes| 0 omits the
// counter (the [NO COUNTER] variant). It returns one on success and zero on
// error.
OPENSSL_EXPORT int KBKDF_hmac_double_pipeline(
    const EVP_MD *md, const uint8_t *ki, size_t ki_len, unsigned counter_bytes,
    const uint8_t *label, size_t label_len, const uint8_t *context,
    size_t context_len, uint8_t *out, size_t out_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_KBKDF_H
