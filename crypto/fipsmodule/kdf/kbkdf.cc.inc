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

// KBKDF (SP 800-108 / TTAK.KO-12.0272), HMAC-based counter and feedback modes.
// The PRF-input encoding matches the KISA reference implementation. Verified
// against the KISA KBKDF-HMAC-SHA256 vectors.

#include <openssl/kbkdf.h>

#include <openssl/digest.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>

#include <string.h>

#include "../../internal.h"


namespace {

// addLparam appends |l| (the output length in bits) to |out| using the minimum
// number of big-endian bytes, exactly as the KISA reference does. It returns
// the number of bytes written (1..4).
size_t kbkdf_add_l_param(uint8_t out[4], uint32_t l) {
  if (l < 0x100) {
    out[0] = (uint8_t)l;
    return 1;
  }
  if (l < 0x10000) {
    out[0] = (uint8_t)(l >> 8);
    out[1] = (uint8_t)l;
    return 2;
  }
  if (l < 0x1000000) {
    out[0] = (uint8_t)(l >> 16);
    out[1] = (uint8_t)(l >> 8);
    out[2] = (uint8_t)l;
    return 3;
  }
  out[0] = (uint8_t)(l >> 24);
  out[1] = (uint8_t)(l >> 16);
  out[2] = (uint8_t)(l >> 8);
  out[3] = (uint8_t)l;
  return 4;
}

// kbkdf_put_counter writes |ctr| as |n| big-endian bytes.
void kbkdf_put_counter(uint8_t *out, uint32_t ctr, unsigned n) {
  for (unsigned i = 0; i < n; i++) {
    out[i] = (uint8_t)(ctr >> ((n - 1 - i) * 8));
  }
}

int kbkdf_hmac(const EVP_MD *md, const uint8_t *ki, size_t ki_len,
               unsigned counter_bytes, const uint8_t *label, size_t label_len,
               const uint8_t *context, size_t context_len, const uint8_t *iv,
               size_t iv_len, int feedback, uint8_t *out, size_t out_len) {
  if (out_len == 0) {
    return 1;
  }
  if (counter_bytes < 1 || counter_bytes > 4) {
    return 0;
  }

  const size_t h = EVP_MD_size(md);
  if (h == 0) {
    return 0;
  }
  // L is the output length in bits; reject lengths that don't fit the encoding.
  if (out_len > (SIZE_MAX / 8)) {
    return 0;
  }
  const uint32_t l_bits = (uint32_t)(out_len * 8);

  // Build the fixed suffix: Label || 0x00 || Context || [L].
  uint8_t l_param[4];
  size_t l_len = kbkdf_add_l_param(l_param, l_bits);
  size_t fixed_len = label_len + 1 + context_len + l_len;

  // The feedback prefix K(i-1) has length |iv_len| for the first block and |h|
  // thereafter (matching the KISA reference, which omits the prefix entirely
  // when the IV is empty). Size the input buffer for the larger of the two.
  size_t max_prefix = 0;
  if (feedback) {
    max_prefix = iv_len > h ? iv_len : h;
  }
  size_t input_cap = max_prefix + counter_bytes + fixed_len;
  uint8_t *input = reinterpret_cast<uint8_t *>(OPENSSL_malloc(input_cap));
  if (input == nullptr) {
    return 0;
  }

  int ret = 0;
  uint8_t prev[EVP_MAX_MD_SIZE];
  size_t prev_len = iv_len;  // K(0) = IV.
  if (feedback && iv_len > 0) {
    OPENSSL_memcpy(prev, iv, iv_len);
  }

  uint8_t block[EVP_MAX_MD_SIZE];
  size_t done = 0;
  uint32_t ctr = 0;
  while (done < out_len) {
    ctr++;

    // Lay out [prefix] || [i]_r || Label || 0x00 || Context || [L].
    uint8_t *p = input;
    if (feedback && prev_len > 0) {
      OPENSSL_memcpy(p, prev, prev_len);
      p += prev_len;
    }
    kbkdf_put_counter(p, ctr, counter_bytes);
    p += counter_bytes;
    if (label_len != 0) {
      OPENSSL_memcpy(p, label, label_len);
    }
    p[label_len] = 0x00;
    if (context_len != 0) {
      OPENSSL_memcpy(p + label_len + 1, context, context_len);
    }
    OPENSSL_memcpy(p + label_len + 1 + context_len, l_param, l_len);
    p += fixed_len;
    size_t input_len = (size_t)(p - input);

    unsigned mac_len = 0;
    if (HMAC(md, ki, ki_len, input, input_len, block, &mac_len) == nullptr ||
        mac_len != h) {
      goto err;
    }
    if (feedback) {
      OPENSSL_memcpy(prev, block, h);
      prev_len = h;
    }

    size_t take = out_len - done < h ? out_len - done : h;
    OPENSSL_memcpy(out + done, block, take);
    done += take;
  }
  ret = 1;

err:
  OPENSSL_cleanse(block, sizeof(block));
  OPENSSL_cleanse(prev, sizeof(prev));
  OPENSSL_cleanse(input, input_cap);
  OPENSSL_free(input);
  if (!ret) {
    OPENSSL_cleanse(out, out_len);
  }
  return ret;
}

}  // namespace

extern "C" {

int KBKDF_hmac_counter(const EVP_MD *md, const uint8_t *ki, size_t ki_len,
                       unsigned counter_bytes, const uint8_t *label,
                       size_t label_len, const uint8_t *context,
                       size_t context_len, uint8_t *out, size_t out_len) {
  return kbkdf_hmac(md, ki, ki_len, counter_bytes, label, label_len, context,
                    context_len, nullptr, 0, /*feedback=*/0, out, out_len);
}

int KBKDF_hmac_feedback(const EVP_MD *md, const uint8_t *ki, size_t ki_len,
                        unsigned counter_bytes, const uint8_t *label,
                        size_t label_len, const uint8_t *context,
                        size_t context_len, const uint8_t *iv, size_t iv_len,
                        uint8_t *out, size_t out_len) {
  return kbkdf_hmac(md, ki, ki_len, counter_bytes, label, label_len, context,
                    context_len, iv, iv_len, /*feedback=*/1, out, out_len);
}

}  // extern "C"
