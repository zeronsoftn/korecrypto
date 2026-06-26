// Copyright 2023 The BoringSSL Authors
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

#include <openssl/cpu.h>

#include "internal.h"

// While Arm system registers are normally not available to userspace, FreeBSD
// expects userspace to simply read them. It traps the reads and fills in CPU
// capabilities.
//
// KORECRYPTO_BAREMETAL(UEFI 포함): freestanding 환경에는 getauxval 등 OS 의
// CPU 특성 질의 수단이 없고, 통합자가 EL1/EL2(특권 레벨)에서 구동하므로 ID_AA64*
// 시스템 레지스터를 MRS 로 직접 읽을 수 있다. 그래서 이 sysreg 경로를 사용한다.
// (다른 cpu_aarch64_*.cc 는 모두 특정 OS 플랫폼 매크로를 요구해 baremetal 에서는
//  OPENSSL_cpuid_setup 이 정의되지 않으므로, 여기서 정의를 제공해야 한다.)
#if defined(OPENSSL_AARCH64) && !defined(OPENSSL_STATIC_ARMCAP) &&  \
    (defined(ANDROID_BAREMETAL) || defined(OPENSSL_FREEBSD) ||      \
     defined(KORECRYPTO_BAREMETAL)) &&                              \
    !defined(OPENSSL_NO_ASM)

#include "./armv8_feature_parsing.h"

BSSL_NAMESPACE_BEGIN

#define ID_AA64PFR0_EL1_ADVSIMD 5

#define READ_SYSREG(name)                \
  ({                                     \
    uint64_t _r;                         \
    __asm__("mrs %0, " name : "=r"(_r)); \
    _r;                                  \
  })

// We use the common GetIDField helper now, but need a signed variant
// for the NEON check using ID_AA64PFR0_EL1.
static int GetSignedIDField(uint64_t reg, unsigned field) {
  unsigned value = armcap::GetIDField(reg, field);
  if (value & (1 << (NBITS_ID_FIELD - 1))) {
    return (int)(value | (UINT64_MAX << NBITS_ID_FIELD));
  } else {
    return (int)value;
  }
}

void OPENSSL_cpuid_setup() {
  uint64_t id_aa64pfr0_el1 = READ_SYSREG("id_aa64pfr0_el1");
  if (GetSignedIDField(id_aa64pfr0_el1, ID_AA64PFR0_EL1_ADVSIMD) < 0) {
    // If AdvSIMD ("NEON") is missing, don't report other features either.
    // This matches OpenSSL.
    return;
  }

  // Use the common parsing function to check all cryptographic features.
  uint64_t id_aa64isar0_el1 = READ_SYSREG("id_aa64isar0_el1");
  OPENSSL_armcap_P |= ARMV7_NEON | armcap::ParseISAR0Flags(id_aa64isar0_el1);
}

BSSL_NAMESPACE_END

#endif  // OPENSSL_AARCH64 && !OPENSSL_STATIC_ARMCAP &&
        // (ANDROID_BAREMETAL || OPENSSL_FREEBSD || KORECRYPTO_BAREMETAL)
