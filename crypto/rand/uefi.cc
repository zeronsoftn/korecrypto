// Copyright 2025 The BoringSSL Authors
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

// UEFI(freestanding) 환경의 시스템 엔트로피 소스. UEFI 에는 OS RNG 가 없으므로,
// 부팅 단계에서 EFI Boot Services 포인터(gBS)를 CRYPTO_uefi_init() 로 전달받아
// EFI_RNG_PROTOCOL 을 통해 난수를 얻는다.

#include <openssl/base.h>

#include "../bcm_support.h"
#include "internal.h"

#if defined(OPENSSL_RAND_UEFI)

#include <stdlib.h>  // abort (overlay)

#include <openssl/crypto.h>

namespace {

// 최소한의 UEFI 타입/구조체 정의(EFI ABI 는 안정적이다). x86_64-unknown-uefi 의
// 기본 호출규약이 MS x64 이지만, EFI 함수 포인터에는 명시적으로 ms_abi 를 붙인다.
#define EFIAPI __attribute__((ms_abi))
typedef uint64_t UINTN;
typedef UINTN EFI_STATUS;
constexpr EFI_STATUS kEfiSuccess = 0;

struct EFI_GUID {
  uint32_t Data1;
  uint16_t Data2;
  uint16_t Data3;
  uint8_t Data4[8];
};

struct EFI_RNG_PROTOCOL {
  EFI_STATUS(EFIAPI *GetInfo)
  (EFI_RNG_PROTOCOL *self, UINTN *list_size, EFI_GUID *list);
  EFI_STATUS(EFIAPI *GetRNG)
  (EFI_RNG_PROTOCOL *self, EFI_GUID *algorithm, UINTN length, uint8_t *out);
};

struct EFI_TABLE_HEADER {
  uint64_t Signature;
  uint32_t Revision;
  uint32_t HeaderSize;
  uint32_t CRC32;
  uint32_t Reserved;
};

// EFI_BOOT_SERVICES 는 함수 포인터 테이블이다. 우리는 LocateProtocol 만 쓰므로,
// 그 앞의 37개 포인터(RaiseTPL .. LocateHandleBuffer)는 자리만 맞춘다. LocateProtocol
// 의 오프셋은 UEFI 명세상 0x140(=24 + 37*8)로 고정이다.
struct EFI_BOOT_SERVICES {
  EFI_TABLE_HEADER Hdr;
  void *reserved_fns[37];
  EFI_STATUS(EFIAPI *LocateProtocol)
  (EFI_GUID *protocol, void *registration, void **interface);
};

// EFI_RNG_PROTOCOL_GUID = {3152bca5-eade-433d-862e-c01cdc291f44}
EFI_GUID kRngProtocolGuid = {
    0x3152bca5, 0xeade, 0x433d, {0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44}};

EFI_BOOT_SERVICES *g_boot_services = nullptr;

}  // namespace

// CRYPTO_uefi_init 는 EFI 앱이 부팅 단계에서 호출해 Boot Services 테이블(gBS)을
// 전달한다. 이후 CRYPTO_sysrand 가 이 포인터로 EFI_RNG_PROTOCOL 을 찾아 쓴다.
extern "C" void CRYPTO_uefi_init(void *boot_services) {
  g_boot_services = reinterpret_cast<EFI_BOOT_SERVICES *>(boot_services);
}

void bssl::CRYPTO_init_sysrand() {}

void bssl::CRYPTO_sysrand(uint8_t *out, size_t requested) {
  if (g_boot_services == nullptr) {
    // CRYPTO_uefi_init 이 호출되지 않았다. 엔트로피를 얻을 수 없으면 치명적이다.
    abort();
  }

  EFI_RNG_PROTOCOL *rng = nullptr;
  if (g_boot_services->LocateProtocol(&kRngProtocolGuid, nullptr,
                                      reinterpret_cast<void **>(&rng)) !=
          kEfiSuccess ||
      rng == nullptr) {
    abort();
  }

  while (requested > 0) {
    UINTN todo = requested;
    // algorithm=nullptr 이면 펌웨어의 기본(가장 강한) 알고리즘을 사용한다.
    if (rng->GetRNG(rng, nullptr, todo, out) != kEfiSuccess) {
      abort();
    }
    out += todo;
    requested -= todo;
  }
}

#endif  // OPENSSL_RAND_UEFI
