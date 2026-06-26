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

// LSH hash function (KS X 3262). Templated scalar core covering both LSH-256
// (32-bit) and LSH-512 (64-bit), with fully precomputed step constants. Ported
// from the KISA reference; verified against KISA reference digests.

#include <openssl/lsh.h>

#include <openssl/digest.h>
#include <openssl/nid.h>

#include <string.h>

#include "../../internal.h"
#include "../delocate.h"
#include "../digest/internal.h"


namespace {

const uint32_t kLsh256Step[208] = {
    0x917caf90u, 0x6c1b10a2u, 0x6f352943u, 0xcf778243u, 0x2ceb7472u, 0x29e96ff2u, 0x8a9ba428u, 0x2eeb2642u,
    0x0e2c4021u, 0x872bb30eu, 0xa45e6cb2u, 0x46f9c612u, 0x185fe69eu, 0x1359621bu, 0x263fccb2u, 0x1a116870u,
    0x3a6c612fu, 0xb2dec195u, 0x02cb1f56u, 0x40bfd858u, 0x784684b6u, 0x6cbb7d2eu, 0x660c7ed8u, 0x2b79d88au,
    0xa6cd9069u, 0x91a05747u, 0xcdea7558u, 0x00983098u, 0xbecb3b2eu, 0x2838ab9au, 0x728b573eu, 0xa55262b5u,
    0x745dfa0fu, 0x31f79ed8u, 0xb85fce25u, 0x98c8c898u, 0x8a0669ecu, 0x60e445c2u, 0xfde295b0u, 0xf7b5185au,
    0xd2580983u, 0x29967709u, 0x182df3ddu, 0x61916130u, 0x90705676u, 0x452a0822u, 0xe07846adu, 0xaccd7351u,
    0x2a618d55u, 0xc00d8032u, 0x4621d0f5u, 0xf2f29191u, 0x00c6cd06u, 0x6f322a67u, 0x58bef48du, 0x7a40c4fdu,
    0x8beee27fu, 0xcd8db2f2u, 0x67f2c63bu, 0xe5842383u, 0xc793d306u, 0xa15c91d6u, 0x17b381e5u, 0xbb05c277u,
    0x7ad1620au, 0x5b40a5bfu, 0x5ab901a2u, 0x69a7a768u, 0x5b66d9cdu, 0xfdee6877u, 0xcb3566fcu, 0xc0c83a32u,
    0x4c336c84u, 0x9be6651au, 0x13baa3fcu, 0x114f0fd1u, 0xc240a728u, 0xec56e074u, 0x009c63c7u, 0x89026cf2u,
    0x7f9ff0d0u, 0x824b7fb5u, 0xce5ea00fu, 0x605ee0e2u, 0x02e7cfeau, 0x43375560u, 0x9d002ac7u, 0x8b6f5f7bu,
    0x1f90c14fu, 0xcdcb3537u, 0x2cfeafddu, 0xbf3fc342u, 0xeab7b9ecu, 0x7a8cb5a3u, 0x9d2af264u, 0xfacedb06u,
    0xb052106eu, 0x99006d04u, 0x2bae8d09u, 0xff030601u, 0xa271a6d6u, 0x0742591du, 0xc81d5701u, 0xc9a9e200u,
    0x02627f1eu, 0x996d719du, 0xda3b9634u, 0x02090800u, 0x14187d78u, 0x499b7624u, 0xe57458c9u, 0x738be2c9u,
    0x64e19d20u, 0x06df0f36u, 0x15d1cb0eu, 0x0b110802u, 0x2c95f58cu, 0xe5119a6du, 0x59cd22aeu, 0xff6eac3cu,
    0x467ebd84u, 0xe5ee453cu, 0xe79cd923u, 0x1c190a0du, 0xc28b81b8u, 0xf6ac0852u, 0x26efd107u, 0x6e1ae93bu,
    0xc53c41cau, 0xd4338221u, 0x8475fd0au, 0x35231729u, 0x4e0d3a7au, 0xa2b45b48u, 0x16c0d82du, 0x890424a9u,
    0x017e0c8fu, 0x07b5a3f5u, 0xfa73078eu, 0x583a405eu, 0x5b47b4c8u, 0x570fa3eau, 0xd7990543u, 0x8d28ce32u,
    0x7f8a9b90u, 0xbd5998fcu, 0x6d7a9688u, 0x927a9eb6u, 0xa2fc7d23u, 0x66b38e41u, 0x709e491au, 0xb5f700bfu,
    0x0a262c0fu, 0x16f295b9u, 0xe8111ef5u, 0x0d195548u, 0x9f79a0c5u, 0x1a41cfa7u, 0x0ee7638au, 0xacf7c074u,
    0x30523b19u, 0x09884ecfu, 0xf93014ddu, 0x266e9d55u, 0x191a6664u, 0x5c1176c1u, 0xf64aed98u, 0xa4b83520u,
    0x828d5449u, 0x91d71dd8u, 0x2944f2d6u, 0x950bf27bu, 0x3380ca7du, 0x6d88381du, 0x4138868eu, 0x5ced55c4u,
    0x0fe19dcbu, 0x68f4f669u, 0x6e37c8ffu, 0xa0fe6e10u, 0xb44b47b0u, 0xf5c0558au, 0x79bf14cfu, 0x4a431a20u,
    0xf17f68dau, 0x5deb5fd1u, 0xa600c86du, 0x9f6c7eb0u, 0xff92f864u, 0xb615e07fu, 0x38d3e448u, 0x8d5d3a6au,
    0x70e843cbu, 0x494b312eu, 0xa6c93613u, 0x0beb2f4fu, 0x928b5d63u, 0xcbf66035u, 0x0cb82c80u, 0xea97a4f7u,
    0x592c0f3bu, 0x947c5f77u, 0x6fff49b9u, 0xf71a7e5au, 0x1de8c0f5u, 0xc2569600u, 0xc4e4ac8cu, 0x823c9ce1u,
};

const uint32_t kLsh256IV224[16] = {
    0x068608d3u, 0x62d8f7a7u, 0xd76652abu, 0x4c600a43u, 0xbdc40aa8u, 0x1eca0b68u, 0xda1a89beu, 0x3147d354u,
    0x707eb4f9u, 0xf65b3862u, 0x6b0b2abeu, 0x56b8ec0au, 0xcf237286u, 0xee0d1727u, 0x33636595u, 0x8bb8d05fu,
};

const uint32_t kLsh256IV256[16] = {
    0x46a10f1fu, 0xfddce486u, 0xb41443a8u, 0x198e6b9du, 0x3304388du, 0xb0f5a3c7u, 0xb36061c4u, 0x7adbd553u,
    0x105d5378u, 0x2f74de54u, 0x5c2f2d95u, 0xf2553fbeu, 0x8051357au, 0x138668c8u, 0x47aa4484u, 0xe01afb41u,
};

const uint64_t kLsh512Step[224] = {
    0x97884283c938982aull, 0xba1fca93533e2355ull, 0xc519a2e87aeb1c03ull, 0x9a0fc95462af17b1ull,
    0xfc3dda8ab019a82bull, 0x02825d079a895407ull, 0x79f2d0a7ee06a6f7ull, 0xd76d15eed9fdf5feull,
    0x1fcac64d01d0c2c1ull, 0xd9ea5de69161790full, 0xdebc8b6366071fc8ull, 0xa9d91db711c6c94bull,
    0x3a18653ac9c1d427ull, 0x84df64a223dd5b09ull, 0x6cc37895f4ad9e70ull, 0x448304c8d7f3f4d5ull,
    0xea91134ed29383e0ull, 0xc4484477f2da88e8ull, 0x9b47eec96d26e8a6ull, 0x82f6d4c8d89014f4ull,
    0x527da0048b95fb61ull, 0x644406c60138648dull, 0x303c0e8aa24c0edcull, 0xc787cda0cbe8ca19ull,
    0x7ba46221661764caull, 0x0c8cbc6acd6371acull, 0xe336b836940f8f41ull, 0x79cb9da168a50976ull,
    0xd01da49021915cb3ull, 0xa84accc7399cf1f1ull, 0x6c4a992cee5aeb0cull, 0x4f556e6cb4b2e3e0ull,
    0x200683877d7c2f45ull, 0x9949273830d51db8ull, 0x19eeeecaa39ed124ull, 0x45693f0a0dae7fefull,
    0xedc234b1b2ee1083ull, 0xf3179400d68ee399ull, 0xb6e3c61b4945f778ull, 0xa4c3db216796c42full,
    0x268a0b04f9ab7465ull, 0xe2705f6905f2d651ull, 0x08ddb96e426ff53dull, 0xaea84917bc2e6f34ull,
    0xaff6e664a0fe9470ull, 0x0aab94d765727d8cull, 0x9aa9e1648f3d702eull, 0x689efc88fe5af3d3ull,
    0xb0950ffea51fd98bull, 0x52cfc86ef8c92833ull, 0xe69727b0b2653245ull, 0x56f160d3ea9da3e2ull,
    0xa6dd4b059f93051full, 0xb6406c3cd7f00996ull, 0x448b45f3ccad9ec8ull, 0x079b8587594ec73bull,
    0x45a50ea3c4f9653bull, 0x22983767c1f15b85ull, 0x7dbed8631797782bull, 0x485234be88418638ull,
    0x842850a5329824c5ull, 0xf6aca914c7f9a04cull, 0xcfd139c07a4c670cull, 0xa3210ce0a8160242ull,
    0xeab3b268be5ea080ull, 0xbacf9f29b34ce0a7ull, 0x3c973b7aaf0fa3a8ull, 0x9a86f346c9c7be80ull,
    0xac78f5d7cabcea49ull, 0xa355bddcc199ed42ull, 0xa10afa3ac6b373dbull, 0xc42ded88be1844e5ull,
    0x9e661b271cff216aull, 0x8a6ec8dd002d8861ull, 0xd3d2b629beb34be4ull, 0x217a3a1091863f1aull,
    0x256ecda287a733f5ull, 0xf9139a9e5b872fe5ull, 0xac0535017a274f7cull, 0xf21b7646d65d2aa9ull,
    0x048142441c208c08ull, 0xf937a5dd2db5e9ebull, 0xa688dfe871ff30b7ull, 0x9bb44aa217c5593bull,
    0x943c702a2edb291aull, 0x0cae38f9e2b715deull, 0xb13a367ba176cc28ull, 0x0d91bd1d3387d49bull,
    0x85c386603cac940cull, 0x30dd830ae39fd5e4ull, 0x2f68c85a712fe85dull, 0x4ffeecb9dd1e94d6ull,
    0xd0ac9a590a0443aeull, 0xbae732dc99ccf3eaull, 0xeb70b21d1842f4d9ull, 0x9f4eda50bb5c6fa8ull,
    0x4949e69ce940a091ull, 0x0e608dee8375ba14ull, 0x983122cba118458cull, 0x4eeba696fbb36b25ull,
    0x7d46f3630e47f27eull, 0xa21a0f7666c0dea4ull, 0x5c22cf355b37cec4ull, 0xee292b0c17cc1847ull,
    0x9330838629e131daull, 0x6eee7c71f92fce22ull, 0xc953ee6cb95dd224ull, 0x3a923d92af1e9073ull,
    0xc43a5671563a70fbull, 0xbc2985dd279f8346ull, 0x7ef2049093069320ull, 0x17543723e3e46035ull,
    0xc3b409b00b130c6dull, 0x5d6aee6b28fdf090ull, 0x1d425b26172ff6edull, 0xcccfd041cdaf03adull,
    0xfe90c7c790ab6cbfull, 0xe5af6304c722ca02ull, 0x70f695239999b39eull, 0x6b8b5b07c844954cull,
    0x77bdb9bb1e1f7a30ull, 0xc859599426ee80edull, 0x5f9d813d4726e40aull, 0x9ca0120f7cb2b179ull,
    0x8f588f583c182cbdull, 0x951267cbe9eccce7ull, 0x678bb8bd334d520eull, 0xf6e662d00cd9e1b7ull,
    0x357774d93d99aaa7ull, 0x21b2edbb156f6eb5ull, 0xfd1ebe846e0aee69ull, 0x3cb2218c2f642b15ull,
    0xe7e7e7945444ea4cull, 0xa77a33b5d6b9b47cull, 0xf34475f0809f6075ull, 0xdd4932dce6bb99adull,
    0xacec4e16d74451dcull, 0xd4a0a8d084de23d6ull, 0x1bdd42f278f95866ull, 0xeed3adbb938f4051ull,
    0xcfcf7be8992f3733ull, 0x21ade98c906e3123ull, 0x37ba66711fffd668ull, 0x267c0fc3a255478aull,
    0x993a64ee1b962e88ull, 0x754979556301faaaull, 0xf920356b7251be81ull, 0xc281694f22cf923full,
    0x9f4b6481c8666b02ull, 0xcf97761cfe9f5444ull, 0xf220d7911fd63e9full, 0xa28bd365f79cd1b0ull,
    0xd39f5309b1c4b721ull, 0xbec2ceb864fca51full, 0x1955a0ddc410407aull, 0x43eab871f261d201ull,
    0xeaafe64a2ed16da1ull, 0x670d931b9df39913ull, 0x12f868b0f614de91ull, 0x2e5f395d946e8252ull,
    0x72f25cbb767bd8f4ull, 0x8191871d61a1c4ddull, 0x6ef67ea1d450ba93ull, 0x2ea32a645433d344ull,
    0x9a963079003f0f8bull, 0x74a0aeb9918cac7aull, 0x0b6119a70af36fa3ull, 0x8d9896f202f0d480ull,
    0x654f1831f254cd66ull, 0x1318a47f0366a25eull, 0x65752076250b4e01ull, 0xd1cd8eb888071772ull,
    0x30c6a9793f4e9b25ull, 0x154f684b1e3926eeull, 0x6c7ac0b1fe6312aeull, 0x262f88f4f3c5550dull,
    0xb4674a24472233cbull, 0x2bbd23826a090071ull, 0xda95969b30594f66ull, 0x9f5c47408f1e8a43ull,
    0xf77022b88de9c055ull, 0x64b7b36957601503ull, 0xe73b72b06175c11aull, 0x55b87de8b91a6233ull,
    0x1bb16e6b6955ff7full, 0xe8e0a5ec7309719cull, 0x702c31cb89a8b640ull, 0xfba387cfada8cde2ull,
    0x6792db4677aa164cull, 0x1c6b1cc0b7751867ull, 0x22ae2311d736dc01ull, 0x0e3666a1d37c9588ull,
    0xcd1fd9d4bf557e9aull, 0xc986925f7c7b0e84ull, 0x9c5dfd55325ef6b0ull, 0x9f2b577d5676b0ddull,
    0xfa6e21be21c062b3ull, 0x8787dd782c8d7f83ull, 0xd0d134e90e12dd23ull, 0x449d087550121d96ull,
    0xecf9ae9414d41967ull, 0x5018f1dbf789934dull, 0xfa5b52879155a74cull, 0xca82d4d3cd278e7cull,
    0x688fdfdfe22316adull, 0x0f6555a4ba0d030aull, 0xa2061df720f000f3ull, 0xe1a57dc5622fb3daull,
    0xe6a842a8e8ed8153ull, 0x690acdd3811ce09dull, 0x55adda18e6fcf446ull, 0x4d57a8a0f4b60b46ull,
    0xf86fbfc20539c415ull, 0x74bafa5ec7100d19ull, 0xa824151810f0f495ull, 0x8723432791e38ebbull,
    0x8eeaeb91d66ed539ull, 0x73d8a1549dfd7e06ull, 0x0387f2ffe3f13a9bull, 0xa5004995aac15193ull,
    0x682f81c73efdda0dull, 0x2fb55925d71d268dull, 0xcc392d2901e58a3dull, 0xaa666ab975724a42ull,
};

const uint64_t kLsh512IV224[16] = {
    0x0c401e9fe8813a55ull, 0x4a5f446268fd3d35ull, 0xff13e452334f612aull, 0xf8227661037e354aull,
    0xa5f223723c9ca29dull, 0x95d965a11aed3979ull, 0x01e23835b9ab02ccull, 0x52d49cbad5b30616ull,
    0x9e5c2027773f4ed3ull, 0x66a5c8801925b701ull, 0x22bbc85b4c6779d9ull, 0xc13171a42c559c23ull,
    0x31e2b67d25be3813ull, 0xd522c4deed8e4d83ull, 0xa79f5509b43fbafeull, 0xe00d2cd88b4b6c6aull,
};

const uint64_t kLsh512IV256[16] = {
    0x6dc57c33df989423ull, 0xd8ea7f6e8342c199ull, 0x76df8356f8603ac4ull, 0x40f1b44de838223aull,
    0x39ffe7cfc31484cdull, 0x39c4326cc5281548ull, 0x8a2ff85a346045d8ull, 0xff202aa46dbdd61eull,
    0xcf785b3cd5fcdb8bull, 0x1f0323b64a8150bfull, 0xff75d972f29ea355ull, 0x2e567f30bf1ca9e1ull,
    0xb596875bf8ff6dbaull, 0xfcca39b089ef4615ull, 0xecff4017d020b4b6ull, 0x7e77384c772ed802ull,
};

const uint64_t kLsh512IV384[16] = {
    0x53156a66292808f6ull, 0xb2c4f362b204c2bcull, 0xb84b7213bfa05c4eull, 0x976ceb7c1b299f73ull,
    0xdf0cc63c0570ae97ull, 0xda4441baa486ce3full, 0x6559f5d9b5f2acc2ull, 0x22dacf19b4b52a16ull,
    0xbbcdacefde80953aull, 0xc9891a2879725b3eull, 0x7c9fe6330237e440ull, 0xa30ba550553f7431ull,
    0xbb08043fb34e3e30ull, 0xa0dec48d54618eadull, 0x150317267464bc57ull, 0x32d1501fde63dc93ull,
};

const uint64_t kLsh512IV512[16] = {
    0xadd50f3c7f07094eull, 0xe3f3cee8f9418a4full, 0xb527ecde5b3d0ae9ull, 0x2ef6dec68076f501ull,
    0x8cb994cae5aca216ull, 0xfbb9eae4bba48cc7ull, 0x650a526174725feaull, 0x1f9a61a73f8d8085ull,
    0xb6607378173b539bull, 0x1bc99853b0c0b9edull, 0xdf727fc19b182d47ull, 0xdbef360cf893a457ull,
    0x4981f5e570147e80ull, 0xd00c4490ca7d3e30ull, 0x5d73940c0e4ae1ecull, 0x894085e2edb2d819ull,
};
const unsigned kLsh256Gamma[8] = {0, 8, 16, 24, 24, 16, 8, 0};
const unsigned kLsh512Gamma[8] = {0, 16, 32, 48, 8, 24, 40, 56};

inline uint32_t lshRotl(uint32_t x, unsigned r) {
  return (x << r) | (x >> (32 - r));
}
inline uint64_t lshRotl(uint64_t x, unsigned r) {
  return (x << r) | (x >> (64 - r));
}

template <typename W>
struct LshTraits;

template <>
struct LshTraits<uint32_t> {
  static constexpr int kNumStep = 26;
  static constexpr int kBlock = 128;  // bytes
  static constexpr unsigned kAlphaEven = 29, kAlphaOdd = 5;
  static constexpr unsigned kBetaEven = 1, kBetaOdd = 17;
  static const unsigned *gamma() { return kLsh256Gamma; }
  static const uint32_t *step() { return kLsh256Step; }
  static uint32_t load(const uint8_t *p) { return CRYPTO_load_u32_le(p); }
  static void store(uint8_t *p, uint32_t v) { CRYPTO_store_u32_le(p, v); }
};

template <>
struct LshTraits<uint64_t> {
  static constexpr int kNumStep = 28;
  static constexpr int kBlock = 256;  // bytes
  static constexpr unsigned kAlphaEven = 23, kAlphaOdd = 7;
  static constexpr unsigned kBetaEven = 59, kBetaOdd = 3;
  static const unsigned *gamma() { return kLsh512Gamma; }
  static const uint64_t *step() { return kLsh512Step; }
  static uint64_t load(const uint8_t *p) { return CRYPTO_load_u64_le(p); }
  static void store(uint8_t *p, uint64_t v) { CRYPTO_store_u64_le(p, v); }
};

// compress processes one |kBlock|-byte message block into the 16-word chaining
// value |cv|.
template <typename W>
void lshCompress(W cv[16], const uint8_t *block) {
  using T = LshTraits<W>;
  const int NS = T::kNumStep;
  W msg[16 * (T::kNumStep + 1)];

  for (int i = 0; i < 32; i++) {
    msg[i] = T::load(block + i * sizeof(W));
  }
  for (int i = 2; i <= NS; i++) {
    int idx = 16 * i;
    msg[idx + 0] = msg[idx - 16] + msg[idx - 29];
    msg[idx + 1] = msg[idx - 15] + msg[idx - 30];
    msg[idx + 2] = msg[idx - 14] + msg[idx - 32];
    msg[idx + 3] = msg[idx - 13] + msg[idx - 31];
    msg[idx + 4] = msg[idx - 12] + msg[idx - 25];
    msg[idx + 5] = msg[idx - 11] + msg[idx - 28];
    msg[idx + 6] = msg[idx - 10] + msg[idx - 27];
    msg[idx + 7] = msg[idx - 9] + msg[idx - 26];
    msg[idx + 8] = msg[idx - 8] + msg[idx - 21];
    msg[idx + 9] = msg[idx - 7] + msg[idx - 22];
    msg[idx + 10] = msg[idx - 6] + msg[idx - 24];
    msg[idx + 11] = msg[idx - 5] + msg[idx - 23];
    msg[idx + 12] = msg[idx - 4] + msg[idx - 17];
    msg[idx + 13] = msg[idx - 3] + msg[idx - 20];
    msg[idx + 14] = msg[idx - 2] + msg[idx - 19];
    msg[idx + 15] = msg[idx - 1] + msg[idx - 18];
  }

  const W *STEP = T::step();
  const unsigned *G = T::gamma();
  W tcv[16];
  for (int s = 0; s < NS; s++) {
    unsigned alpha = (s & 1) ? T::kAlphaOdd : T::kAlphaEven;
    unsigned beta = (s & 1) ? T::kBetaOdd : T::kBetaEven;
    for (int c = 0; c < 8; c++) {
      W vl = cv[c] ^ msg[16 * s + c];
      W vr = cv[c + 8] ^ msg[16 * s + c + 8];
      vl = lshRotl((W)(vl + vr), alpha) ^ STEP[8 * s + c];
      vr = lshRotl((W)(vl + vr), beta);
      tcv[c] = vl + vr;
      tcv[c + 8] = lshRotl(vr, G[c]);
    }
    // Word permutation.
    cv[0] = tcv[6];
    cv[1] = tcv[4];
    cv[2] = tcv[5];
    cv[3] = tcv[7];
    cv[4] = tcv[12];
    cv[5] = tcv[15];
    cv[6] = tcv[14];
    cv[7] = tcv[13];
    cv[8] = tcv[2];
    cv[9] = tcv[0];
    cv[10] = tcv[1];
    cv[11] = tcv[3];
    cv[12] = tcv[8];
    cv[13] = tcv[11];
    cv[14] = tcv[10];
    cv[15] = tcv[9];
  }

  for (int i = 0; i < 16; i++) {
    cv[i] ^= msg[16 * NS + i];
  }
}

template <typename W, typename CTX>
void lshUpdate(CTX *c, const uint8_t *data, size_t len) {
  const size_t kBlock = LshTraits<W>::kBlock;
  size_t boff = c->boff;

  if (boff > 0) {
    size_t gap = kBlock - boff;
    if (len >= gap) {
      memcpy(c->buf + boff, data, gap);
      lshCompress<W>(c->cv, c->buf);
      boff = 0;
      data += gap;
      len -= gap;
    } else {
      memcpy(c->buf + boff, data, len);
      c->boff = boff + len;
      return;
    }
  }
  while (len >= kBlock) {
    lshCompress<W>(c->cv, data);
    data += kBlock;
    len -= kBlock;
  }
  if (len > 0) {
    memcpy(c->buf, data, len);
    boff = len;
  }
  c->boff = boff;
}

template <typename W, typename CTX>
void lshFinal(CTX *c, uint8_t *out) {
  const size_t kBlock = LshTraits<W>::kBlock;
  size_t r = c->boff;
  c->buf[r] = 0x80;
  for (size_t i = r + 1; i < kBlock; i++) {
    c->buf[i] = 0;
  }
  lshCompress<W>(c->cv, c->buf);

  W t[8];
  for (int i = 0; i < 8; i++) {
    t[i] = c->cv[i] ^ c->cv[i + 8];
  }
  uint8_t full[64];
  for (int i = 0; i < 8; i++) {
    LshTraits<W>::store(full + i * sizeof(W), t[i]);
  }
  memcpy(out, full, c->outlen);
  OPENSSL_cleanse(full, sizeof(full));
  OPENSSL_cleanse(c, sizeof(CTX));
}

struct LSH256_CTX {
  uint32_t cv[16];
  uint8_t buf[128];
  size_t boff;
  unsigned outlen;
};

struct LSH512_CTX {
  uint64_t cv[16];
  uint8_t buf[256];
  size_t boff;
  unsigned outlen;
};

template <typename W, typename CTX>
void lshInit(CTX *c, const W iv[16], unsigned outlen) {
  memcpy(c->cv, iv, 16 * sizeof(W));
  c->boff = 0;
  c->outlen = outlen;
}

}  // namespace

static void lsh256_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  lshUpdate<uint32_t>(reinterpret_cast<LSH256_CTX *>(ctx->md_data),
                      reinterpret_cast<const uint8_t *>(data), count);
}
static void lsh256_final(EVP_MD_CTX *ctx, uint8_t *out) {
  lshFinal<uint32_t>(reinterpret_cast<LSH256_CTX *>(ctx->md_data), out);
}
static void lsh512_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  lshUpdate<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data),
                      reinterpret_cast<const uint8_t *>(data), count);
}
static void lsh512_final(EVP_MD_CTX *ctx, uint8_t *out) {
  lshFinal<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data), out);
}

static void lsh256_224_init(EVP_MD_CTX *ctx) {
  lshInit<uint32_t>(reinterpret_cast<LSH256_CTX *>(ctx->md_data), kLsh256IV224,
                    28);
}
static void lsh256_256_init(EVP_MD_CTX *ctx) {
  lshInit<uint32_t>(reinterpret_cast<LSH256_CTX *>(ctx->md_data), kLsh256IV256,
                    32);
}
static void lsh512_224_init(EVP_MD_CTX *ctx) {
  lshInit<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data), kLsh512IV224,
                    28);
}
static void lsh512_256_init(EVP_MD_CTX *ctx) {
  lshInit<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data), kLsh512IV256,
                    32);
}
static void lsh512_384_init(EVP_MD_CTX *ctx) {
  lshInit<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data), kLsh512IV384,
                    48);
}
static void lsh512_512_init(EVP_MD_CTX *ctx) {
  lshInit<uint64_t>(reinterpret_cast<LSH512_CTX *>(ctx->md_data), kLsh512IV512,
                    64);
}

#define DEFINE_LSH_MD(name, nid_val, md_sz, init_fn, upd_fn, fin_fn, blk, ctx_t) \
  DEFINE_METHOD_FUNCTION(EVP_MD, name) {                                        \
    out->type = (nid_val);                                                      \
    out->md_size = (md_sz);                                                     \
    out->flags = 0;                                                             \
    out->init = (init_fn);                                                      \
    out->update = (upd_fn);                                                     \
    out->final = (fin_fn);                                                      \
    out->block_size = (blk);                                                    \
    out->ctx_size = sizeof(ctx_t);                                              \
  }

DEFINE_LSH_MD(EVP_lsh256_224, NID_lsh256_224, 28, lsh256_224_init,
              lsh256_update, lsh256_final, 128, LSH256_CTX)
DEFINE_LSH_MD(EVP_lsh256_256, NID_lsh256_256, 32, lsh256_256_init,
              lsh256_update, lsh256_final, 128, LSH256_CTX)
DEFINE_LSH_MD(EVP_lsh512_224, NID_lsh512_224, 28, lsh512_224_init,
              lsh512_update, lsh512_final, 256, LSH512_CTX)
DEFINE_LSH_MD(EVP_lsh512_256, NID_lsh512_256, 32, lsh512_256_init,
              lsh512_update, lsh512_final, 256, LSH512_CTX)
DEFINE_LSH_MD(EVP_lsh512_384, NID_lsh512_384, 48, lsh512_384_init,
              lsh512_update, lsh512_final, 256, LSH512_CTX)
DEFINE_LSH_MD(EVP_lsh512_512, NID_lsh512_512, 64, lsh512_512_init,
              lsh512_update, lsh512_final, 256, LSH512_CTX)
