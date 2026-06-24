// Copyright 2015 The BoringSSL Authors
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

// Ensure we can't call OPENSSL_malloc circularly.
#define _BORINGSSL_PROHIBIT_OPENSSL_MALLOC
#include "internal.h"

#if defined(OPENSSL_WINDOWS_THREADS)

#include <windows.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>


BSSL_NAMESPACE_BEGIN

static BOOL CALLBACK call_once_init(INIT_ONCE *once, void *arg, void **out) {
  void (**init)() = (void (**)())arg;
  (**init)();
  return TRUE;
}

void CRYPTO_once(CRYPTO_once_t *once, void (*init)()) {
  BSSL_CHECK(InitOnceExecuteOnce(once, call_once_init, &init, nullptr));
}

void StaticMutex::LockRead() { AcquireSRWLockShared(&lock_); }
void StaticMutex::UnlockRead() { ReleaseSRWLockShared(&lock_); }
void StaticMutex::LockWrite() { AcquireSRWLockExclusive(&lock_); }
void StaticMutex::UnlockWrite() { ReleaseSRWLockExclusive(&lock_); }
Mutex::~Mutex() { /* SRWLOCKs require no cleanup. */ }

static SRWLOCK g_destructors_lock = SRWLOCK_INIT;
static thread_local_destructor_t g_destructors[NUM_OPENSSL_THREAD_LOCALS];

static CRYPTO_once_t g_thread_local_init_once = CRYPTO_ONCE_INIT;
static DWORD g_thread_local_key;
static int g_thread_local_failed;

static void thread_local_init() {
  g_thread_local_key = TlsAlloc();
  g_thread_local_failed = (g_thread_local_key == TLS_OUT_OF_INDEXES);
}

static void NTAPI thread_local_destructor(PVOID module, DWORD reason,
                                          PVOID reserved) {
  // Only free memory on `DLL_THREAD_DETACH`, not `DLL_PROCESS_DETACH`. In
  // VS2015's debug runtime, the C runtime has been unloaded by the time
  // `DLL_PROCESS_DETACH` runs. See https://crbug.com/575795. This is consistent
  // with `pthread_key_create` which does not call destructors on process exit,
  // only thread exit.
  if (reason != DLL_THREAD_DETACH) {
    return;
  }

  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return;
  }

  void **pointers = (void **)TlsGetValue(g_thread_local_key);
  if (pointers == nullptr) {
    return;
  }

  thread_local_destructor_t destructors[NUM_OPENSSL_THREAD_LOCALS];

  AcquireSRWLockExclusive(&g_destructors_lock);
  OPENSSL_memcpy(destructors, g_destructors, sizeof(destructors));
  ReleaseSRWLockExclusive(&g_destructors_lock);

  for (unsigned i = 0; i < NUM_OPENSSL_THREAD_LOCALS; i++) {
    if (destructors[i] != nullptr) {
      destructors[i](pointers[i]);
    }
  }

  free(pointers);
}

// Thread Termination Callbacks.
//
// Windows doesn't support a per-thread destructor with its TLS primitives.
// So, we build it manually by inserting a function to be called on each
// thread's exit. This magic is from http://www.codeproject.com/threads/tls.asp
// and it works for VC++ 7.0 and later.
//
// Force a reference to _tls_used to make the linker create the TLS directory
// if it's not already there. (E.g. if __declspec(thread) is not used). Force
// a reference to p_thread_callback_boringssl to prevent whole program
// optimization from discarding the variable.
//
// Note, in the prefixed build, `p_thread_callback_boringssl` may be a macro.
// .CRT$XLA to .CRT$XLZ is an array of PIMAGE_TLS_CALLBACK pointers that are
// called automatically by the OS loader code (not the CRT) when the module is
// loaded and on thread creation. They are NOT called if the module has been
// loaded by a LoadLibrary() call. It must have implicitly been loaded at
// process startup.
//
// See VC\crt\src\tlssup.c for reference.
#define STRINGIFY(x) #x
#define EXPAND_AND_STRINGIFY(x) STRINGIFY(x)

#if defined(_MSC_VER)

// MSVC: use linker /INCLUDE pragmas and segment pragmas to place the callback.
#ifdef _WIN64
__pragma(comment(linker, "/INCLUDE:_tls_used")) __pragma(comment(
    linker, "/INCLUDE:" EXPAND_AND_STRINGIFY(p_thread_callback_boringssl)))
#else
__pragma(comment(linker, "/INCLUDE:__tls_used")) __pragma(comment(
    linker, "/INCLUDE:_" EXPAND_AND_STRINGIFY(p_thread_callback_boringssl)))
#endif

#ifdef _WIN64

// .CRT section is merged with .rdata on x64 so it must be constant data.
#pragma const_seg(".CRT$XLC")
    // clang-format off
    // When defining a const variable, it must have external linkage to be sure
    // the linker doesn't discard it.
extern "C" {
  extern const PIMAGE_TLS_CALLBACK p_thread_callback_boringssl;
}
// clang-format on
const PIMAGE_TLS_CALLBACK p_thread_callback_boringssl = thread_local_destructor;
// Reset the default section.
#pragma const_seg()

#else

#pragma data_seg(".CRT$XLC")
    // clang-format off
extern "C" {
  extern PIMAGE_TLS_CALLBACK p_thread_callback_boringssl;
}
// clang-format on
PIMAGE_TLS_CALLBACK p_thread_callback_boringssl = thread_local_destructor;
// Reset the default section.
#pragma data_seg()

#endif  // _WIN64

#else  // !_MSC_VER

// MinGW/clang(GNU 툴체인)에는 const_seg/comment(linker) 프라그마가 없다. 대신
// section/used 속성으로 콜백 포인터를 .CRT$XLC 에 배치한다. mingw-w64 CRT 가
// .CRT$XLA..XLZ 사이의 콜백들을 TLS 디렉터리에 연결해 OS 로더가 호출한다.
// _tls_used 를 참조해 TLS 디렉터리가 반드시 생성되도록 강제한다.
extern "C" {
extern char _tls_used;
}
static void *const force_tls_used __attribute__((used)) = &_tls_used;

extern "C" {
__attribute__((section(".CRT$XLC"), used)) PIMAGE_TLS_CALLBACK
    p_thread_callback_boringssl = thread_local_destructor;
}

#endif  // _MSC_VER

static void **get_thread_locals() {
  // `TlsGetValue` clears the last error even on success, so that callers may
  // distinguish it successfully returning NULL or failing. It is documented to
  // never fail if the argument is a valid index from `TlsAlloc`, so we do not
  // need to handle this.
  //
  // However, this error-mangling behavior interferes with the caller's use of
  // `GetLastError`. In particular `SSL_get_error` queries the error queue to
  // determine whether the caller should look at the OS's errors. To avoid
  // destroying state, save and restore the Windows error.
  //
  // https://msdn.microsoft.com/en-us/library/windows/desktop/ms686812(v=vs.85).aspx
  DWORD last_error = GetLastError();
  void **ret = reinterpret_cast<void **>(TlsGetValue(g_thread_local_key));
  SetLastError(last_error);
  return ret;
}

void *CRYPTO_get_thread_local(thread_local_data_t index) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    return nullptr;
  }

  void **pointers = get_thread_locals();
  if (pointers == nullptr) {
    return nullptr;
  }
  return pointers[index];
}

int CRYPTO_set_thread_local(thread_local_data_t index, void *value,
                            thread_local_destructor_t destructor) {
  CRYPTO_once(&g_thread_local_init_once, thread_local_init);
  if (g_thread_local_failed) {
    destructor(value);
    return 0;
  }

  void **pointers = get_thread_locals();
  if (pointers == nullptr) {
    pointers = reinterpret_cast<void **>(
        malloc(sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS));
    if (pointers == nullptr) {
      destructor(value);
      return 0;
    }
    OPENSSL_memset(pointers, 0, sizeof(void *) * NUM_OPENSSL_THREAD_LOCALS);
    if (TlsSetValue(g_thread_local_key, pointers) == 0) {
      free(pointers);
      destructor(value);
      return 0;
    }
  }

  AcquireSRWLockExclusive(&g_destructors_lock);
  g_destructors[index] = destructor;
  ReleaseSRWLockExclusive(&g_destructors_lock);

  pointers[index] = value;
  return 1;
}

BSSL_NAMESPACE_END

#endif  // OPENSSL_WINDOWS_THREADS
