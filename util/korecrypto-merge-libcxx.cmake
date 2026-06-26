# 번들 libc++/libc++abi 정적 라이브러리를 libcrypto.a 안으로 병합한다.
#
# CMakeLists.txt 의 crypto POST_BUILD 단계에서 `cmake -P` 로 호출된다:
#   cmake -DAR=<ar> -DCRYPTO=<libcrypto.a> -DLIBCXX=<liblibcxx.a>
#         -DLIBCXXABI=<liblibcxxabi.a> -P util/korecrypto-merge-libcxx.cmake
#
# boringssl 의 C++ 오브젝트는 libc++ 심볼을 객체 경계 너머로 참조하므로, 심볼을
# 그냥 숨기면(local 화) 링크가 깨진다. 대신 세 아카이브의 멤버를 하나의 libcrypto.a
# 로 합친다. 모체 libc++ 와의 충돌 회피는 ABI 네임스페이스 격리
# (-D_LIBCPP_ABI_NAMESPACE=__korecrypto, CMakeLists.txt 참고)가 담당한다.

if(NOT EXISTS "${CRYPTO}" OR NOT EXISTS "${LIBCXX}" OR NOT EXISTS "${LIBCXXABI}")
  # 번들 libc++ 가 없으면(USE_CUSTOM_LIBCXX 미사용 등) 병합할 것이 없다.
  return()
endif()

# 멱등성: libc++abi 멤버(private_typeinfo.cpp.o)가 이미 libcrypto.a 에 있으면 병합이
# 끝난 상태이므로 건너뛴다. (crypto 멤버명과 겹치지 않음을 확인했다.)
execute_process(
  COMMAND "${AR}" t "${CRYPTO}"
  OUTPUT_VARIABLE _members
  RESULT_VARIABLE _list_rc)
if(_list_rc EQUAL 0 AND _members MATCHES "(^|\n)private_typeinfo\\.cpp\\.o(\n|$)")
  return() # already merged
endif()

# 임시 출력에 합친 뒤 원자적으로 교체한다(libcrypto.a 를 입력이자 출력으로 동시에
# 쓰는 것을 피한다). ar 의 MRI 스크립트(addlib)는 아카이브의 모든 멤버를 풀어서
# 추가한다.
set(_merged "${CRYPTO}.merged")
set(_mri "${CRYPTO}.mri")
file(REMOVE "${_merged}")
file(WRITE "${_mri}"
     "create ${_merged}\n"
     "addlib ${CRYPTO}\n"
     "addlib ${LIBCXX}\n"
     "addlib ${LIBCXXABI}\n"
     "save\n"
     "end\n")

execute_process(
  COMMAND "${AR}" -M
  INPUT_FILE "${_mri}"
  RESULT_VARIABLE _merge_rc)
file(REMOVE "${_mri}")

if(NOT _merge_rc EQUAL 0)
  message(FATAL_ERROR "Failed to merge libc++ into libcrypto.a (${AR} -M, rc=${_merge_rc})")
endif()

file(RENAME "${_merged}" "${CRYPTO}")
message(STATUS "Merged libc++/libc++abi into libcrypto.a")
