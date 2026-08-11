cmake_minimum_required(VERSION 3.16)
project(upsu VERSION 1.0.0 LANGUAGES C CXX)

include(cmake/VerifyEnvironment.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)

include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenMP REQUIRED)
find_library(NTL_LIBRARY NAMES ntl REQUIRED)
find_library(GMP_LIBRARY NAMES gmp REQUIRED)

set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(fmt)

set(SEAL_BUILD_DEPS OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
set(SEAL_USE_MSGSL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(seal
  GIT_REPOSITORY https://github.com/microsoft/SEAL.git
  GIT_TAG v4.1.1
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(seal)

set(LIBOTE_STD_VER 20 CACHE STRING "" FORCE)
set(CRYPTO_TOOLS_STD_VER 20 CACHE STRING "" FORCE)
set(ENABLE_COPROTO ON CACHE BOOL "" FORCE)
set(ENABLE_BOOST ON CACHE BOOL "" FORCE)
set(ENABLE_CIRCUITS ON CACHE BOOL "" FORCE)
set(ENABLE_IKNP ON CACHE BOOL "" FORCE)
set(ENABLE_KOS ON CACHE BOOL "" FORCE)
set(ENABLE_SOFTSPOKEN_OT ON CACHE BOOL "" FORCE)
set(ENABLE_SILENTOT ON CACHE BOOL "" FORCE)
set(ENABLE_SILENT_VOLE ON CACHE BOOL "" FORCE)
set(ENABLE_PPRF ON CACHE BOOL "" FORCE)
set(ENABLE_BITPOLYMUL ON CACHE BOOL "" FORCE)
set(ENABLE_MRR_TWIST ON CACHE BOOL "" FORCE)
set(ENABLE_SODIUM ON CACHE BOOL "" FORCE)
set(ENABLE_LOGVOLE OFF CACHE BOOL "" FORCE)
set(FETCH_SEAL OFF CACHE BOOL "" FORCE)
set(FETCH_AUTO ON CACHE BOOL "" FORCE)
set(FETCH_BITPOLYMUL ON CACHE BOOL "" FORCE)
set(FETCH_COPROTO ON CACHE BOOL "" FORCE)
set(FETCH_LIBDIVIDE ON CACHE BOOL "" FORCE)
set(FETCH_SODIUM ON CACHE BOOL "" FORCE)
set(NO_KOS_WARNING ON CACHE BOOL "" FORCE)
set(MACORO_TESTS OFF CACHE BOOL "" FORCE)
set(ENABLE_NET_LOG OFF CACHE BOOL "" FORCE)
set(ENABLE_AVX512 OFF CACHE BOOL "" FORCE)
set(LIBOTE_BUILD_DIR "${CMAKE_BINARY_DIR}/libote-work" CACHE PATH "" FORCE)
set(CRYPTOTOOLS_BUILD_DIR "${CMAKE_BINARY_DIR}/libote-work/cryptoTools" CACHE PATH "" FORCE)
set(OC_THIRDPARTY_CLONE_DIR "${CMAKE_BINARY_DIR}/libote-thirdparty/src" CACHE PATH "" FORCE)
set(OC_THIRDPARTY_HINT "${CMAKE_BINARY_DIR}/libote-thirdparty/install" CACHE PATH "" FORCE)
set(OC_THIRDPARTY_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/libote-thirdparty/install" CACHE PATH "" FORCE)
file(MAKE_DIRECTORY "${LIBOTE_BUILD_DIR}" "${CRYPTOTOOLS_BUILD_DIR}"
                    "${OC_THIRDPARTY_CLONE_DIR}" "${OC_THIRDPARTY_INSTALL_PREFIX}")

FetchContent_Declare(libote
  GIT_REPOSITORY https://github.com/osu-crypto/libOTe.git
  # Exact revision declared by secure-join's own dependency manifest.
  GIT_TAG 657f6da90bff5774a2d01c824e997572d5e8ba00
  GIT_SUBMODULES_RECURSE TRUE
  PATCH_COMMAND ${CMAKE_COMMAND}
    -DSOURCE_DIR=<SOURCE_DIR>
    -DPATCH_FILE=${CMAKE_CURRENT_SOURCE_DIR}/cmake/patches/libote_fetch_mkdir.patch
    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ApplyPatch.cmake)
FetchContent_GetProperties(libote)
if(NOT libote_POPULATED)
  FetchContent_Populate(libote)
  foreach(relative_file CMakeLists.txt cryptoTools/CMakeLists.txt)
    set(input_file "${libote_SOURCE_DIR}/${relative_file}")
    file(READ "${input_file}" contents)
    string(REPLACE "add_subdirectory(libOTe_Tests)"
                   "add_subdirectory(libOTe_Tests EXCLUDE_FROM_ALL)"
                   contents "${contents}")
    string(REPLACE "add_subdirectory(frontend)"
                   "add_subdirectory(frontend EXCLUDE_FROM_ALL)"
                   contents "${contents}")
    string(REPLACE "add_subdirectory(tests_cryptoTools)"
                   "add_subdirectory(tests_cryptoTools EXCLUDE_FROM_ALL)"
                   contents "${contents}")
    string(REPLACE "add_subdirectory(frontend_cryptoTools)"
                   "add_subdirectory(frontend_cryptoTools EXCLUDE_FROM_ALL)"
                   contents "${contents}")
    file(WRITE "${input_file}" "${contents}")
  endforeach()
  add_subdirectory("${libote_SOURCE_DIR}" "${libote_BINARY_DIR}" EXCLUDE_FROM_ALL)
endif()

FetchContent_Declare(secure_join
  GIT_REPOSITORY https://github.com/ladnir/secure-join.git
  GIT_TAG 377ca63b9d8f4f6aede0d3a2e3d9078973a3ee10
  GIT_SHALLOW TRUE)
FetchContent_GetProperties(secure_join)
if(NOT secure_join_POPULATED)
  FetchContent_Populate(secure_join)
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/secure-join")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/generated/secure-join/config.h"
  "#pragma once\n/* #undef SECUREJOIN_ENABLE_PAILLIER */\n"
  "/* #undef SECUREJOIN_ENABLE_FAKE_GEN */\n#define SEC_JOIN_ROOT_DIRECTORY \".\"\n")

set(SECURE_JOIN_SOURCES
  AggTree/AggTree.cpp AggTree/Level.cpp AggTree/PlainAggTree.cpp
  CorGenerator/Batch.cpp CorGenerator/BinOleBatch.cpp
  CorGenerator/CorGenerator.cpp CorGenerator/F4BitOtBatch.cpp
  CorGenerator/OtBatch.cpp CorGenerator/Request.cpp CorGenerator/TritOtBatch.cpp
  GMW/Circuit.cpp GMW/Gmw.cpp Join/OmJoin.cpp Join/OoJoin.cpp Join/Table.cpp
  Perm/AltModComposedPerm.cpp Perm/AltModPerm.cpp Perm/ComposedPerm.cpp
  Perm/LowMCPerm.cpp Perm/PermCorrelation.cpp Perm/Permutation.cpp
  Perm/PprfPermGen.cpp Prf/AltModKeyMult.cpp Prf/AltModPrf.cpp
  Prf/AltModPrfProto.cpp Prf/ConvertToF3.cpp Prf/F2LinearCode.cpp
  Prf/F3LinearCode.cpp Prf/mod3.cpp Sort/BitInjection.cpp Sort/RadixSort.cpp
  TableOps/Extract.cpp TableOps/GroupBy.cpp TableOps/Where.cpp
  TableOps/WhereParser.cpp Util/Trim.cpp)
list(TRANSFORM SECURE_JOIN_SOURCES
  PREPEND "${secure_join_SOURCE_DIR}/secure-join/")
add_library(secure_join_impl STATIC ${SECURE_JOIN_SOURCES})
target_include_directories(secure_join_impl PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
  "${secure_join_SOURCE_DIR}")
target_compile_definitions(secure_join_impl PUBLIC mMultType=mLpnMultType)
target_compile_options(secure_join_impl PRIVATE
  -fpermissive -Wno-unused-parameter -Wno-unused-variable -Wno-sign-compare)
target_link_libraries(secure_join_impl PUBLIC libOTe)

add_executable(psu
  main.cc unbalanced_psu.cc polynomial_links.cc dh_oprf.cc response_sanitizer.cc
  peqt_coproto_globals.cc
  GMW/Circuit.cpp GMW/Gmw.cpp GMW/SilentTripleGen.cpp
  src/common.cc src/parallel.cc src/net_context.cc src/powers_dag.cc)
target_include_directories(psu PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_options(psu PRIVATE
  -O3 -maes -mbmi2 -mpclmul -msse4.1 -mavx -mavx2
  -Wno-unused-parameter -Wno-redundant-move -Wno-ignored-qualifiers
  -Wno-deprecated-copy)
target_link_options(psu PRIVATE -no-pie -Wl,--allow-multiple-definition)
target_link_libraries(psu PRIVATE
  secure_join_impl libOTe SEAL::seal fmt::fmt OpenSSL::SSL OpenSSL::Crypto
  OpenMP::OpenMP_CXX Threads::Threads ${NTL_LIBRARY} ${GMP_LIBRARY} dl)

install(TARGETS psu RUNTIME DESTINATION bin)
install(FILES settings.json DESTINATION share/upsu)
