cmake_minimum_required(VERSION 3.10)

project(DKCryptopals)

include(FindOpenSSL)
find_library(Gmp gmp REQUIRED)
find_path(Gmp_path gmp.h)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB run_scripts "${PROJECT_SOURCE_DIR}/*.sh")
file(COPY ${run_scripts} DESTINATION ${PROJECT_BINARY_DIR})

file(GLOB data_files "${PROJECT_SOURCE_DIR}/[0-9]*.txt")
file(COPY ${data_files} DESTINATION ${PROJECT_BINARY_DIR})

add_library(Cryptopals
  cryptopals.c
  cryptopals_attack.c
  cryptopals_derived_key.c
  cryptopals_dh.c
  cryptopals_mac.c
  cryptopals_random.c
  cryptopals_utils.c
  md4c.c
  sha1.c
  )
target_link_libraries(Cryptopals ${OPENSSL_CRYPTO_LIBRARY} ${Gmp})
target_include_directories(Cryptopals PRIVATE ${OPENSSL_INCLUDE_DIR} ${Gmp_path})

add_library(Cryptopals_cpp cryptopals_mersenne.cpp cryptopals_profile.cpp cryptopals_uri.cpp)

link_libraries(Cryptopals)

add_executable(aes_128_ecb_test aes_128_ecb_test.c)
add_executable(sha1test sha1test.c)
add_executable(md4test mddriver.c)

file(GLOB C_challenges "set*.c")
foreach(challenge ${C_challenges})
  get_filename_component(basename ${challenge} NAME_WE)
  add_executable(${basename} ${challenge})
endforeach()

link_libraries(Cryptopals_cpp)

file(GLOB CPP_challenges "set*.cpp")
foreach(challenge ${CPP_challenges})
  get_filename_component(basename ${challenge} NAME_WE)
  add_executable(${basename} ${challenge})
endforeach()

target_link_libraries(set5_challenge33 ${Gmp})
target_include_directories(set5_challenge33 PRIVATE ${Gmp_path})
