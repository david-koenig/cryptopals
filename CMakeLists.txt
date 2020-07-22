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

add_library(Cryptopals cryptopals.c)
target_link_libraries(Cryptopals ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(Cryptopals PRIVATE ${OPENSSL_INCLUDE_DIR})

add_library(Cryptopals_utils cryptopals_utils.c)
add_library(Cryptopals_attack cryptopals_attack.c)
add_library(Cryptopals_mac cryptopals_mac.c)
add_library(Cryptopals_random cryptopals_random.c)
add_library(Cryptopals_mersenne cryptopals_mersenne.cpp)
add_library(Cryptopals_profile cryptopals_profile.cpp)
add_library(Cryptopals_uri cryptopals_uri.cpp)

add_library(Sha1 sha1.c)
add_library(Md4c md4c.c)

add_executable(aes_128_ecb_test aes_128_ecb_test.c)
target_link_libraries(aes_128_ecb_test Cryptopals_utils Cryptopals)

add_executable(sha1test sha1test.c)
target_link_libraries(sha1test Sha1)

add_executable(md4test mddriver.c)
target_link_libraries(md4test Md4c)


add_executable(set1_challenge1 set1_challenge1.c)
target_link_libraries(set1_challenge1 Cryptopals_utils)

add_executable(set1_challenge2 set1_challenge2.c)
target_link_libraries(set1_challenge2 Cryptopals_utils)

add_executable(set1_challenge3 set1_challenge3.c)
target_link_libraries(set1_challenge3 Cryptopals_utils Cryptopals)

add_executable(set1_challenge4 set1_challenge4.c)
target_link_libraries(set1_challenge4 Cryptopals_utils Cryptopals)

add_executable(set1_challenge5 set1_challenge5.c)
target_link_libraries(set1_challenge5 Cryptopals_utils Cryptopals)

add_executable(set1_challenge6a set1_challenge6a.c)
target_link_libraries(set1_challenge6a Cryptopals_utils)

add_executable(set1_challenge6b set1_challenge6b.c)
target_link_libraries(set1_challenge6b Cryptopals_utils Cryptopals)

add_executable(set1_challenge6c set1_challenge6c.c)
target_link_libraries(set1_challenge6c Cryptopals_utils Cryptopals)

add_executable(set1_challenge7 set1_challenge7.c)
target_link_libraries(set1_challenge7 Cryptopals_utils Cryptopals)

add_executable(set1_challenge8 set1_challenge8.cpp)
target_link_libraries(set1_challenge2 Cryptopals_utils)


add_executable(set2_challenge9 set2_challenge9.c)
target_link_libraries(set2_challenge9 Cryptopals_utils Cryptopals)

add_executable(set2_challenge10 set2_challenge10.c)
target_link_libraries(set2_challenge10 Cryptopals_utils Cryptopals)

add_executable(set2_challenge11 set2_challenge11.c)
target_link_libraries(set2_challenge11 Cryptopals_utils Cryptopals Cryptopals_random)

add_executable(set2_challenge12 set2_challenge12.c)
target_link_libraries(set2_challenge12 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_attack)

add_executable(set2_challenge13 set2_challenge13.cpp)
target_link_libraries(set2_challenge13 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_profile)

add_executable(set2_challenge14 set2_challenge14.c)
target_link_libraries(set2_challenge14 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_attack)

add_executable(set2_challenge15 set2_challenge15.c)
target_link_libraries(set2_challenge15 Cryptopals_utils Cryptopals)

add_executable(set2_challenge16 set2_challenge16.cpp)
target_link_libraries(set2_challenge16 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_profile Cryptopals_uri)


add_executable(set3_challenge17 set3_challenge17.c)
target_link_libraries(set3_challenge17 Cryptopals_utils Cryptopals Cryptopals_random)

add_executable(set3_challenge18 set3_challenge18.c)
target_link_libraries(set3_challenge18 Cryptopals_utils Cryptopals)

add_executable(set3_challenge19 set3_challenge19.c)
target_link_libraries(set3_challenge19 Cryptopals_utils Cryptopals Cryptopals_random)

add_executable(set3_challenge20 set3_challenge20.c)
target_link_libraries(set3_challenge20 Cryptopals_utils Cryptopals Cryptopals_random)

add_executable(set3_challenge21 set3_challenge21.cpp)
target_link_libraries(set3_challenge21 Cryptopals_utils Cryptopals_mersenne)

add_executable(set3_challenge22 set3_challenge22.cpp)
target_link_libraries(set3_challenge22 Cryptopals_utils Cryptopals_mersenne)

add_executable(set3_challenge23 set3_challenge23.cpp)
target_link_libraries(set3_challenge23 Cryptopals_utils Cryptopals_mersenne)

add_executable(set3_challenge24a set3_challenge24a.cpp)
target_link_libraries(set3_challenge24a Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_mersenne)

add_executable(set3_challenge24b set3_challenge24b.cpp)
target_link_libraries(set3_challenge24b Cryptopals_utils Cryptopals_mersenne)


add_executable(set4_challenge25 set4_challenge25.c)
target_link_libraries(set4_challenge25 Cryptopals_utils Cryptopals Cryptopals_random)

add_executable(set4_challenge26 set4_challenge26.cpp)
target_link_libraries(set4_challenge26 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_profile Cryptopals_uri)

add_executable(set4_challenge27 set4_challenge27.cpp)
target_link_libraries(set4_challenge27 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_profile Cryptopals_uri)

add_executable(set4_challenge28 set4_challenge28.c)
target_link_libraries(set4_challenge28 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_mac Sha1 Md4c)

add_executable(set4_challenge29 set4_challenge29.c)
target_link_libraries(set4_challenge29 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_mac Sha1 Md4c)

add_executable(set4_challenge30 set4_challenge30.c)
target_link_libraries(set4_challenge30 Cryptopals_utils Cryptopals Cryptopals_random Cryptopals_mac Sha1 Md4c)


add_executable(set5_challenge33 set5_challenge33.c)
target_include_directories(set5_challenge33 PRIVATE ${Gmp_path})
target_link_libraries(set5_challenge33 ${Gmp})
