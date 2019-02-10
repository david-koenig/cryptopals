ARGS=-Wall -Werror -g
GCC=gcc $(ARGS)
GPP=g++ -std=gnu++0x $(ARGS)

ifeq ($(OPENSSL_ROOT_DIR),)
OPENSSL_INCLUDE=
OPENSSL=-lcrypto
else
OPENSSL_INCLUDE=-I$(OPENSSL_ROOT_DIR)/include
OPENSSL=$(OPENSSL_INCLUDE) -L$(OPENSSL_ROOT_DIR)/lib -lcrypto
endif

all: test set1 set2 set3 set4 set5

test: aes_128_ecb_test sha1test md4test

set1: set1_challenge1 set1_challenge2 set1_challenge3 set1_challenge4 set1_challenge5 set1_challenge6a set1_challenge6b set1_challenge6c set1_challenge7 set1_challenge8

set2: set2_challenge9 set2_challenge10 set2_challenge11 set2_challenge12 set2_challenge13 set2_challenge14 set2_challenge15 set2_challenge16

set3: set3_challenge17 set3_challenge18 set3_challenge19 set3_challenge20 set3_challenge21 set3_challenge22 set3_challenge23 set3_challenge24a set3_challenge24b

set4: set4_challenge25 set4_challenge26 set4_challenge27 set4_challenge28 set4_challenge29 set4_challenge30

set5: set5_challenge33

aes_128_ecb_test: aes_128_ecb_test.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

sha1test: sha1test.c sha1.o
	$(GCC) -o $@ $^

md4test: mddriver.c md4c.o
	$(GCC) -o $@ $^

set1_challenge1: set1_challenge1.c cryptopals_utils.o
	$(GCC) -o $@ $^

set1_challenge2: set1_challenge2.c cryptopals_utils.o
	$(GCC) -o $@ $^

set1_challenge3: set1_challenge3.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge4: set1_challenge4.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge5: set1_challenge5.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge6a: set1_challenge6a.c cryptopals_utils.o
	$(GCC) -o $@ $^

set1_challenge6b: set1_challenge6b.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge6c: set1_challenge6c.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge7: set1_challenge7.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set1_challenge8: set1_challenge8.cpp
	$(GPP) -o $@ $^

set2_challenge9: set2_challenge9.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge10: set2_challenge10.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge11: set2_challenge11.c cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge12: set2_challenge12.c cryptopals_utils.o cryptopals.o cryptopals_random.o cryptopals_attack.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge13: set2_challenge13.cpp cryptopals_profile.o cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GPP) -o $@ $^ $(OPENSSL)

set2_challenge14: set2_challenge14.c cryptopals_utils.o cryptopals.o cryptopals_random.o cryptopals_attack.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge15: set2_challenge15.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set2_challenge16: set2_challenge16.cpp cryptopals_utils.o cryptopals.o cryptopals_random.o cryptopals_profile.o cryptopals_uri.o
	$(GPP) -o $@ $^ $(OPENSSL)

set3_challenge17: set3_challenge17.c cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set3_challenge18: set3_challenge18.c cryptopals_utils.o cryptopals.o
	$(GCC) -o $@ $^ $(OPENSSL)

set3_challenge19: set3_challenge19.c cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set3_challenge20: set3_challenge20.c cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set3_challenge21: set3_challenge21.cpp cryptopals_mersenne.o cryptopals_utils.o
	$(GPP) -o $@ $^

set3_challenge22: set3_challenge22.cpp cryptopals_mersenne.o cryptopals_utils.o
	$(GPP) -o $@ $^

set3_challenge23: set3_challenge23.cpp cryptopals_mersenne.o cryptopals_utils.o
	$(GPP) -o $@ $^

set3_challenge24a: set3_challenge24a.cpp cryptopals_mersenne.o cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GPP) -o $@ $^ $(OPENSSL)

set3_challenge24b: set3_challenge24b.cpp cryptopals_mersenne.o cryptopals_utils.o
	$(GPP) -o $@ $^

set4_challenge25: set4_challenge25.c cryptopals_utils.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set4_challenge26: set4_challenge26.cpp cryptopals_utils.o cryptopals.o cryptopals_random.o cryptopals_profile.o cryptopals_uri.o
	$(GPP) -o $@ $^ $(OPENSSL)

set4_challenge27: set4_challenge27.cpp cryptopals_utils.o cryptopals.o cryptopals_random.o cryptopals_profile.o cryptopals_uri.o
	$(GPP) -o $@ $^ $(OPENSSL)

set4_challenge28: set4_challenge28.c cryptopals_utils.o cryptopals_mac.o sha1.o md4c.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set4_challenge29: set4_challenge29.c cryptopals_utils.o cryptopals_mac.o sha1.o md4c.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set4_challenge30: set4_challenge30.c cryptopals_utils.o cryptopals_mac.o sha1.o md4c.o cryptopals.o cryptopals_random.o
	$(GCC) -o $@ $^ $(OPENSSL)

set5_challenge33: set5_challenge33.c
	$(GCC) -o $@ $^ -lgmp

cryptopals_utils.o: cryptopals_utils.c cryptopals_utils.h
	$(GCC) -c cryptopals_utils.c

cryptopals.o: cryptopals.c cryptopals.h cryptopals_utils.h
	$(GCC) $(OPENSSL_INCLUDE) -c cryptopals.c

cryptopals_random.o: cryptopals_random.c cryptopals_random.h cryptopals.h cryptopals_utils.h
	$(GCC) -c cryptopals_random.c

cryptopals_attack.o: cryptopals_attack.c cryptopals_attack.h cryptopals_utils.h
	$(GCC) -c cryptopals_attack.c

cryptopals_uri.o: cryptopals_uri.cpp cryptopals_uri.h
	$(GPP) -c cryptopals_uri.cpp

cryptopals_profile.o: cryptopals_profile.cpp cryptopals_profile.h
	$(GPP) -c cryptopals_profile.cpp

cryptopals_mersenne.o: cryptopals_mersenne.cpp cryptopals_mersenne.h
	$(GPP) -c cryptopals_mersenne.cpp

cryptopals_mac.o: cryptopals_mac.c cryptopals_mac.h
	$(GCC) -c cryptopals_mac.c

sha1.o: sha1.c sha1.h
	$(GCC) -c sha1.c

md4c.o: md4c.c md4.h md4_global.h
	$(GCC) -c md4c.c

clean:
	rm -f *test set[1-2]_challenge[1-9] set1_challenge6[a-c] set[2-5]_challenge[1-3][0-9] set3_challenge24[a-b] *.o
	rm -rf *.dSYM
