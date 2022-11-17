#include "cryptopals.h"
#include <stdio.h>
#include <assert.h>

int main(int argc, char ** argv) {
    uint64_t nonce = 0;
    byte_array key = cstring_to_bytes("YELLOW SUBMARINE");
    byte_array cipher = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

    init_openssl();

    byte_array plain = decrypt_aes_128_ctr(cipher, key, nonce);
    print_byte_array_ascii(plain);

    byte_array cipher2 = encrypt_aes_128_ctr(plain, key, nonce);
    assert(byte_arrays_equal(cipher, cipher2));

    cleanup_openssl();
    free_byte_arrays(key, cipher, cipher2, plain, NO_BA);
    return 0;
}
