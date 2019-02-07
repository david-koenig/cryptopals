#include "cryptopals.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(int argc, char ** argv) {
    char * test_vectors[3] = {"ICE ICE BABY\x04\x04\x04\x04",
                              "ICE ICE BABY\x05\x05\x05\x05",
                              "ICE ICE BABY\x01\x02\x03\x04"};
    size_t idx;
    for (idx = 0; idx < 3; idx++) {
        byte_array * ba = cstring_to_bytes(test_vectors[idx]);
        byte_array * unpadded = remove_pkcs7_padding(ba);
        if (idx == 0) {
            assert(unpadded != NULL);
            assert(unpadded->len == 12);
            assert(!memcmp(unpadded->bytes, "ICE ICE BABY", 12));
        } else {
            assert(unpadded == NULL);
        }
    }
    printf("All tests passed!\n");
    return 0;
}
