#include <stdio.h>
#include "cryptopals_mac.h"

int main() {
    byte_array * message = cstring_to_bytes("The quick brown fox jumps over the lazy dog.");
    byte_array * padded_msg = sha1_pad(message);

    print_byte_array(padded_msg);
    print_byte_array_ascii(message);

    printf("msg len = %ld\tpadded msg len = %ld\n", message->len, padded_msg->len);
    free_byte_array(message);
    free_byte_array(padded_msg);
    return 0;
}
