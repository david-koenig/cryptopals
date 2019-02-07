#include <stdio.h>
#include "cryptopals_mac.h"

int main() {
    byte_array * key = cstring_to_bytes("KEYKEYKEY");
    byte_array * message = cstring_to_bytes("The quick brown fox jumps over the lazy dog.");

    byte_array * mac = sha1_mac(key, message);
    printf("Secret: ???\n");
    printf("Message: ");
    print_byte_array_ascii(message);
    printf("MAC: ");
    print_byte_array(mac);

    free_byte_array(key);
    free_byte_array(message);
    free_byte_array(mac);
    return 0;
}
