#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_mac.h"

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nCalculate a SHA1 keyed MAC\n", argv[0]);
        return 1;
    }
    init_random_mac_key(atoi(argv[1]));

    byte_array message = cstring_to_bytes("The quick brown fox jumps over the lazy dog.");

    byte_array mac = sha1_mac(message);
    printf("Secret: ???\n");
    printf("Message: ");
    print_byte_array_ascii(message);
    printf("MAC: ");
    print_byte_array(mac);

    free_byte_arrays(message, mac, NO_BA);
    cleanup_random_mac_key();
    return 0;
}
