#include "cryptopals.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\nTest all lines of file for single-character XOR encryption. Use 4.txt\n", argv[0]);
        return 1;
    }
    FILE * f = fopen(argv[1], "r");
    char line[256] = "";

    while(fgets(line, 256, f)) {
        char * c = strchr(line, '\n');
        if (c) *c = '\0';

        byte_array cipher = hex_to_bytes(line);
        score_single_byte_xor(cipher, true);
        free_byte_array(cipher);
    }
    fclose(f);
    return 0;
}
