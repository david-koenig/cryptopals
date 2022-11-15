#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // stat
#include <sys/stat.h>  // stat
#include <unistd.h>    // stat
#include "cryptopals_utils.h"

byte_array alloc_byte_array(size_t len) {
    byte_array ba;
    ba.len = len;
    ba.bytes = calloc(len, sizeof(uint8_t));
    return ba;
}

void free_byte_array(byte_array x) {
    if (x.bytes != NULL) {
        free(x.bytes);
    }
}

void print_byte_array(const byte_array x) {
    size_t idx;
    for (idx = 0 ; idx < x.len ; idx++) {
        printf("%02hhx", x.bytes[idx]);
    }
    printf("\n");
}

byte_array byte_array_to_hex_byte_array(const byte_array x) {
    byte_array out = alloc_byte_array(1 + x.len * 2);
    size_t idx;
    for (idx = 0 ; idx < x.len ; idx++) {
        sprintf((char *) out.bytes + 2*idx, "%02hhx", x.bytes[idx]);
    }
    return out;
}

void print_byte_array_blocks(const byte_array x, size_t block_size, char separator) {
    size_t idx;
    for (idx = 0 ; idx < x.len ; idx++) {
        printf("%02hhx", x.bytes[idx]);
        if (idx % block_size == block_size - 1) {
            printf("%c", separator);
        }
    }
    printf("\n");
}

void print_byte_array_ascii(const byte_array x) {
    size_t idx;
    for (idx = 0; idx < x.len ; idx++) {
        printf("%c", x.bytes[idx]);
    }
    printf("\n");
}

void print_byte_array_ascii_blocks(const byte_array x, size_t block_size, char separator) {
    size_t idx;
    for (idx = 0 ; idx < x.len ; idx++) {
        printf("%c", x.bytes[idx]);
        if (idx % block_size == block_size - 1) {
            printf("%c", separator);
        }
    }
    printf("\n");
}

uint8_t hex_char_to_byte(uint8_t hex_char) {
    if ('0' <= hex_char && hex_char <= '9')
        return hex_char - '0';
    if ('a' <= hex_char && hex_char <= 'f')
        return hex_char - 'a' + 10;
    if ('A' <= hex_char && hex_char <= 'F')
        return hex_char - 'A' + 10;
    fprintf(stderr, "%s: disallowed character: %c %i", __func__, hex_char, hex_char);
    exit(-1);
}

byte_array hex_to_bytes(const char * hex_str) {
    size_t len = strlen(hex_str);
    size_t idx;
    byte_array ba = alloc_byte_array((len+1)/2);
    uint8_t byte;

    size_t offset = len&1;
    for (idx = 0 ; idx < len ; idx++) {
        byte = hex_char_to_byte(hex_str[idx]);
        ba.bytes[(idx+offset)/2] += byte << ((1^offset^(idx&1))<<2); // shifts either 0 or 4 bits if odd or even
    }
    return ba;
}

byte_array cstring_to_bytes(const char * str) {
    size_t len = strlen(str);
    byte_array ba = alloc_byte_array(len);
    memcpy(ba.bytes, str, len); // strcpy copies the null byte, which we don't want here
    return ba;
}

uint8_t base64_lookup[64] =
{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

uint8_t * three_bytes_to_base64(uint8_t * base64_ptr, uint8_t b0, uint8_t b1, uint8_t b2) {
    *base64_ptr++ = base64_lookup[b0 >> 2];
    *base64_ptr++ = base64_lookup[((b0 & 0x3) << 4) + (b1 >> 4)];
    *base64_ptr++ = base64_lookup[((b1 & 0xf) << 2) + (b2 >> 6)];
    *base64_ptr++ = base64_lookup[b2 & 0x3f];
    return base64_ptr;
}

uint8_t * byte_array_to_base64(const byte_array ba) {
    size_t num_24_bit_blocks = (ba.len) / 3;
    size_t leftover_bytes = (ba.len) % 3;
    size_t base64_str_sz = (((ba.len + 2) / 3) << 2) + 1; // 4 characters for each 3 byte chunk and null byte
    uint8_t * base64_str = calloc(base64_str_sz, sizeof(uint8_t));
    uint8_t * base64_ptr = base64_str;
    size_t idx;

    for (idx = 0 ; idx < num_24_bit_blocks ; idx++) {
        base64_ptr = three_bytes_to_base64(base64_ptr, ba.bytes[3 * idx], ba.bytes[3 * idx + 1], ba.bytes[3 * idx + 2]);
    }
    if (leftover_bytes == 2) {
        base64_ptr = three_bytes_to_base64(base64_ptr, ba.bytes[3 * num_24_bit_blocks], ba.bytes[3 * num_24_bit_blocks + 1], 0);
        base64_ptr[-1] = '=';
    } else if (leftover_bytes == 1) {
        base64_ptr = three_bytes_to_base64(base64_ptr, ba.bytes[3 * num_24_bit_blocks], 0, 0);
        base64_ptr[-1] = '=';
        base64_ptr[-2] = '=';
    }
    return base64_str;
}

uint8_t * hex_to_base64(const char * hex_str) {
    byte_array ba = hex_to_bytes(hex_str);
    uint8_t * base64_str = byte_array_to_base64(ba);
    free_byte_array(ba);
    return base64_str;
}

uint8_t base64_char_to_byte(char x) {
    if ('A' <= x && x <= 'Z')
        return x - 'A';
    if ('a' <= x && x <= 'z')
        return x - 'a' + 26;
    if ('0' <= x && x <= '9')
        return x - '0' + 52;
    if (x == '+')
        return 62;
    if (x == '/')
        return 63;
    if (x == '=')
        return 0;
    fprintf(stderr, "%s: disallowed character: %c %i\n", __func__, x, x);
    exit(-1);
}

void four_base64_chars_to_three_bytes(uint8_t * bytes, const char * base64_ptr) {
    uint8_t byte;
    bytes[0] = base64_char_to_byte(*base64_ptr++) << 2;
    byte = base64_char_to_byte(*base64_ptr++);
    bytes[0] += byte >> 4;
    bytes[1] = byte << 4;
    byte = base64_char_to_byte(*base64_ptr++);
    bytes[1] += byte >> 2;
    bytes[2] = byte << 6;
    bytes[2] += base64_char_to_byte(*base64_ptr++);
}

byte_array base64_to_bytes(const char * base64_str) {
    size_t base64_len = strlen(base64_str);
    if (base64_len % 4) {
        fprintf(stderr, "%s: string length not multiple of 4\n", __func__);
        exit(1);
    }
    size_t byte_len = (base64_len >> 2) * 3;
    if (base64_str[base64_len - 1] == '=') {
        --byte_len;
        if (base64_str[base64_len - 2] == '=') {
            --byte_len;
        }
    }
    byte_array ba = alloc_byte_array(byte_len);
    const char * base64_ptr = base64_str;
    uint8_t * byte_ptr = ba.bytes;
    for ( ; byte_ptr < ba.bytes + byte_len - 2 ; base64_ptr += 4, byte_ptr += 3) {
        four_base64_chars_to_three_bytes(byte_ptr, base64_ptr);
    }
    if (byte_len % 3) {
        uint8_t end_bytes[3];
        four_base64_chars_to_three_bytes(end_bytes, base64_ptr);
        byte_ptr[0] = end_bytes[0];
        if (byte_len % 3 == 2) {
            byte_ptr[1] = end_bytes[1];
        }
    }
    return ba;
}

byte_array sub_byte_array(const byte_array ba, size_t x, size_t y) {
    if (x > y) {
        fprintf(stderr, "%s: starting index %li > ending index %li\n", __func__, x, y);
        exit(1);
    }
    if (y > ba.len) {
        fprintf(stderr, "%s: ending index %li > byte array len %li\n", __func__, y, ba.len); 
    }
    byte_array sub_ba = alloc_byte_array(y - x);
    memcpy(sub_ba.bytes, ba.bytes + x, y - x);
    return sub_ba;
}

byte_array copy_byte_array(const byte_array ba) {
    return sub_byte_array(ba, 0, ba.len);
}

byte_array append_null_byte(const byte_array x) {
    byte_array ba = alloc_byte_array(x.len+1);
    memcpy(ba.bytes, x.bytes, x.len);
    return ba;
}

byte_array append_byte_arrays(const byte_array x, const byte_array y) {
    byte_array ba = alloc_byte_array(x.len + y.len);
    memcpy(ba.bytes, x.bytes, x.len);
    memcpy(ba.bytes + x.len, y.bytes, y.len);
    return ba;
}

byte_array append_three_byte_arrays(const byte_array x, const byte_array y, const byte_array z) {
    byte_array ba = alloc_byte_array(x.len + y.len + z.len);
    memcpy(ba.bytes, x.bytes, x.len);
    memcpy(ba.bytes + x.len, y.bytes, y.len);
    memcpy(ba.bytes + x.len + y.len, z.bytes, z.len);
    return ba;
}

byte_array join_byte_arrays(const byte_array x, char sep, const byte_array y) {
    byte_array ba = alloc_byte_array(x.len + y.len + 1);
    memcpy(ba.bytes, x.bytes, x.len);
    ba.bytes[x.len] = sep;
    memcpy(ba.bytes + x.len + 1, y.bytes, y.len);
    return ba;
}

bool byte_arrays_equal(const byte_array x, const byte_array y) {
    return x.len == y.len && !memcmp(x.bytes, y.bytes, x.len);
}

byte_array xor_byte_arrays(byte_array z, const byte_array x, const byte_array y) {
    size_t idx;
    size_t len = x.len <= y.len ? x.len : y.len;

    if (z.bytes == NULL) {
        z = alloc_byte_array(len);
    }
    for (idx = 0; idx < len ; idx++) {
        z.bytes[idx] = x.bytes[idx] ^ y.bytes[idx];
    }
    return z;
}

void xor_block(uint8_t * z, const uint8_t * x, const uint8_t * y, size_t block_size) {
    size_t idx;
    for (idx = 0; idx < block_size ; idx++) {
        z[idx] = x[idx] ^ y[idx];
    }
}

void set_all_bytes(byte_array ba, uint8_t c) {
    memset(ba.bytes, c, ba.len);
}

size_t pop_count_byte(uint8_t b) {
    b = ((b & 0xaa) >> 1) + (b & 0x55);
    b = ((b & 0xcc) >> 2) + (b & 0x33);
    b = (b >> 4) + (b & 0x0f);
    return b;
}

size_t pop_count_byte_array(const byte_array ba) {
    size_t idx;
    size_t bits = 0;
    for (idx = 0 ; idx < ba.len ; idx++) {
        bits += pop_count_byte(ba.bytes[idx]);
    }
    return bits;
}

size_t hamming_distance(const byte_array x, const byte_array y) {
    byte_array z = xor_byte_arrays(NO_BA, x, y);
    size_t bits = pop_count_byte_array(z);
    free_byte_array(z);
    return bits;
}

byte_array file_to_bytes(const char * filename) {
    struct stat sb;
    if (stat(filename, &sb) == -1) {
        fprintf(stderr, "%s: File %s not found\n", __func__, filename);
        exit(1);
    }
    off_t filesize = sb.st_size;
    byte_array ba = alloc_byte_array(filesize);
    FILE * f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: Error opening file %s\n", __func__, filename);
        exit(2);
    }
    size_t bytes_read = fread(ba.bytes, 1, filesize, f);
    if (bytes_read != filesize) {
        fprintf(stderr, "%s: Error reading file %s. %ld bytes were read.\n", __func__, filename, bytes_read);
        exit(3);
    }
    fclose(f);
    return ba;
}

byte_array base64_file_to_bytes(const char * filename) {
    /*
     * Currently assumes each line is valid base64.
     * TODO: concatenate all lines into one string first,
     * then convert from base64 to byte array.
     */

    FILE * f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: error reading file %s\n", __func__, filename);
        exit(1);
    }
    char line[256] = "";

    byte_array ba = alloc_byte_array(0);
    byte_array old_ba;

    while (fgets(line, 256, f)) {
        char * c = strchr(line, '\n');
        if (c) *c = '\0';

        byte_array ba_line = base64_to_bytes(line);

        old_ba = ba;
        ba = append_byte_arrays(old_ba, ba_line);
        free_byte_array(old_ba);
        free_byte_array(ba_line);
    }
    fclose(f);
    return ba;
}

byte_array* base64_each_line_to_bytes(size_t * num_byte_arrays, const char * filename) {
    FILE * f = fopen(filename, "r");
    if (f == NULL) {
        fprintf(stderr, "%s: error reading file %s\n", __func__, filename);
        exit(1);
    }
    size_t line_num = 0;
    char line[256] = "";
    while (fgets(line, 256, f)) {
        ++line_num;
    }
    rewind(f);
    byte_array* ba_p = malloc(line_num * sizeof(byte_array));
    line_num = 0;
    while (fgets(line, 256, f)) {
        char * c = strchr(line, '\n');
        if (c) *c = '\0';
        ba_p[line_num++] = base64_to_bytes(line);
    }
    * num_byte_arrays = line_num;
    fclose(f);
    return ba_p;
}

void free_array_of_byte_arrays(byte_array* ba_p, size_t num_byte_arrays) {
    size_t idx;
    for (idx = 0 ; idx < num_byte_arrays ; ++idx) {
        free_byte_array(ba_p[idx]);
    }
    free(ba_p);
}
