#include "cryptopals.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

void score_single_byte_xor(const byte_array cipher, bool print_plain) {
    byte_array key = alloc_byte_array(cipher.len);
    byte_array plain = alloc_byte_array(cipher.len);
    int score;
    uint8_t key_byte = 0;
    size_t idx;

    do {
        set_all_bytes(key, key_byte);
        xor_byte_arrays(plain, cipher, key);

        score = 0;
        for (idx = 0; idx < plain.len ; idx++) {
            if (isalpha(plain.bytes[idx]) || plain.bytes[idx] == ' ') {
                score++;
            }
        }
        if (score > plain.len * 0.87) {
            printf("key = 0x%02hhx\tscore = %i\tlen = %li\n", key_byte, score, plain.len);
            if (print_plain) print_byte_array_ascii(plain);
        }
        key_byte++;
    } while (key_byte);
    free_byte_array(key);
    free_byte_array(plain);
}

byte_array repeating_byte_xor(const byte_array ba, const byte_array repeating_key) {
    size_t idx;
    byte_array key = alloc_byte_array(ba.len);
    for (idx = 0 ; idx < key.len ; idx++) {
        key.bytes[idx] = repeating_key.bytes[idx % repeating_key.len];
    }
    byte_array cipher = xor_byte_arrays(NO_BA, ba, key);
    free_byte_array(key);
    return cipher;
}

void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
void init_openssl() {
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);
}

void cleanup_openssl() {
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
}
#else
void init_openssl() {}
void cleanup_openssl() {}
#endif

// returns OpenSSL return value or 0 on error, 1 on success
static int EVP_encrypt_decrypt(byte_array output,
                               const byte_array input,
                               const byte_array key,
                               const EVP_CIPHER *type,
                               int (*EVP_init_ex)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                                                  ENGINE *impl, const unsigned char *key, const unsigned char *iv),
                               int (*EVP_update)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                                 int *outl, const unsigned char *in, int inl),
                               int (*EVP_final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                                   int *outl),
                               bool padding
    ) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int output_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Initialise the en/decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * In ECB mode, there is no IV. */
    if(1 != (ret = EVP_init_ex(ctx, type, NULL, key.bytes, NULL))) {
        ERR_print_errors_fp(stderr);
        return ret;
    }

    /* Needs to be done after EVP_init_ex, because that resets padding */
    if (!padding) EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Provide the message to be en/decrypted, and obtain the plaintext output.
     * EVP_update can be called multiple times if necessary
     */
    if(1 != (ret = EVP_update(ctx, output.bytes, &len, input.bytes, input.len))) {
        ERR_print_errors_fp(stderr);
        return ret;
    }
    output_len = len;

    /* Finalise the en/decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != (ret = EVP_final_ex(ctx, output.bytes + len, &len))) {
	ERR_print_errors_fp(stderr);
        return ret;
    }
    output_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    output.len = output_len;
    return 1;
}

byte_array decrypt_aes_128_ecb(const byte_array cipher, const byte_array key) {
    byte_array padded_plaintext = alloc_byte_array(cipher.len);

    if (1 != EVP_encrypt_decrypt(padded_plaintext,
                                 cipher,
                                 key,
                                 EVP_aes_128_ecb(),
                                 EVP_DecryptInit_ex,
                                 EVP_DecryptUpdate,
                                 EVP_DecryptFinal_ex,
                                 false)
        ) {
        free_byte_array(padded_plaintext);
        return NO_BA;
    }
    byte_array plaintext = remove_pkcs7_padding(padded_plaintext);
    free_byte_array(padded_plaintext);
    return plaintext;
}

byte_array encrypt_aes_128_ecb(const byte_array plaintext, const byte_array key) {
    byte_array padded_plaintext = pkcs7_padding(plaintext, 16);
    byte_array cipher = alloc_byte_array(padded_plaintext.len);
    if (1 != EVP_encrypt_decrypt(cipher,
                                 padded_plaintext,
                                 key,
                                 EVP_aes_128_ecb(),
                                 EVP_EncryptInit_ex,
                                 EVP_EncryptUpdate,
                                 EVP_EncryptFinal_ex,
                                 false)
        ) {
        free_byte_array(cipher);
        cipher = NO_BA;
    }
    free_byte_array(padded_plaintext);
    return cipher;
}

byte_array decrypt_aes_128_cbc(const byte_array cipher, const byte_array key, const byte_array iv) {
    byte_array ecb_decrypt = alloc_byte_array(cipher.len);
    if (1 != EVP_encrypt_decrypt(ecb_decrypt,
                                 cipher,
                                 key,
                                 EVP_aes_128_ecb(),
                                 EVP_DecryptInit_ex,
                                 EVP_DecryptUpdate,
                                 EVP_DecryptFinal_ex,
                                 false)
        ) {
        free_byte_array(ecb_decrypt);
        return NO_BA;
    }
    size_t block_size = 16;
    size_t num_blocks = cipher.len >> 4;
    size_t block_idx;
    xor_block(ecb_decrypt.bytes, ecb_decrypt.bytes, iv.bytes, block_size);
    for (block_idx = 1 ; block_idx < num_blocks ; block_idx++) {
        xor_block(ecb_decrypt.bytes + block_size*block_idx,
                  ecb_decrypt.bytes + block_size*block_idx,
                  cipher.bytes + block_size*(block_idx-1),
                  block_size);
    }
    byte_array plaintext = remove_pkcs7_padding(ecb_decrypt);
    free_byte_array(ecb_decrypt);
    return plaintext;
}

byte_array encrypt_aes_128_cbc(const byte_array plaintext, const byte_array key, const byte_array iv) {
    size_t block_size = 16;
    byte_array padded_plaintext = pkcs7_padding(plaintext, block_size);
    byte_array cipher = alloc_byte_array(padded_plaintext.len);
    size_t num_blocks = padded_plaintext.len >> 4;
    byte_array input_block = alloc_byte_array(block_size);
    byte_array output_block = alloc_byte_array(block_size);

    xor_block(input_block.bytes, padded_plaintext.bytes, iv.bytes, block_size);
    if (1 != EVP_encrypt_decrypt(output_block,
                                 input_block,
                                 key,
                                 EVP_aes_128_ecb(),
                                 EVP_EncryptInit_ex,
                                 EVP_EncryptUpdate,
                                 EVP_EncryptFinal_ex,
                                 false)
        ) {
        free_byte_array(cipher);
        cipher = NO_BA;
        goto OUT;
    }
    memcpy(cipher.bytes, output_block.bytes, block_size);

    size_t block_idx;
    for (block_idx = 1 ; block_idx < num_blocks ; block_idx++) {
        xor_block(input_block.bytes,
                  padded_plaintext.bytes + block_size*block_idx,
                  cipher.bytes + block_size*(block_idx-1),
                  block_size);
        if (1 != EVP_encrypt_decrypt(output_block,
                                     input_block,
                                     key,
                                     EVP_aes_128_ecb(),
                                     EVP_EncryptInit_ex,
                                     EVP_EncryptUpdate,
                                     EVP_EncryptFinal_ex,
                                     false)
            ) {
            free_byte_array(cipher);
            cipher = NO_BA;
            goto OUT;
        }
        memcpy(cipher.bytes + block_size*block_idx, output_block.bytes, block_size);
    }

OUT:
    free_byte_array(padded_plaintext);
    free_byte_array(input_block);
    free_byte_array(output_block);
    return cipher;
}

byte_array pkcs7_padding(const byte_array ba, size_t block_size) {
    size_t padding_len = block_size - (ba.len % block_size);
    byte_array padded_ba = alloc_byte_array(ba.len + padding_len);
    memcpy(padded_ba.bytes, ba.bytes, ba.len);
    memset(padded_ba.bytes + ba.len, (uint8_t) padding_len, padding_len);
    return padded_ba;
}

byte_array remove_pkcs7_padding(const byte_array ba) {
    size_t pad_len = ba.bytes[ba.len - 1];
    size_t idx;
    if (!pad_len || pad_len > ba.len) {
        //fprintf(stderr, "%s: byte array does not have valid PKCS7 padding\n", __func__);
        return NO_BA;
    }
    for (idx = ba.len - 2 ; idx != -1L && idx >= ba.len - pad_len ; --idx) {
        if (ba.bytes[idx] != pad_len) {
            //fprintf(stderr, "%s: byte array does not have valid PKCS7 padding\n", __func__);
            return NO_BA;
        }
    }
    byte_array ba_without_padding = alloc_byte_array(ba.len - pad_len);
    memcpy(ba_without_padding.bytes, ba.bytes, ba_without_padding.len);
    return ba_without_padding;
}

byte_array encrypt_decrypt_aes_128_ctr(const byte_array input, const byte_array key, uint64_t nonce) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int output_len = 0;

    size_t block_size = 16;
    byte_array output = alloc_byte_array((input.len + block_size - 1) & ~(block_size - 1));
    uint64_t num_blocks = output.len / block_size;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();

    /* Initialise the en/decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * In ECB mode, there is no IV. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.bytes, NULL)) handle_openssl_errors();

    /* Needs to be done after EVP_init_ex, because that resets padding */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Provide the message to be en/decrypted, and obtain the plaintext output.
     * EVP_update can be called multiple times if necessary
     */
    byte_array key_stream_in = alloc_byte_array(block_size);
    *((uint64_t *) key_stream_in.bytes) = nonce; // assumes little endian machine
    uint64_t block_idx;
    for (block_idx = 0 ; block_idx < num_blocks ; ++block_idx) {
        *((uint64_t *) (key_stream_in.bytes + 8)) = block_idx; // assumes little endian machine
        if(1 != EVP_EncryptUpdate(ctx, output.bytes + output_len, &len, key_stream_in.bytes, block_size))
            handle_openssl_errors();
        output_len += len;
    }
    /* Finalise the en/decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, output.bytes + output_len, &len)) handle_openssl_errors();
    output_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    output.len = input.len;
    output.bytes = realloc(output.bytes, input.len);
    xor_byte_arrays(output, output, input);
    free_byte_array(key_stream_in);
    return output;
}

byte_array encrypt_aes_128_ctr(const byte_array plain, const byte_array key, uint64_t nonce) {
    return encrypt_decrypt_aes_128_ctr(plain, key, nonce);
}

byte_array decrypt_aes_128_ctr(const byte_array cipher, const byte_array key, uint64_t nonce) {
    return encrypt_decrypt_aes_128_ctr(cipher, key, nonce);
}

byte_array edit_ciphertext_aes_128_ctr(const byte_array cipher, const byte_array key, uint64_t nonce, size_t offset, byte_array new_plain) {
    if (offset + new_plain.len > cipher.len) {
        fprintf(stderr, "%s: new plain would extend past end of cipher\n", __func__);
        exit(-1);
    }
    byte_array new_cipher = copy_byte_array(cipher);
    if (!new_plain.len)
        return new_cipher;

    size_t block_size = 16;
    size_t edit_end = offset + new_plain.len - 1;
    size_t start_block_idx = offset / block_size;
    size_t end_block_idx = edit_end / block_size;

    EVP_CIPHER_CTX *ctx;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();

    /* Initialise the en/decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher.
     * In ECB mode, there is no IV. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.bytes, NULL)) handle_openssl_errors();

    /* Needs to be done after EVP_init_ex, because that resets padding */
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    byte_array key_stream_in = alloc_byte_array(block_size);
    byte_array key_stream_out = alloc_byte_array(block_size * (end_block_idx - start_block_idx + 1));
    *((uint64_t *) key_stream_in.bytes) = nonce; // assumes little endian machine

    size_t block_idx;
    uint8_t * key_stream_p = key_stream_out.bytes;
    for (block_idx = start_block_idx ; block_idx <= end_block_idx ; ++block_idx, key_stream_p += block_size) {
        *((uint64_t *) (key_stream_in.bytes + 8)) = block_idx; // assumes little endian machine

        int len = 0;
        if(1 != EVP_EncryptUpdate(ctx, key_stream_p, &len, key_stream_in.bytes, block_size))
            handle_openssl_errors();
        if (len != block_size) {
            fprintf(stderr, "%s: encrypt did not produce output block", __func__);
            exit(-1);
        }
    }

    size_t skip_bytes = offset % block_size;
    size_t new_plain_idx;
    for (new_plain_idx = 0; new_plain_idx <= new_plain.len ; ++new_plain_idx) {
        new_cipher.bytes[offset + new_plain_idx] = new_plain.bytes[new_plain_idx] ^ key_stream_out.bytes[skip_bytes + new_plain_idx];
    }
    free_byte_array(key_stream_in);
    free_byte_array(key_stream_out);
    return new_cipher;
}
