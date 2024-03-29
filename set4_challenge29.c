#include <stdio.h>
#include <stdlib.h>
#include "cryptopals_mac.h"
#include "sha1.h"
#include <assert.h>

static void check_err(int err) {
    if (err) {
        fprintf(stderr, "SHA1 error: %d\n", err);
        exit(1);
    }
}

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nBreak SHA1 keyed MAC with length extension\n", argv[0]);
        return 1;
    }
    init_random_mac_key(atoi(argv[1]));

    // We do not have access to the key, but we do have access to these.
    byte_array message = cstring_to_bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon");
    byte_array mac = sha1_mac(message);

    // We cannot use sha1_mac ourselves, but we can use check_message_sha1_mac to verify that we have
    // successfully forged a new message and MAC pair.
    assert(check_message_sha1_mac(message, mac));

    // We want to forge a new message and MAC pair in which the message has this at the end.
    byte_array extension = cstring_to_bytes(";admin=true");

    /* Length extension attack
     *
     * The glue-padding in the middle of our counterfeit message varies depending on the length of the key,
     * so we start by assuming a one-byte key and step by a byte at a time. However, the counterfeit MAC that we
     * calculate only varies when the number of 64-byte blocks used for (key || message || padding) changes.
     * That's because the original MAC value that we use to seed the hacked SHA1 state already includes the
     * hash of the correct glue-padding, and we know that at the point where we are adding the extension
     * we are exactly at a multiple of 512 bits. (i.e., 64 bytes)
     *
     * So we only calculate the counterfeit MAC once and just keep stepping the glue padding until we get a
     * hit. Only if the key length gets long enough to increase the number of blocks do we recalculate the
     * counterfeit MAC.
     *
     * If len = byte length of (key || message) then the number of blocks = (len + 72) >> 6
     */
    uint64_t key_len_guess = 1;
    uint64_t num_blocks_guess = (message.len + key_len_guess + 72) >> 6;
    bool broke_the_mac = false;

    while(!broke_the_mac) {
        SHA1Context sha;
        // Sets up internal state of SHA1 context to the same as it would be after hashing
        // (key || message || padding) but with it still able to receive more data.
        check_err(SHA1Reset_hack(&sha, num_blocks_guess, mac.bytes));

        // Adds the extension after the padding that was already applied.
        check_err(SHA1Input(&sha, extension.bytes, extension.len));

        // Finalizes the digest of (key || message || padding || extension), which will include
        // a new layer of padding being applied to the end before hashing.
        byte_array counterfeit_mac = alloc_byte_array(20);
        check_err(SHA1Result(&sha, counterfeit_mac.bytes));

        // We may have already calculated the correct counterfeit MAC, but we don't yet know
        // the value of the glue-padding, so we try different values.
        do {
            byte_array glue_padding = sha1_pad(key_len_guess + message.len);
            byte_array counterfeit_message = append_three_byte_arrays(message, glue_padding, extension);
            if (check_message_sha1_mac(counterfeit_message, counterfeit_mac)) {
                broke_the_mac = true;
            }
            free_byte_arrays(glue_padding, counterfeit_message, NO_BA);
        } while(!(broke_the_mac || num_blocks_guess != (message.len + ++key_len_guess + 72) >> 6));

        // If we are here and broke_the_mac is still false, it means none of the possible key
        // lengths at that number of blocks worked.
        ++num_blocks_guess;
        free_byte_array(counterfeit_mac);
    }
    printf("Attack succeeded!\n");

    free_byte_arrays(message, mac, extension, NO_BA);

    cleanup_random_mac_key();
    return 0;
}
