#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* Print all of the plaintext guess byte arrays, using '*' in place of null bytes for readability. */
void print_guesses(byte_array* guesses, size_t num_plaintexts) {
    size_t guess_idx, ba_idx;
    for (guess_idx = 0 ; guess_idx < num_plaintexts ; ++guess_idx) {
        printf("%2li: ", guess_idx);
        for (ba_idx = 0 ; ba_idx < guesses[guess_idx].len ; ++ba_idx) {
            printf("%c", guesses[guess_idx].bytes[ba_idx] ? guesses[guess_idx].bytes[ba_idx] : '*');
        }
        printf("\n");
    }
}

/* For plaintext number plain_num, set character at position plain_pos to c. Use the known XOR-ed plaintexts
 * to set the bytes in every other plaintext at the same position. You can overwrite an old guess by just
 * calling this again for the same value of plain_pos.
 */
void guess(byte_array xored_plaintexts[][40], byte_array guesses[], size_t num_plaintexts, size_t plain_num, size_t plain_pos, uint8_t c) {
    size_t plain_idx;
    guesses[plain_num].bytes[plain_pos] = c;
    for (plain_idx = 0 ; plain_idx < plain_num ; ++plain_idx) {
        if (plain_pos < guesses[plain_idx].len)
            guesses[plain_idx].bytes[plain_pos] = guesses[plain_num].bytes[plain_pos] ^ xored_plaintexts[plain_idx][plain_num].bytes[plain_pos];
    }
    for (plain_idx = plain_num + 1 ; plain_idx < num_plaintexts ; ++plain_idx) {
        if (plain_pos < guesses[plain_idx].len)
            guesses[plain_idx].bytes[plain_pos] = guesses[plain_num].bytes[plain_pos] ^ xored_plaintexts[plain_num][plain_idx].bytes[plain_pos];
    }
}

/* Like the previous function but don't actually record the guesses. Just score them based on the percent of
 * implied bytes that would be alphabetical characters or spaces.
 */
double score_guess(byte_array xored_plaintexts[][40], byte_array guesses[], size_t num_plaintexts, size_t plain_num, size_t plain_pos, uint8_t c) {
    size_t num_good_chars = 0;
    size_t total_chars = 0;
    size_t plain_idx;
    for (plain_idx = 0 ; plain_idx < plain_num ; ++plain_idx) {
        if (plain_pos < guesses[plain_idx].len) {
            uint8_t ch = c ^ xored_plaintexts[plain_idx][plain_num].bytes[plain_pos];
            if (isalpha(ch) || ch == ' ') ++num_good_chars;
            ++total_chars;
        }
    }
    for (plain_idx = plain_num + 1 ; plain_idx < num_plaintexts ; ++plain_idx) {
        if (plain_pos < guesses[plain_idx].len) {
            uint8_t ch = c ^ xored_plaintexts[plain_num][plain_idx].bytes[plain_pos];
            if (isalpha(ch) || ch == ' ') ++num_good_chars;
            ++total_chars;
        }
    }
    return num_good_chars / (double) total_chars;
}

void print_freq_chart(size_t freq[]) {
    size_t idx;
    // only printed top half because bottom half was all zeroes
    for (idx = 0 ; idx < 128 ; ++idx) {
        printf("0x%02lx\t%li\n", idx, freq[idx]);
    }
}

int main(int argc, char ** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s seed\nCrack CTR cipher with identical key streams\n", argv[0]);
        return 1;
    }
    init_random_encrypt(atoi(argv[1]));

    char * plaintexts[] = {
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
    };
    const size_t num_plaintexts = sizeof(plaintexts)/sizeof(char *);
    byte_array ciphertexts[num_plaintexts];
    byte_array xored_plaintexts[num_plaintexts][num_plaintexts];
    byte_array plaintext_guesses[num_plaintexts];

    size_t * byte_freq = calloc(256, sizeof(size_t));

    size_t idx, a, b;
    size_t longest_plaintext_len = 0;

    for (idx = 0 ; idx < num_plaintexts ; ++idx) {
        byte_array plain = base64_to_bytes(plaintexts[idx]);
        ciphertexts[idx] = encrypt_ctr_mystery_key(plain);
        free_byte_array(plain);
        plaintext_guesses[idx] = alloc_byte_array(ciphertexts[idx].len);
        if (ciphertexts[idx].len > longest_plaintext_len)
            longest_plaintext_len = ciphertexts[idx].len;
    }

    bool guessed_position[longest_plaintext_len];
    for (idx = 0 ; idx < longest_plaintext_len ; ++idx) {
        guessed_position[idx] = false;
    }
    
    /* Xor all cipher pairs together to cancel out key streams and get xors of plaintexts.
     * Note that we are only allocating byte arrays at xored_plaintexts[a][b] when a < b.
     * Also captured byte frequency histogram for looking at patterns. It is not used
     * in final implementation but was helpful along the way.
     */
    for (a = 0 ; a < num_plaintexts - 1 ; ++a) {
        for (b = a + 1 ; b < num_plaintexts ; ++b) {
            xored_plaintexts[a][b] = xor_byte_arrays(NO_BA, ciphertexts[a], ciphertexts[b]);
            for (idx = 0; idx < xored_plaintexts[a][b].len ; ++idx) {
                uint8_t byte = xored_plaintexts[a][b].bytes[idx];
                ++byte_freq[byte];
            }
        }
    }

    /* The key idea: 0x45 byte is highly likely to be an xor of 'e' and ' ' (space character).
     * When you come across it, score both 'e' and ' ' in the same spot and take the better one.
     * All but one of these guesses will be correct, and it will fill in most of the plaintext bytes.
     */
    printf("Assuming 0x45 is always XOR of 'e' and space character...\n\n");
    for (a = 0 ; a < num_plaintexts - 1 ; ++a) {
        for (b = a + 1 ; b < num_plaintexts ; ++b) {
            for (idx = 0; idx < xored_plaintexts[a][b].len ; ++idx) {
                uint8_t byte = xored_plaintexts[a][b].bytes[idx];
                if (!guessed_position[idx] && byte == 0x45) {
                    if (score_guess(xored_plaintexts, plaintext_guesses, num_plaintexts, a, idx, ' ') >
                        score_guess(xored_plaintexts, plaintext_guesses, num_plaintexts, a, idx, ' ' ^ byte)) {
                        guess(xored_plaintexts, plaintext_guesses, num_plaintexts, a, idx, ' ');
                    } else {
                        guess(xored_plaintexts, plaintext_guesses, num_plaintexts, a, idx, ' ' ^ byte);
                    }
                    guessed_position[idx] = true;
                }                
            }
        }
    }

    print_guesses(plaintext_guesses, num_plaintexts);
    printf("\nPositions still unguessed: ");
    for (idx = 0 ; idx < longest_plaintext_len ; ++idx) {
        if (!guessed_position[idx])
            printf("%li ", idx);
    }
    printf("\n\n");

    printf("Manual guessing to fix errors and fill in rest of unknown bytes.\n\n");
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 29, 27, 'u');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 29, 30, 't');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 30, 0, 'T');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 6, 31, 'd');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 27, 32, 'd');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 4, 33, 'e');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 4, 34, 'a');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 4, 35, 'd');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 37, 36, 'n');
    guess(xored_plaintexts, plaintext_guesses, num_plaintexts, 37, 37, ',');

    print_guesses(plaintext_guesses, num_plaintexts);

    /* clean up */
    for (a = 0 ; a < num_plaintexts - 1 ; ++a) {
        for (b = a + 1 ; b < num_plaintexts ; ++b) {
            free_byte_array(xored_plaintexts[a][b]);
        }
    }

    for (idx = 0 ; idx < num_plaintexts ; ++idx) {
        free_byte_arrays(ciphertexts[idx], plaintext_guesses[idx], NO_BA);
    }
    free(byte_freq);
    cleanup_random_encrypt();
    return 0;
}
