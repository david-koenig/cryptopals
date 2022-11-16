#include "cryptopals_cbcmac.h"
#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ZERO_REQ (request_v1){0L, 0L, 0L}

static byte_array K;

static const size_t block_size = 16;
static uint8_t zeros[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const byte_array zero_iv = {zeros, block_size};

static const size_t max_digits_long = 19;
static const size_t min_msg_len = 20; // "from=0&to=1&amount=1"
static const size_t max_msg_len = min_msg_len - 3 + 3*max_digits_long;
static const size_t max_tx_len = 2*max_digits_long + 1; // "to:amount"

static const long my_accounts[] = {213, 867, 201, 917};

void init_serverclient(unsigned int seed) {
    init_random_encrypt(seed);
    K = random_128_bits();
}

void cleanup_serverclient() {
    free_byte_array(K);
    cleanup_random_encrypt();
}

static bool account_allowed(long acc) {
    for (int idx = 0 ; idx < sizeof(my_accounts)/sizeof(long) ; idx++) {
        if (acc == my_accounts[idx]) return true;
    }
    return false;
}

static byte_array cbc_mac_iv(const byte_array plain, const byte_array key, const byte_array iv) {
    byte_array cipher = encrypt_aes_128_cbc(plain, key, iv);
    byte_array mac = sub_byte_array(cipher, cipher.len-block_size, cipher.len);
    free_byte_array(cipher);
    return mac;
}

inline byte_array cbc_mac(const byte_array plain, const byte_array key) {
    return cbc_mac_iv(plain, key, zero_iv);
}

byte_array sign_request_v1(request_v1 req) {
    if (!account_allowed(req.from) || !account_allowed(req.to) || !req.amount) {
        return NO_BA;
    }
    byte_array msg = alloc_byte_array(max_msg_len+1);
    msg.len = 1+snprintf(msg.bytes, max_msg_len+1, "from=%ld&to=%ld&amount=%ld", req.from, req.to, req.amount);
    byte_array iv = random_128_bits();
    byte_array mac = cbc_mac_iv(msg, K, iv);
    byte_array signed_msg = append_three_byte_arrays(msg, iv, mac);
    free_byte_array(msg);
    free_byte_array(iv);
    free_byte_array(mac);
    return signed_msg;
}

byte_array sign_request_v2(long from, ...) {
    va_list ap;
    va_start(ap, from);

    transaction tx = va_arg(ap, transaction);

    byte_array msg = alloc_byte_array(max_msg_len);
    msg.len = 1+sprintf(msg.bytes, "from=%ld&tx_list=%ld:%ld", from, tx.to, tx.amount);

    while (tx = va_arg(ap, transaction), tx.amount) {
        byte_array tx_txt = alloc_byte_array(max_tx_len);
        tx_txt.len = 1+sprintf(tx_txt.bytes, "%ld:%ld", tx.to, tx.amount);
        msg.len--; // chop off the null byte
        byte_array join = join_byte_arrays(msg, ';', tx_txt);
        free_byte_array(tx_txt);
        free_byte_array(msg);
        msg = join;
    }
    byte_array mac = cbc_mac(msg, K);
    byte_array signed_msg = append_byte_arrays(msg, mac);
    free_byte_array(msg);
    free_byte_array(mac);
    va_end(ap);
    return signed_msg;
}

// checks that message has valid form "from=#{from_id}&to=#{to_id}&amount=#{amount}"
static request_v1 deserialize_req_v1(byte_array msg) {
    request_v1 req = ZERO_REQ;
    char * from_s = strtok(msg.bytes, "&");
    char * to_s = strtok(NULL, "&");
    char * amount_s = strtok(NULL, "&");
    if (from_s && to_s && amount_s &&
        !strncmp(from_s, "from=", strlen("from=")) &&
        !strncmp(to_s, "to=", strlen("to=")) &&
        !strncmp(amount_s, "amount=", strlen("amount="))) {
        errno = 0;
        req.from = strtol(from_s+strlen("from="), NULL, 10);
        req.to = strtol(to_s+strlen("to="), NULL, 10);
        req.amount = strtol(amount_s+strlen("amount="), NULL, 10);
        if (errno) req = ZERO_REQ;
    }
    return req;
}

bool verify_request_v1(const byte_array signed_msg) {
    if (signed_msg.len < 2*block_size + min_msg_len) {
        return false;
    }
    byte_array mac = sub_byte_array(signed_msg, signed_msg.len-block_size, signed_msg.len);
    byte_array iv = sub_byte_array(signed_msg, signed_msg.len-2*block_size, signed_msg.len-block_size);
    byte_array msg = sub_byte_array(signed_msg, 0, signed_msg.len-2*block_size);
    byte_array mac2 = cbc_mac_iv(msg, K, iv);
    bool ret = false;
    if (byte_arrays_equal(mac, mac2)) {
        request_v1 req = deserialize_req_v1(msg);
        if (req.amount) {
            ret = true;
            printf("Request verified: %ld spacebucks will be sent from account %ld to account %ld\n",
                   req.amount, req.from, req.to);
        }
    }
    free_byte_array(mac2);
    free_byte_array(msg);
    free_byte_array(iv);
    free_byte_array(mac);
    return ret;
}

#define MAX_TRANSACTIONS 64

static bool deserialize_req_v2(byte_array msg) {
    long from;
    transaction tx[MAX_TRANSACTIONS];
    size_t num_tx = 0;

    char *equal_ptr, *semicolon_ptr, *colon_ptr;
    char * tok = msg.bytes;
    char * end;

    // strtok_r and similar functions were stopping at gibberish bits.
    // So I implemented tokenizer with memchr which allows this
    // vulnerability to be exploited. Seems artificial. <shrug>
    do {
        end = memchr(tok, '&', msg.bytes + msg.len - (uint8_t *)tok);
        if (end) *end = 0;

        char *type, *value;
        type = strtok_r(tok, "=", &equal_ptr);
        value = strtok_r(NULL, "", &equal_ptr);

        if (type && value) {
            if (!strcmp(type, "from")) {
                from = strtol(value, NULL, 10);
            } else if (!strcmp(type, "tx_list")) {
                char *tx_str;
                while (tx_str = strtok_r(value, ";", &semicolon_ptr)) {
                    value = NULL;
                    if (num_tx < MAX_TRANSACTIONS) {
                        char *to_str, *amount_str;
                        to_str = strtok_r(tx_str, ":", &colon_ptr);
                        amount_str = strtok_r(NULL, "", &colon_ptr);
                        if (to_str && amount_str) {
                            tx[num_tx].to = strtol(to_str, NULL, 10);
                            tx[num_tx].amount = strtol(amount_str, NULL, 10);
                            num_tx++;
                        }
                    }
                }
            }
        }
        tok = end+1;
    } while (end);

    printf("Request verified: The following transactions will be sent from account %ld:\n", from);
    for (size_t idx = 0; idx < num_tx; idx++) {
        printf("%ld spacebucks to account %ld\n", tx[idx].amount, tx[idx].to);
    }
    return true;
}

bool verify_request_v2(const byte_array signed_msg) {
    if (signed_msg.len < block_size + min_msg_len) {
        return false;
    }
    byte_array mac = sub_byte_array(signed_msg, signed_msg.len-block_size, signed_msg.len);
    byte_array msg = sub_byte_array(signed_msg, 0, signed_msg.len-block_size);
    byte_array mac2 = cbc_mac(msg, K);
    bool ret = byte_arrays_equal(mac, mac2);

    if (ret) {
        ret = deserialize_req_v2(msg);
    }
    free_byte_array(mac2);
    free_byte_array(msg);
    free_byte_array(mac);
    return ret;
}
