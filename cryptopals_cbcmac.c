#include "cryptopals_cbcmac.h"
#include "cryptopals_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ZERO_REQ (request){0L, 0L, 0L}

static byte_array K;
static byte_array zero_iv;

static const size_t max_digits_long = 19;
static const size_t block_size = 16;
static const size_t min_msg_len = 20; // "from=0&to=1&amount=1"
static const size_t max_msg_len = min_msg_len - 3 + 3*max_digits_long;

static const long my_accounts[] = {213, 867};

void init_serverclient(unsigned int seed) {
    init_random_encrypt(seed);
    K = random_128_bits();
    zero_iv = alloc_byte_array(block_size);
}

void cleanup_serverclient() {
    free_byte_array(K);
    free_byte_array(zero_iv);
    cleanup_random_encrypt();
}

static bool account_allowed(long acc) {
    for (int idx = 0 ; idx < sizeof(my_accounts)/sizeof(long) ; idx++) {
        if (acc == my_accounts[idx]) return true;
    }
    return false;
}

static byte_array cbc_mac_iv(const byte_array plain, const byte_array iv) {
    byte_array cipher = encrypt_aes_128_cbc(plain, K, iv);
    byte_array mac = sub_byte_array(cipher, cipher.len-block_size, cipher.len);
    free_byte_array(cipher);
    return mac;
}

static inline byte_array cbc_mac(const byte_array plain) {
    return cbc_mac_iv(plain, zero_iv);
}

static byte_array serialize_req(request req) {
    byte_array msg = alloc_byte_array(max_msg_len+1);
    msg.len = snprintf(msg.bytes, max_msg_len+1, "from=%ld&to=%ld&amount=%ld", req.from, req.to, req.amount);
    return msg;
}

byte_array sign_request_iv(request req) {
    if (!account_allowed(req.from) || !account_allowed(req.to) || !req.amount) {
        return NO_BA;
    }
    byte_array msg = serialize_req(req);
    byte_array iv = random_128_bits();
    byte_array mac = cbc_mac_iv(msg, iv);
    byte_array signed_msg = append_three_byte_arrays(msg, iv, mac);
    free_byte_array(msg);
    free_byte_array(iv);
    free_byte_array(mac);
    return signed_msg;
}

byte_array sign_request(request req) {
    if (!account_allowed(req.from) || !account_allowed(req.to) || !req.amount) {
        return NO_BA;
    }
    byte_array msg = serialize_req(req);
    byte_array mac = cbc_mac(msg);
    byte_array signed_msg = append_byte_arrays(msg, mac);
    free_byte_array(msg);
    free_byte_array(mac);
    return signed_msg;
}

// checks that message has valid form "from=#{from_id}&to=#{to_id}&amount=#{amount}"
static request deserialize_req(byte_array msg) {
    request req = ZERO_REQ;
    byte_array m = append_null_byte(msg);
    char * from_s = strtok(m.bytes, "&");
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
    free_byte_array(m);
    return req;
}

bool verify_request_iv(const byte_array signed_msg) {
    if (signed_msg.len < 2*block_size + min_msg_len) {
        return false;
    }
    byte_array mac = sub_byte_array(signed_msg, signed_msg.len-block_size, signed_msg.len);
    byte_array iv = sub_byte_array(signed_msg, signed_msg.len-2*block_size, signed_msg.len-block_size);
    byte_array msg = sub_byte_array(signed_msg, 0, signed_msg.len-2*block_size);
    request req = deserialize_req(msg);
    bool ret;
    if (!req.amount) ret = false;
    byte_array mac2 = cbc_mac_iv(msg, iv);
    ret = byte_arrays_equal(mac, mac2);

    if (ret) {
        printf("Request verified: %ld spacebucks will be sent from account %ld to account %ld\n",
               req.amount, req.from, req.to);
    }
    free_byte_array(mac2);
    free_byte_array(msg);
    free_byte_array(iv);
    free_byte_array(mac);
    return ret;
}

bool verify_request(const byte_array signed_msg) {
    if (signed_msg.len < block_size + min_msg_len) {
        return false;
    }
    byte_array mac = sub_byte_array(signed_msg, signed_msg.len-block_size, signed_msg.len);
    byte_array msg = sub_byte_array(signed_msg, 0, signed_msg.len-block_size);
    request req = deserialize_req(msg);
    bool ret;
    if (!req.amount) ret = false;
    byte_array mac2 = cbc_mac(msg);
    ret = byte_arrays_equal(mac, mac2);

    if (ret) {
        printf("Request verified: %ld spacebucks will be sent from account %ld to account %ld\n",
               req.amount, req.from, req.to);
    }
    free_byte_array(mac2);
    free_byte_array(msg);
    free_byte_array(mac);
    return ret;
}
