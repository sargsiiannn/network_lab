#ifndef TAGLINK_H
#define TAGLINK_H

#include <stddef.h>
#include <stdint.h>

enum { TAG_BYTES = 16, KEY_BYTES = 32, FRAME_CAP = 65549, CACHE_SIZE = 1024 };
#define NONCE_LIMIT (UINT64_C(1) << 24)

struct selector {
    uint8_t endpoints[2][4];
    unsigned service;
};

struct segment {
    size_t ip_length;
    size_t ip_header;
    size_t tcp_header;
};

struct ticket {
    uint64_t number;
    uint8_t tag[TAG_BYTES];
};

enum frame_type { IGNORE, NEIGHBOR, SEGMENT };
enum frame_type inspect(const uint8_t *frame, size_t length, const struct selector *filter,
                        unsigned sender, struct segment *seg);
int seal(uint8_t *frame, const struct segment *seg, const uint8_t key[KEY_BYTES],
         unsigned sender, uint64_t number);
int unseal(uint8_t *frame, const struct segment *seg, const uint8_t key[KEY_BYTES],
           unsigned sender, uint64_t number);
struct ticket *find_ticket(struct ticket cache[CACHE_SIZE], const uint8_t tag[TAG_BYTES]);

#endif
