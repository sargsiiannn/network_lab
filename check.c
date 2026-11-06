#include "control.h"
#include "taglink.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct selector filter = { .endpoints = {{10, 55, 0, 1}, {10, 55, 0, 2}},
                                        .service = 9090 };

static unsigned folded_sum(const uint8_t *data, size_t n, unsigned sum)
{
    while (n > 1) {
        sum += (unsigned)data[0] * 256 + data[1];
        data += 2;
        n -= 2;
    }
    if (n)
        sum += (unsigned)data[0] * 256;
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 65535);
    return sum;
}

static void check_sums(const uint8_t *f, const struct segment *s)
{
    const uint8_t *ip = f + 14;
    unsigned length = (unsigned)(s->ip_length - s->ip_header);
    assert(folded_sum(ip, s->ip_header, 0) == 65535);
    assert(folded_sum(ip + s->ip_header, length, folded_sum(ip + 12, 8, length + 6)) == 65535);
}

static void packets(unsigned sender, size_t payload)
{
    uint8_t first[FRAME_CAP] = {0}, second[FRAME_CAP], damaged[FRAME_CAP];
    first[12] = 8;
    uint8_t *ip = first + 14, *tcp = ip + 24;
    ip[0] = 0x46;
    ip[2] = (uint8_t)((48 + payload) >> 8);
    ip[3] = (uint8_t)(48 + payload);
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 6;
    ip[20] = 1;
    memcpy(ip + 12, filter.endpoints[sender], 4);
    memcpy(ip + 16, filter.endpoints[1 - sender], 4);
    tcp[sender ? 0 : 2] = 9090 >> 8;
    tcp[sender ? 1 : 3] = 9090 & 255;
    tcp[7] = 82;
    tcp[12] = 0x60;
    tcp[13] = 0x18;
    tcp[20] = 1;
    memset(tcp + 24, 'p', payload);
    const size_t original = 62 + payload;
    const size_t wire = original + TAG_BYTES;
    memcpy(second, first, original);
    struct segment seg;
    uint8_t key[KEY_BYTES] = {3};
    assert(inspect(first, original, &filter, sender, &seg) == SEGMENT);
    assert(!seal(first, &seg, key, sender, 0));
    assert(seal(first, &seg, key, sender, 1));
    assert(seal(second, &seg, key, sender, 2000));
    assert(memcmp(first + original, second + original, TAG_BYTES));
    if (payload)
        assert(memcmp(first + 62, second + 62, payload));
    assert(inspect(second, wire, &filter, sender, &seg) == SEGMENT);
    assert(inspect(second, wire - 1, &filter, sender, &seg) == IGNORE);
    check_sums(second, &seg);
    memcpy(damaged, second, wire);
    damaged[45] ^= 1; /* A TCP sequence number byte */
    assert(!unseal(damaged, &seg, key, sender, 2000));
    assert(!unseal(second, &seg, key, sender, 1999));
    assert(!unseal(second, &seg, key, 1 - sender, 2000));

    struct ticket cache[CACHE_SIZE] = {0};
    cache[0].number = 2000;
    memcpy(cache[0].tag, second + original, TAG_BYTES);
    assert(!find_ticket(cache, first + original));
    struct ticket *ticket = find_ticket(cache, second + original);
    assert(ticket && unseal(second, &seg, key, sender, ticket->number));
    ticket->number = 0;
    assert(!find_ticket(cache, second + original));
    assert(inspect(second, original, &filter, sender, &seg) == SEGMENT);
    check_sums(second, &seg);
    for (size_t i = 62; i < original; ++i)
        assert(second[i] == 'p');
    assert(second[45] == 82 && second[58] == 1 && second[34] == 1);
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        packets(0, 0);
        packets(1, 13);
        packets(0, 1436);
        puts("PASS encryption, header preservation, checksums, nonce separation and ticket lookup");
        return 0;
    }
    assert(argc == 6);
    signal(SIGPIPE, SIG_IGN);
    const unsigned role = (unsigned)atoi(argv[1]);
    struct control c;
    if (!control_open(&c, role, "127.0.0.1", "127.0.0.1",
                      (unsigned)atoi(argv[2]), argv[3], argv[4]))
        return 1;
    uint8_t tag[TAG_BYTES] = {91}, record[1 + TAG_BYTES];
    if (role == 0)
        assert(control_send(&c, 1, tag));
    assert(control_receive(&c, record));
    assert(record[0] == (role ? 1 : 2) && !memcmp(record + 1, tag, sizeof tag));
    if (role == 1)
        assert(control_send(&c, 2, tag));
    assert(memcmp(c.keys[0], c.keys[1], KEY_BYTES));
    FILE *keys = fopen(argv[5], "wb");
    assert(keys && fwrite(c.keys, sizeof c.keys, 1, keys) == 1 && !fclose(keys));
    control_close(&c);
}
