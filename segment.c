#include "taglink.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

static unsigned get16(const uint8_t *p)
{
    return (unsigned)p[0] * 256 + p[1];
}

static void put16(uint8_t *p, unsigned value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static unsigned accumulate(const uint8_t *bytes, size_t count, unsigned sum)
{
    for (size_t i = 0; i < count; ++i)
        sum += (unsigned)bytes[i] << ((i & 1) ? 0 : 8);
    return sum;
}

static unsigned complement(unsigned sum)
{
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum & 0xffff;
}

static void update_lengths(uint8_t *ip, size_t ihl, size_t length)
{
    uint8_t *tcp = ip + ihl;
    const unsigned tcp_size = (unsigned)(length - ihl);
    put16(ip + 2, (unsigned)length);
    put16(ip + 10, 0);
    put16(ip + 10, complement(accumulate(ip, ihl, 0)));
    put16(tcp + 16, 0);
    const unsigned pseudo = accumulate(ip + 12, 8, tcp_size + 6);
    put16(tcp + 16, complement(accumulate(tcp, tcp_size, pseudo)));
}

enum frame_type inspect(const uint8_t *frame, size_t length, const struct selector *filter,
                        unsigned sender, struct segment *seg)
{
    if (length < 14 || length > FRAME_CAP)
        return IGNORE;
    const uint8_t *p = frame + 14;
    const unsigned type = get16(frame + 12);
    const uint8_t *source = filter->endpoints[sender];
    const uint8_t *destination = filter->endpoints[1 - sender];

    if (type == 0x0806 && length >= 42 && get16(p) == 1 && get16(p + 2) == 0x0800 &&
        p[4] == 6 && p[5] == 4 && (get16(p + 6) == 1 || get16(p + 6) == 2) &&
        !memcmp(p + 14, source, 4) && !memcmp(p + 24, destination, 4))
        return NEIGHBOR;

    if (type != 0x0800 || length < 54 || (p[0] >> 4) != 4 || p[9] != 6 ||
        (get16(p + 6) & 0xbfff) || memcmp(p + 12, source, 4) ||
        memcmp(p + 16, destination, 4))
        return IGNORE;

    const size_t ihl = 4u * (p[0] & 15);
    const size_t total = get16(p + 2);
    if (ihl < 20 || total < ihl + 20 || total > length - 14)
        return IGNORE;
    const uint8_t *tcp = p + ihl;
    const size_t thl = 4u * (tcp[12] >> 4);
    if (thl < 20 || total < ihl + thl || get16(tcp + (sender ? 0 : 2)) != filter->service)
        return IGNORE;

    *seg = (struct segment){total, ihl, thl};
    return SEGMENT;
}

static int crypt_segment(uint8_t *frame, const struct segment *s, const uint8_t key[KEY_BYTES],
                         unsigned sender, uint64_t number, int encrypt)
{
    const size_t headers = s->ip_header + s->tcp_header;
    if (!number || number > NONCE_LIMIT ||
        (encrypt && s->ip_length > 65535 - TAG_BYTES) ||
        (!encrypt && s->ip_length < headers + TAG_BYTES))
        return 0;

    const size_t original = encrypt ? s->ip_length : s->ip_length - TAG_BYTES;
    const int bytes = (int)(original - headers);
    uint8_t *ip = frame + 14;
    uint8_t *payload = ip + headers;
    uint8_t *tag = payload + bytes;
    uint8_t nonce[12] = { 'T', 'L', 1, (uint8_t)sender };
    for (unsigned i = 0; i < 8; ++i)
        nonce[11 - i] = (uint8_t)(number >> (8 * i));

    uint8_t aad[120];
    memcpy(aad, ip, headers);
    put16(aad + 2, (unsigned)original);
    put16(aad + 10, 0);
    put16(aad + s->ip_header + 16, 0);

    uint8_t scratch[65535];
    int count, final;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ok = ctx &&
        EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce, encrypt) &&
        EVP_CipherUpdate(ctx, NULL, &count, aad, (int)headers) &&
        EVP_CipherUpdate(ctx, scratch, &count, payload, bytes) && count == bytes &&
        (encrypt || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_BYTES, tag)) &&
        EVP_CipherFinal_ex(ctx, scratch + count, &final) && final == 0 &&
        (!encrypt || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_BYTES, tag));

    if (ok) {
        memcpy(payload, scratch, (size_t)bytes);
        update_lengths(ip, s->ip_header, original + (encrypt ? TAG_BYTES : 0));
    }
    OPENSSL_cleanse(scratch, (size_t)bytes);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int seal(uint8_t *frame, const struct segment *seg, const uint8_t key[KEY_BYTES],
         unsigned sender, uint64_t number)
{
    return crypt_segment(frame, seg, key, sender, number, 1);
}

int unseal(uint8_t *frame, const struct segment *seg, const uint8_t key[KEY_BYTES],
           unsigned sender, uint64_t number)
{
    return crypt_segment(frame, seg, key, sender, number, 0);
}

struct ticket *find_ticket(struct ticket cache[CACHE_SIZE], const uint8_t tag[TAG_BYTES])
{
    for (size_t i = 0; i < CACHE_SIZE; ++i)
        if (cache[i].number && !memcmp(cache[i].tag, tag, TAG_BYTES))
            return &cache[i];
    return NULL;
}
