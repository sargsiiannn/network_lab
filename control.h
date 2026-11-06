#ifndef CONTROL_H
#define CONTROL_H
#include "taglink.h"
#include <openssl/ssl.h>

struct control {
    int fd;
    SSL *tls;
    uint8_t keys[2][KEY_BYTES];
};

int control_open(struct control *c, unsigned role, const char *self, const char *peer,
                 unsigned port, const char *ca, const char *identity);
void control_close(struct control *c);
int control_send(struct control *c, uint8_t type, const uint8_t tag[TAG_BYTES]);
int control_receive(struct control *c, uint8_t message[1 + TAG_BYTES]);

#endif
