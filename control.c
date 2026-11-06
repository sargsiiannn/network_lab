#include "control.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int dial(unsigned role, const char *self, const char *peer, unsigned port)
{
    struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(role ? port : 0) };
    struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (inet_pton(AF_INET, self, &local.sin_addr) != 1 ||
        inet_pton(AF_INET, peer, &remote.sin_addr) != 1)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int yes = 1;
    struct timeval timeout = { .tv_sec = 10 };
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        bind(fd, (struct sockaddr *)&local, sizeof local))
        goto error;

    if (!role) {
        if (!connect(fd, (struct sockaddr *)&remote, sizeof remote))
            return fd;
        goto error;
    }

    if (listen(fd, 1))
        goto error;
    fputs("Listening for the control connection\n", stderr);
    struct sockaddr_in from;
    socklen_t len = sizeof from;
    int connection = accept(fd, (struct sockaddr *)&from, &len);
    if (connection < 0)
        goto error;
    close(fd);
    if (from.sin_addr.s_addr != remote.sin_addr.s_addr) {
        close(connection);
        return -1;
    }
    return connection;

error:
    perror("control connection");
    close(fd);
    return -1;
}

int control_open(struct control *c, unsigned role, const char *self, const char *peer,
                 unsigned port, const char *ca, const char *identity)
{
    static const char label[] = "EXPORTER-taglink-directional-keys-v1";
    *c = (struct control){ .fd = -1 };
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    int success = 0;
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(ctx, "ffdhe3072") ||
        !SSL_CTX_set_num_tickets(ctx, 0) ||
        !SSL_CTX_load_verify_locations(ctx, ca, NULL) ||
        !SSL_CTX_use_certificate_file(ctx, identity, SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, identity, SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(ctx))
        goto finish;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    c->fd = dial(role, self, peer, port);
    c->tls = SSL_new(ctx);
    if (c->fd < 0 || !c->tls || !SSL_set_fd(c->tls, c->fd) ||
        !SSL_set1_host(c->tls, role ? "west.taglink" : "east.taglink"))
        goto finish;

    struct timeval timeout = { .tv_sec = 5 };
    int enabled = 1;
    if (setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
        setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
        setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled))
        goto finish;
    if ((role ? SSL_accept(c->tls) : SSL_connect(c->tls)) != 1 ||
        SSL_get_verify_result(c->tls) != X509_V_OK ||
        SSL_get_negotiated_group(c->tls) != NID_ffdhe3072 ||
        !SSL_export_keying_material(c->tls, &c->keys[0][0], sizeof c->keys,
                                    label, sizeof label - 1, NULL, 0, 0))
        goto finish;

    uint8_t ready = 'R';
    success = role ? SSL_write(c->tls, &ready, 1) == 1 :
        SSL_read(c->tls, &ready, 1) == 1 && ready == 'R';

finish:
    SSL_CTX_free(ctx);
    if (!success) {
        ERR_print_errors_fp(stderr);
        control_close(c);
    }
    return success;
}

void control_close(struct control *c)
{
    SSL_free(c->tls);
    if (c->fd >= 0)
        close(c->fd);
    OPENSSL_cleanse(c, sizeof *c);
    c->fd = -1;
}

int control_send(struct control *c, uint8_t type, const uint8_t tag[TAG_BYTES])
{
    uint8_t message[1 + TAG_BYTES] = {type};
    memcpy(message + 1, tag, TAG_BYTES);
    return SSL_write(c->tls, message, sizeof message) == (int)sizeof message;
}

int control_receive(struct control *c, uint8_t message[1 + TAG_BYTES])
{
    int total = 0;
    while (total < 1 + TAG_BYTES) {
        int read = SSL_read(c->tls, message + total, 1 + TAG_BYTES - total);
        if (read <= 0)
            return 0;
        total += read;
    }
    return 1;
}
