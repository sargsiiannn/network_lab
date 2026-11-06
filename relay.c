#include "control.h"
#include "taglink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { ANNOUNCE = 1, ACKNOWLEDGE = 2 };

struct interface {
    int fd;
    int index;
    unsigned mtu;
};

struct relay {
    struct control control;
    struct interface lan, transit;
    struct selector filter;
    unsigned role;
    uint64_t outgoing, incoming;
    struct ticket tickets[CACHE_SIZE];
    uint8_t waiting[FRAME_CAP];
    size_t waiting_size;
    time_t deadline;
    unsigned long encrypted, restored, rejected, errors;
};

static volatile sig_atomic_t stop_requested;

static void stop(int signum)
{
    (void)signum;
    stop_requested = 1;
}

static time_t monotonic_seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec;
}

static int attach(struct interface *iface, const char *name)
{
    struct ifreq request = {0};
    if (strlen(name) >= sizeof request.ifr_name)
        return 0;
    memcpy(request.ifr_name, name, strlen(name) + 1);
    const int index = (int)if_nametoindex(name);
    if (!index)
        return 0;
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0)
        return 0;
    struct sockaddr_ll address = { .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = index };
    struct packet_mreq membership = { .mr_ifindex = index, .mr_type = PACKET_MR_PROMISC };
    if (bind(fd, (struct sockaddr *)&address, sizeof address) ||
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, sizeof membership) ||
        ioctl(fd, SIOCGIFMTU, &request) || request.ifr_mtu < 68) {
        close(fd);
        return 0;
    }
    *iface = (struct interface){fd, index, (unsigned)request.ifr_mtu};
    return 1;
}

static void emit(struct relay *r, const struct interface *iface, uint8_t *data, size_t n)
{
    struct sockaddr_ll target = {
        .sll_family = AF_PACKET, .sll_ifindex = iface->index, .sll_halen = ETH_ALEN
    };
    memcpy(&target.sll_protocol, data + 12, 2);
    memcpy(target.sll_addr, data, ETH_ALEN);
    if (n < ETH_ZLEN) {
        memset(data + n, 0, ETH_ZLEN - n);
        n = ETH_ZLEN;
    }
    if (sendto(iface->fd, data, n, MSG_DONTWAIT,
               (struct sockaddr *)&target, sizeof target) != (ssize_t)n) {
        if (!r->errors++)
            perror("forward Ethernet frame");
    }
}

static int handle_control(struct relay *r)
{
    uint8_t message[1 + TAG_BYTES];
    if (!control_receive(&r->control, message))
        return 0;
    const uint8_t *tag = message + 1;
    if (message[0] == ANNOUNCE) {
        if (r->incoming == NONCE_LIMIT || find_ticket(r->tickets, tag))
            return 0;
        ++r->incoming;
        struct ticket *slot = &r->tickets[(r->incoming - 1) % CACHE_SIZE];
        slot->number = r->incoming;
        memcpy(slot->tag, tag, TAG_BYTES);
        return control_send(&r->control, ACKNOWLEDGE, tag);
    }
    if (message[0] != ACKNOWLEDGE || !r->waiting_size ||
        memcmp(tag, r->waiting + r->waiting_size - TAG_BYTES, TAG_BYTES))
        return 0;
    emit(r, &r->transit, r->waiting, r->waiting_size);
    r->waiting_size = 0;
    ++r->encrypted;
    return r->outgoing < NONCE_LIMIT;
}

static int handle_frame(struct relay *r, int from_transit)
{
    uint8_t frame[FRAME_CAP];
    const struct interface *input = from_transit ? &r->transit : &r->lan;
    const struct interface *output = from_transit ? &r->lan : &r->transit;
    const unsigned sender = from_transit ? 1 - r->role : r->role;
    struct sockaddr_ll source = {0};
    socklen_t address_len = sizeof source;
    ssize_t count = recvfrom(input->fd, frame, sizeof frame, MSG_TRUNC | MSG_DONTWAIT,
                             (struct sockaddr *)&source, &address_len);
    if (count < 0)
        return errno == EAGAIN || errno == EINTR;
    if (source.sll_pkttype == PACKET_OUTGOING || (size_t)count > sizeof frame)
        return 1;

    struct segment seg;
    enum frame_type type = inspect(frame, (size_t)count, &r->filter, sender, &seg);
    if (type == IGNORE)
        return 1;
    if (type == NEIGHBOR) {
        emit(r, output, frame, 42);
        return 1;
    }
    if (!from_transit) {
        if (seg.ip_length + TAG_BYTES > output->mtu) {
            ++r->rejected;
            return 1;
        }
        if (r->outgoing == NONCE_LIMIT || r->waiting_size ||
            !seal(frame, &seg, r->control.keys[sender], sender, ++r->outgoing))
            return 0;
        r->waiting_size = 14 + seg.ip_length + TAG_BYTES;
        memcpy(r->waiting, frame, r->waiting_size);
        r->deadline = monotonic_seconds() + 5;
        return control_send(&r->control, ANNOUNCE, r->waiting + r->waiting_size - TAG_BYTES);
    }

    if (seg.ip_length < seg.ip_header + seg.tcp_header + TAG_BYTES ||
        seg.ip_length - TAG_BYTES > output->mtu) {
        ++r->rejected;
        return 1;
    }
    struct ticket *ticket = find_ticket(r->tickets, frame + 14 + seg.ip_length - TAG_BYTES);
    if (!ticket || !unseal(frame, &seg, r->control.keys[sender], sender, ticket->number)) {
        ++r->rejected;
        return 1;
    }
    ticket->number = 0;
    emit(r, output, frame, 14 + seg.ip_length - TAG_BYTES);
    ++r->restored;
    return 1;
}

static int run(struct relay *r)
{
    struct pollfd fds[] = {
        { .fd = r->control.fd, .events = POLLIN },
        { .fd = r->transit.fd, .events = POLLIN },
        { .fd = r->lan.fd, .events = POLLIN }
    };
    while (!stop_requested) {
        fds[2].events = r->waiting_size ? 0 : POLLIN;
        const int buffered = SSL_pending(r->control.tls) > 0;
        if (poll(fds, 3, buffered ? 0 : 500) < 0) {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (buffered || (fds[0].revents & POLLIN))
            if (!handle_control(r))
                return 0;
        if (r->waiting_size && monotonic_seconds() >= r->deadline)
            return 0;
        if ((fds[0].revents | fds[1].revents | fds[2].revents) & (POLLERR | POLLHUP | POLLNVAL))
            return 0;
        if ((fds[1].revents & POLLIN) && !handle_frame(r, 1))
            return 0;
        if ((fds[2].revents & POLLIN) && !handle_frame(r, 0))
            return 0;
    }
    return 1;
}

static unsigned port(const char *text)
{
    char *end;
    unsigned long n = strtoul(text, &end, 10);
    return !*text || *end || n > 65535 ? 0 : (unsigned)n;
}

int main(int argc, char **argv)
{
    if (argc != 12 || (strcmp(argv[1], "west") && strcmp(argv[1], "east"))) {
        fprintf(stderr, "Usage: %s west|east LAN TRANSIT LOCAL_CONTROL_IP PEER_CONTROL_IP "
                "CONTROL_PORT PC1_IP PC2_IP SERVICE_PORT CA_PEM IDENTITY_PEM\n", argv[0]);
        return 2;
    }
    struct relay state = {
        .lan.fd = -1, .transit.fd = -1, .role = !strcmp(argv[1], "east"),
        .filter.service = port(argv[9])
    };
    unsigned control_port = port(argv[6]);
    uint8_t local[4], peer[4];
    if (!state.filter.service || !control_port || !strcmp(argv[2], argv[3]) ||
        inet_pton(AF_INET, argv[4], local) != 1 || inet_pton(AF_INET, argv[5], peer) != 1 ||
        !memcmp(local, peer, 4) ||
        inet_pton(AF_INET, argv[7], state.filter.endpoints[0]) != 1 ||
        inet_pton(AF_INET, argv[8], state.filter.endpoints[1]) != 1 ||
        !memcmp(state.filter.endpoints[0], state.filter.endpoints[1], 4)) {
        fputs("Invalid interfaces, IPv4 addresses or ports\n", stderr);
        return 2;
    }
    for (unsigned i = 0; i < 2; ++i)
        if (!memcmp(local, state.filter.endpoints[i], 4) ||
            !memcmp(peer, state.filter.endpoints[i], 4)) {
            fputs("Control and endpoint addresses must be distinct\n", stderr);
            return 2;
        }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    int status = 1;
    if (!attach(&state.lan, argv[2]) || !attach(&state.transit, argv[3])) {
        perror("attach raw Ethernet socket");
    } else if (state.transit.mtu < state.lan.mtu + TAG_BYTES) {
        fputs("Transit MTU needs at least 16 bytes of headroom\n", stderr);
    } else if (control_open(&state.control, state.role, argv[4], argv[5], control_port,
                            argv[10], argv[11])) {
        fprintf(stderr, "%s ready (TLS 1.3 / ffdhe3072)\n", argv[1]);
        status = !run(&state);
        if (status && !stop_requested)
            fputs("Session ended. Restart both devices to establish fresh keys.\n", stderr);
        fprintf(stderr, "Protected=%lu Restored=%lu Rejected=%lu SendErrors=%lu\n",
                state.encrypted, state.restored, state.rejected, state.errors);
        control_close(&state.control);
    } else {
        fputs("Secure control handshake failed\n", stderr);
    }
    if (state.lan.fd >= 0)
        close(state.lan.fd);
    if (state.transit.fd >= 0)
        close(state.transit.fd);
    return status;
}
