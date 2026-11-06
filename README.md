# TagLink

TagLink is a Linux C prototype for the inline path PC1 ↔ West ↔ East ↔ PC2. West and East secure traffic between them. The endpoints continue to use ordinary TCP.

TagLink uses mutual TLS 1.3 with the **ffdhe3072** group for ephemeral finite-field Diffie–Hellman. The TLS exporter produces distinct 256-bit AES keys for each direction. The TLS connection also synchronizes per-packet counters using the GCM authentication tags. The data frames themselves travel directly over the Ethernet transit link.

## Protected packet format

| Location | Layout |
| --- | --- |
| Endpoint LANs | Ethernet / IPv4 / TCP / original payload |
| Direct transit link | Ethernet / IPv4 / TCP / ciphertext / 16-byte GCM tag |

IPv4 total length and the IPv4 and TCP checksums change to reflect the tag. The original addresses, ports, sequence numbers, flags, options, and other header fields remain in place. The canonical IPv4/TCP headers are authenticated as AES-GCM associated data. Control segments with an empty payload receive a tag over empty plaintext and their headers. The receiver authenticates before restoring the payload, removing the tag, and recalculating checksums.

## How each nonce is recovered

1. The sender increments its directional packet counter and builds a 12-byte nonce from the four-byte prefix `54 4c 01 direction` and the eight-byte big-endian counter. An endpoint TCP retransmission spends a new counter.
2. The sender seals the packet and announces its 16-byte tag over the existing authenticated TLS control connection. The receiver counts announcements in TLS stream order. It stores the tag with that announcement's counter and acknowledges the tag.
3. The sender emits the original IPv4/TCP frame with the ciphertext and tag after the acknowledgment. The receiver looks up the tag, rebuilds the nonce, verifies AES-GCM, and consumes the ticket only if verification succeeds.
4. A replay has no unused ticket after a successful receipt. Raw packet loss leaves an unused ticket that ages out after 1024 incoming announcements. Reordering is supported while a ticket is retained.

There is one outstanding announcement per direction. Every protected packet requires a control round trip, which makes the design suitable for a dedicated local laboratory link. The control stream carries tag announcements and acknowledgments, while the protected TCP data path carries only the original packet structure and the appended tag. Both devices must restart after a control failure or a directional key reaches its 2²⁴-packet limit. Fresh handshakes reset the counters with fresh keys.

## Build and verify

On Ubuntu or Debian with OpenSSL 3.x:

```bash
sudo apt install build-essential libssl-dev openssl iproute2 ethtool tcpdump python3
make test
sudo make integration
```

The unprivileged target checks packet transformations, headers, checksums, wrong nonces and directions, ticket consumption, mutual certificate trust, and matching fresh keys across successive TLS handshakes. The privileged integration target creates and cleans up four network namespaces, exchanges multi-segment application data in both directions, and compares LAN and transit captures for header preservation and exactly 16 bytes of expansion. The included GitHub Actions workflow runs both targets on Linux.

## Manual demo

Give PC1 `10.55.0.1/24` and PC2 `10.55.0.2/24`. Put the endpoint and device LAN interfaces at MTU 1484 and the transit interfaces at MTU 1500. Configure only the device transit interfaces with management addresses `172.27.9.1/30` for West and `172.27.9.2/30` for East. Use dedicated links with no kernel bridge or parallel bypass. Bring all links up and disable offloads such as `sudo ethtool -K INTERFACE tx off tso off gro off gso off`.

Run `./keys.sh` once. Install `keys/root.pem` on both devices and give each device its own private role PEM. Keep the private PEMs out of Git. Run `make` on both devices. The following commands assume the device interfaces are named `lan` and `wire`.

```bash
# East first
sudo ./build/taglink east lan wire 172.27.9.2 172.27.9.1 7444 \
    10.55.0.1 10.55.0.2 9090 keys/root.pem keys/east.pem

# West within ten seconds
sudo ./build/taglink west lan wire 172.27.9.1 172.27.9.2 7444 \
    10.55.0.1 10.55.0.2 9090 keys/root.pem keys/west.pem
```

Wait for both devices to print `ready`. Run `python3 -m http.server 9090 --bind 10.55.0.2` on PC2 and `curl http://10.55.0.2:9090/` on PC1. Capture port 9090 on the `wire` interface to inspect the protected form.

The relay selects the configured PC1 and PC2 addresses and service port. It also forwards ARP between the endpoints so they can learn each other's MAC addresses. ARP is outside the authenticated channel. The prototype assumes trusted LANs, untagged Ethernet, unfragmented IPv4, no IPv4 source routing, and a direct transit link without a TCP-aware middlebox. A TCP-aware middlebox could interpret the tag as application bytes because the transit sequence numbers stay unchanged.

## Publish

```bash
git init -b main
git add .
git commit -m "Implement TagLink inline prototype"
gh auth login
gh repo create taglink --source=. --private --remote=origin --push
gh repo view --json url --jq .url
```

Use the visibility required by the course and make sure the instructor has access to the printed URL.

## References

- [OpenSSL TLS group configuration](https://docs.openssl.org/3.4/man3/SSL_CTX_set1_curves/)
- [OpenSSL TLS exporter](https://docs.openssl.org/3.3/man3/SSL_export_keying_material/)
- [OpenSSL EVP AEAD interface](https://docs.openssl.org/3.4/man3/EVP_EncryptInit/)
- [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html)
