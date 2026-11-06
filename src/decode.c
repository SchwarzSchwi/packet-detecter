/* SPDX-License-Identifier: GPL-2.0-only
 * Small, independent input adapter for the extracted packet predicates.
 * Payload boundaries follow the uploaded Suricata decode-tcp.c,
 * decode-udp.c and the ordinary eight-byte decode-icmpv4.c cases.
 * This is not Suricata's full decoder: no checksum validation, IP/TCP
 * reassembly, tunnel decoding or application-protocol parsing is performed.
 */
#include "detector.h"

#include <limits.h>
#include <string.h>

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t le32(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | p[0];
}

static int skip(const char **reason, const char *message)
{
    if (reason != NULL)
        *reason = message;
    return 0;
}

static bool ipv6_family(uint32_t family)
{
    /* AF_INET6 differs between the platforms that write DLT_NULL files. */
    return family == 10 || family == 24 || family == 28 || family == 30;
}

int decode_packet(const uint8_t *data, size_t caplen, uint32_t wirelen,
                  uint32_t linktype, uint64_t ts_ns, PacketView *packet,
                  const char **skip_reason)
{
    size_t offset = 0;
    uint16_t protocol = 0x0800;

    if (skip_reason != NULL)
        *skip_reason = NULL;
    if (packet == NULL)
        return skip(skip_reason, "invalid_packet_output");
    memset(packet, 0, sizeof(*packet));
    if (data == NULL || caplen == 0)
        return skip(skip_reason, "empty_packet");
    if (caplen > UINT32_MAX || caplen > wirelen)
        return skip(skip_reason, "invalid_capture_length");

    switch (linktype) {
        case 1: /* LINKTYPE_ETHERNET */
            if (caplen < 14)
                return skip(skip_reason, "truncated_ethernet_header");
            protocol = be16(data + 12);
            offset = 14;
            break;
        case 113: /* LINKTYPE_LINUX_SLL */
            if (caplen < 16)
                return skip(skip_reason, "truncated_sll_header");
            if (be16(data + 4) > 8)
                return skip(skip_reason, "invalid_sll_header");
            protocol = be16(data + 14);
            offset = 16;
            break;
        case 276: /* LINKTYPE_LINUX_SLL2 */
            if (caplen < 20)
                return skip(skip_reason, "truncated_sll2_header");
            if (be16(data + 2) != 0 || data[11] > 8)
                return skip(skip_reason, "invalid_sll2_header");
            protocol = be16(data);
            offset = 20;
            break;
        case 0: /* DLT_NULL: family in the capturing host's byte order */
        case 108: { /* LINKTYPE_LOOP: family in network byte order */
            if (caplen < 4)
                return skip(skip_reason, "truncated_null_header");
            uint32_t family_be = be32(data);
            uint32_t family_le = linktype == 0 ? le32(data) : family_be;
            if (family_be != 2 && family_le != 2) {
                if (ipv6_family(family_be) || ipv6_family(family_le))
                    return skip(skip_reason, "ipv6_unsupported");
                return skip(skip_reason, "non_ipv4");
            }
            offset = 4;
            break;
        }
        case 12: /* Some legacy writers serialize their DLT_RAW value. */
        case 101: /* LINKTYPE_RAW */
        case 228: /* LINKTYPE_IPV4 */
            break;
        case 229: /* LINKTYPE_IPV6 */
            return skip(skip_reason, "ipv6_unsupported");
        default:
            return skip(skip_reason, "unsupported_linktype");
    }

    /* A VLAN header follows the link-layer protocol field. This also handles
     * captures that preserve a VLAN tag behind a Linux cooked header. */
    unsigned vlan_count = 0;
    while (protocol == 0x8100 || protocol == 0x88a8 || protocol == 0x9100) {
        if (++vlan_count > 2)
            return skip(skip_reason, "too_many_vlan_tags");
        if (caplen - offset < 4)
            return skip(skip_reason, "truncated_vlan_header");
        protocol = be16(data + offset + 2);
        offset += 4;
    }
    if (protocol == 0x86dd)
        return skip(skip_reason, "ipv6_unsupported");
    if (protocol != 0x0800)
        return skip(skip_reason, "non_ipv4");
    if (offset == caplen)
        return skip(skip_reason, "truncated_ipv4_header");

    const uint8_t *ip = data + offset;
    size_t available = caplen - offset;
    if ((ip[0] >> 4) == 6)
        return skip(skip_reason, "ipv6_unsupported");
    if ((ip[0] >> 4) != 4)
        return skip(skip_reason, "invalid_ip_version");
    if (available < 20)
        return skip(skip_reason, "truncated_ipv4_header");
    size_t ip_header_length = (size_t)(ip[0] & 15) * 4;
    if (ip_header_length < 20)
        return skip(skip_reason, "invalid_ipv4_header_length");
    if (ip_header_length > available)
        return skip(skip_reason, "truncated_ipv4_options");
    size_t ip_length = be16(ip + 2);
    if (ip_length < ip_header_length)
        return skip(skip_reason, "invalid_ipv4_total_length");
    if (ip_length > available)
        return skip(skip_reason, "truncated_ipv4_packet");
    uint16_t fragment = be16(ip + 6);
    if ((fragment & 0x3fffU) != 0)
        return skip(skip_reason, "ipv4_fragment");
    if ((fragment & 0x8000U) != 0)
        return skip(skip_reason, "invalid_ipv4_reserved_flag");

    const uint8_t *transport = ip + ip_header_length;
    size_t transport_length = ip_length - ip_header_length;
    size_t header_length;
    size_t payload_length;
    switch (ip[9]) {
        case 6: /* TCP */
            if (transport_length < 20)
                return skip(skip_reason, "truncated_tcp_header");
            header_length = (size_t)(transport[12] >> 4) * 4;
            if (header_length < 20)
                return skip(skip_reason, "invalid_tcp_header_length");
            if (header_length > transport_length)
                return skip(skip_reason, "truncated_tcp_options");
            packet->src_port = be16(transport);
            packet->dst_port = be16(transport + 2);
            packet->tcp_flags = transport[13];
            payload_length = transport_length - header_length;
            break;
        case 17: { /* UDP */
            if (transport_length < 8)
                return skip(skip_reason, "truncated_udp_header");
            size_t udp_length = be16(transport + 4);
            if (udp_length < 8)
                return skip(skip_reason, "invalid_udp_length");
            if (udp_length > transport_length)
                return skip(skip_reason, "truncated_udp_packet");
            packet->src_port = be16(transport);
            packet->dst_port = be16(transport + 2);
            header_length = 8;
            payload_length = udp_length - header_length;
            break;
        }
        case 1: /* ICMPv4 */
            if (transport_length < 8)
                return skip(skip_reason, "truncated_icmp_header");
            switch (transport[0]) {
                case 9:  /* Router advertisement: variable header. */
                case 13: /* Timestamp. */
                case 14: /* Timestamp reply. */
                    return skip(skip_reason, "icmp_extended_header");
                case 0:  /* Echo reply. */
                case 3:  /* Destination unreachable. */
                case 4:  /* Source quench. */
                case 5:  /* Redirect. */
                case 8:  /* Echo request. */
                case 10: /* Router solicitation. */
                case 11: /* Time exceeded. */
                case 12: /* Parameter problem. */
                case 15: /* Information request. */
                case 16: /* Information reply. */
                case 17: /* Address mask request. */
                case 18: /* Address mask reply. */
                    break;
                default:
                    return skip(skip_reason, "unsupported_icmp_type");
            }
            packet->icmp_type = transport[0];
            packet->icmp_code = transport[1];
            header_length = 8;
            payload_length = transport_length - header_length;
            break;
        default:
            return skip(skip_reason, "unsupported_ipv4_protocol");
    }

    packet->ts_ns = ts_ns;
    packet->captured_len = (uint32_t)caplen;
    packet->wire_len = wirelen;
    packet->ip_version = 4;
    packet->protocol = ip[9];
    memcpy(packet->src, ip + 12, 4);
    memcpy(packet->dst, ip + 16, 4);
    packet->payload = transport + header_length;
    packet->payload_len = (uint16_t)payload_length;
    return 1;
}
