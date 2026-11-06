/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LAB_PACKET_DETECTOR_H
#define LAB_PACKET_DETECTOR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define DETECTOR_VERSION "1.0.0"
#define MAX_RULES 256
#define MAX_RULE_TEXT 8192
#define MAX_TRACK_STATES 65536
#define PACKET_BUFFER_SIZE 262144

typedef enum { P_EQ, P_LT, P_LE, P_GT, P_GE, P_RANGE, P_NE,
               P_NOT_RANGE, P_BITMASK, P_NOT_BITMASK } PredicateMode;
typedef struct { uint16_t arg1, arg2; PredicateMode mode; } Predicate;

typedef struct {
    uint64_t ts_ns;
    uint32_t captured_len, wire_len;
    uint8_t ip_version, protocol;
    uint8_t src[16], dst[16];
    uint16_t src_port, dst_port, payload_len;
    uint8_t icmp_type, icmp_code, tcp_flags;
    const uint8_t *payload;
} PacketView;

/* Original predicates are extracted by tools/extract_upstream.py. */
bool predicate_parse(const char *text, unsigned maximum, Predicate *out,
                     char *error, size_t error_size);
int predicate_match(unsigned value, const Predicate *predicate);
int extracted_dsize_match(const PacketView *packet, const Predicate *predicate);
int extracted_itype_match(const PacketView *packet, const Predicate *predicate);
int extracted_icode_match(const PacketView *packet, const Predicate *predicate);

/* Decoder returns 1 for inspected IPv4 TCP/UDP/ICMP packets; 0 for a
 * documented skip, with a static reason string. No reassembly. */
int decode_packet(const uint8_t *data, size_t caplen, uint32_t wirelen,
                  uint32_t linktype, uint64_t ts_ns, PacketView *packet,
                  const char **skip_reason);

typedef int (*CaptureCallback)(const uint8_t *data, size_t caplen,
    uint32_t wirelen, uint32_t linktype, uint64_t ts_ns, void *user);

typedef struct {
    uint64_t packet_limit; /* zero means unlimited */
    unsigned duration_seconds; /* live only, zero means unlimited */
    bool promiscuous;
    bool include_outgoing;
} CaptureOptions;

typedef struct {
    uint64_t delivered, kernel_received, kernel_dropped;
    bool kernel_stats_available;
} CaptureStats;

/* 0 success, -1 error. Callback nonzero requests an error stop. */
int capture_file(const char *path, const CaptureOptions *options,
                 CaptureCallback callback, void *user, CaptureStats *stats,
                 char *error, size_t error_size);
int capture_live(const char *interface_name, const CaptureOptions *options,
                 CaptureCallback callback, void *user, CaptureStats *stats,
                 char *error, size_t error_size);
int capture_list_interfaces(FILE *output, char *error, size_t error_size);

#endif
