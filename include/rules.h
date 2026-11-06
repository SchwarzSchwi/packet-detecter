/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LAB_RULES_H
#define LAB_RULES_H
#include "detector.h"

typedef struct { uint32_t network, mask; bool any, negate; } AddressFilter;
typedef struct { uint16_t low, high; bool any, negate; } PortFilter;
typedef enum { TRACK_SRC, TRACK_DST } TrackMode;
typedef struct {
    uint32_t sid, rev, priority;
    unsigned source_line;
    char message[512], classtype[128];
    uint8_t protocol;
    bool bidirectional;
    AddressFilter source, destination;
    PortFilter source_port, destination_port;
    bool has_dsize, has_itype, has_icode, has_rate;
    Predicate dsize, itype, icode;
    TrackMode track;
    uint32_t count, seconds;
    uint64_t matched_packets, alerts;
} Rule;

int load_rules(const char *path, Rule *rules, size_t *count,
               char *error, size_t error_size);
int load_builtin_rule(Rule *rules, size_t *count, char *error, size_t error_size);
bool rule_matches(const Rule *rule, const PacketView *packet);

#endif
