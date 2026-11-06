/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/* SPDX-License-Identifier: GPL-2.0-only
 * Adaptation, 2026-11-06:
 * - predicate_match is a C translation of detect_match_uint from the uploaded
 *   Suricata rust/src/detect/uint.rs, retaining all ten comparison predicates.
 * - predicate_parse is a new, deliberately restricted decimal-only parser.
 * - Private compatibility types below allow three unchanged original C match
 *   functions to operate on this application's decoded PacketView.
 * See upstream/PROVENANCE.md for the precise extraction boundary.
 */

#include "detector.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>

static bool parse_error(char *error, size_t size, const char *format, ...)
{
    if (error != NULL && size > 0) {
        va_list args;
        va_start(args, format);
        (void)vsnprintf(error, size, format, args);
        va_end(args);
    }
    return false;
}

static void skip_space(const char **cursor)
{
    while (isspace((unsigned char)**cursor))
        (*cursor)++;
}

static bool parse_decimal(const char **cursor, unsigned maximum, uint16_t *value,
                          char *error, size_t error_size)
{
    unsigned result = 0;
    if (**cursor < '0' || **cursor > '9')
        return parse_error(error, error_size, "expected a decimal integer in 0..%u", maximum);
    while (**cursor >= '0' && **cursor <= '9') {
        const unsigned digit = (unsigned)(**cursor - '0');
        if (result > maximum / 10U ||
                (result == maximum / 10U && digit > maximum % 10U))
            return parse_error(error, error_size, "integer is outside 0..%u", maximum);
        result = result * 10U + digit;
        (*cursor)++;
    }
    *value = (uint16_t)result;
    return true;
}

bool predicate_parse(const char *text, unsigned maximum, Predicate *out,
                     char *error, size_t error_size)
{
    if (text == NULL || out == NULL || maximum > UINT16_MAX)
        return parse_error(error, error_size, "invalid numeric predicate arguments");
    const char *cursor = text;
    Predicate result = {0, 0, P_EQ};
    bool range_allowed = true;
    bool negated = false;
    skip_space(&cursor);

    if (strncmp(cursor, "!=", 2) == 0) {
        result.mode = P_NE;
        range_allowed = false;
        cursor += 2;
    } else if (*cursor == '!') {
        negated = true;
        result.mode = P_NE;
        cursor++;
    } else if (*cursor == '>' || *cursor == '<') {
        const bool greater = (*cursor++ == '>');
        const bool inclusive = (*cursor == '=');
        if (inclusive)
            cursor++;
        result.mode = greater ? (inclusive ? P_GE : P_GT) : (inclusive ? P_LE : P_LT);
        range_allowed = false;
    } else if (*cursor == '=') {
        range_allowed = false;
        cursor++;
    }
    skip_space(&cursor);
    if (!parse_decimal(&cursor, maximum, &result.arg1, error, error_size))
        return false;
    skip_space(&cursor);

    if (strncmp(cursor, "<>", 2) == 0) {
        if (!range_allowed)
            return parse_error(error, error_size, "use a<>b or !a<>b for an exclusive range");
        cursor += 2;
        skip_space(&cursor);
        if (!parse_decimal(&cursor, maximum, &result.arg2, error, error_size))
            return false;
        if (result.arg2 <= result.arg1 ||
                (unsigned)result.arg2 - (unsigned)result.arg1 <= 1U)
            return parse_error(error, error_size,
                               "exclusive range must contain at least one integer (b > a + 1)");
        result.mode = negated ? P_NOT_RANGE : P_RANGE;
        skip_space(&cursor);
    }
    if (*cursor != '\0')
        return parse_error(error, error_size,
                           "unsupported numeric syntax; use decimal n, =n, !n, !=n, <n, <=n, >n, >=n, a<>b or !a<>b");

    /* Match the upstream parser's rejection of boundary comparisons that
     * cannot narrow the supported integer domain. */
    if ((result.mode == P_LT && result.arg1 == 0) ||
            (result.mode == P_GT && result.arg1 == maximum) ||
            (result.mode == P_LE && result.arg1 == maximum) ||
            (result.mode == P_GE && result.arg1 == 0))
        return parse_error(error, error_size,
                           "comparison at this integer boundary is rejected by the Suricata parser");

    *out = result;
    if (error != NULL && error_size > 0)
        error[0] = '\0';
    return true;
}

/* C translation of rust/src/detect/uint.rs::detect_match_uint.
 * The range endpoints are intentionally EXCLUDED; negated ranges INCLUDE
 * those endpoints. Bitmask modes are preserved here, but are not accepted by
 * the restricted text parser above. */
int predicate_match(unsigned value, const Predicate *predicate)
{
    if (predicate == NULL)
        return 0;
    switch (predicate->mode) {
        case P_EQ:          return value == predicate->arg1;
        case P_NE:          return value != predicate->arg1;
        case P_LT:          return value < predicate->arg1;
        case P_LE:          return value <= predicate->arg1;
        case P_GT:          return value > predicate->arg1;
        case P_GE:          return value >= predicate->arg1;
        case P_RANGE:       return value > predicate->arg1 && value < predicate->arg2;
        case P_NOT_RANGE:   return value <= predicate->arg1 || value >= predicate->arg2;
        case P_BITMASK:     return (value & predicate->arg1) == predicate->arg2;
        case P_NOT_BITMASK: return (value & predicate->arg1) != predicate->arg2;
    }
    return 0;
}

/* Private names and accessors expected by the three extracted functions.
 * The dummy context pointers are never dereferenced. PacketView represents
 * real captured packets only, hence PKT_IS_PSEUDOPKT is always false. */
typedef struct DetectEngineThreadCtx_ DetectEngineThreadCtx;
typedef struct Signature_ Signature;
typedef void SigMatchCtx;
typedef Predicate DetectU16Data;
typedef Predicate DetectU8Data;
typedef struct { uint8_t type, code; } ICMPV6Hdr;
typedef struct {
    uint16_t payload_len;
    uint8_t ip_version, protocol;
    struct { uint8_t type, code; } icmp_s;
    ICMPV6Hdr icmpv6;
} Packet;

#define SCEnter() ((void)0)
#define SCLogDebug(...) ((void)0)
#define SCReturnInt(value) return (value)
#define DEBUG_VALIDATE_BUG_ON(condition) ((void)(condition))
#define PKT_IS_PSEUDOPKT(packet) ((void)(packet), 0)
#define PacketIsICMPv4(packet) ((packet)->ip_version == 4 && (packet)->protocol == 1)
#define PacketIsICMPv6(packet) ((packet)->ip_version == 6 && (packet)->protocol == 58)
#define PacketGetICMPv6(packet) (&(packet)->icmpv6)
#define ICMPV6_GET_TYPE(header) ((header)->type)
#define ICMPV6_GET_CODE(header) ((header)->code)

static int DetectU16Match(uint16_t value, const DetectU16Data *predicate)
{
    return predicate_match(value, predicate);
}

static int DetectU8Match(uint8_t value, const DetectU8Data *predicate)
{
    return predicate_match(value, predicate);
}

/* Upstream callback signatures retain unused engine/context parameters.
 * Suppress that one warning locally so the bodies can remain unchanged. */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include "suricata_matchers.inc"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

static Packet compatibility_packet(const PacketView *view)
{
    Packet packet = {0};
    packet.payload_len = view->payload_len;
    packet.ip_version = view->ip_version;
    packet.protocol = view->protocol;
    packet.icmp_s.type = view->icmp_type;
    packet.icmp_s.code = view->icmp_code;
    packet.icmpv6.type = view->icmp_type;
    packet.icmpv6.code = view->icmp_code;
    return packet;
}

int extracted_dsize_match(const PacketView *view, const Predicate *predicate)
{
    if (view == NULL || predicate == NULL)
        return 0;
    Packet packet = compatibility_packet(view);
    return DetectDsizeMatch(NULL, &packet, NULL, predicate);
}

int extracted_itype_match(const PacketView *view, const Predicate *predicate)
{
    if (view == NULL || predicate == NULL)
        return 0;
    Packet packet = compatibility_packet(view);
    return DetectITypeMatch(NULL, &packet, NULL, predicate);
}

int extracted_icode_match(const PacketView *view, const Predicate *predicate)
{
    if (view == NULL || predicate == NULL)
        return 0;
    Packet packet = compatibility_packet(view);
    return DetectICodeMatch(NULL, &packet, NULL, predicate);
}
