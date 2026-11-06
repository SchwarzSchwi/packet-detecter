/* SPDX-License-Identifier: GPL-2.0-only
 * New, deliberately strict parser for the documented packet-rule subset.
 * This is not the upstream Suricata signature parser.
 */
#define _POSIX_C_SOURCE 200809L
#include "rules.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static void fail(char *error, size_t size, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, size, format, ap);
    va_end(ap);
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) s[--n] = 0;
    return s;
}

static bool number(const char *s, uint32_t min, uint32_t max, uint32_t *out)
{
    if (!*s) return false;
    uint64_t value = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        value = value * 10 + (unsigned)(*s - '0');
        if (value > max) return false;
    }
    if (value < min) return false;
    *out = (uint32_t)value;
    return true;
}

static bool address_filter(char *text, AddressFilter *out)
{
    memset(out, 0, sizeof(*out));
    if (*text == '!') { out->negate = true; text++; }
    if (strcmp(text, "any") == 0) {
        if (out->negate) return false;
        out->any = true;
        return true;
    }
    char *slash = strchr(text, '/');
    uint32_t bits = 32;
    if (slash) {
        *slash++ = 0;
        if (!number(slash, 0, 32, &bits)) return false;
    }
    struct in_addr ip;
    if (inet_pton(AF_INET, text, &ip) != 1) return false;
    out->mask = bits == 0 ? 0 : UINT32_MAX << (32 - bits);
    out->network = ntohl(ip.s_addr) & out->mask;
    return true;
}

static bool port_filter(char *text, PortFilter *out)
{
    memset(out, 0, sizeof(*out));
    if (*text == '!') { out->negate = true; text++; }
    if (strcmp(text, "any") == 0) {
        if (out->negate) return false;
        out->any = true;
        return true;
    }
    uint32_t low = 0, high = 65535;
    char *colon = strchr(text, ':');
    if (colon) {
        *colon++ = 0;
        if (!*text && !*colon) return false;
        if (*text && !number(text, 0, 65535, &low)) return false;
        if (*colon && !number(colon, 0, 65535, &high)) return false;
        if (low > high) return false;
    } else {
        if (!number(text, 0, 65535, &low)) return false;
        high = low;
    }
    out->low = (uint16_t)low;
    out->high = (uint16_t)high;
    return true;
}

static bool message_value(const char *s, char *out, size_t capacity)
{
    size_t n = strlen(s), k = 0;
    if (n < 2 || s[0] != '"' || s[n - 1] != '"') return false;
    for (size_t i = 1; i < n - 1; i++) {
        if (s[i] == '"') return false;
        if (s[i] == '\\') {
            if (++i >= n - 1) return false;
        }
        if ((unsigned char)s[i] < 32 || k + 1 >= capacity) return false;
        out[k++] = s[i];
    }
    out[k] = 0;
    return true;
}

static bool rate_value(char *text, Rule *rule)
{
    unsigned seen = 0;
    char *part = text;
    for (;;) {
        char *comma = strchr(part, ',');
        if (comma) *comma = 0;
        char *key = trim(part), *value = key;
        while (*value && !isspace((unsigned char)*value)) value++;
        if (!*value) return false;
        *value++ = 0;
        value = trim(value);
        if (strcmp(key, "track") == 0) {
            if (seen & 1) return false;
            seen |= 1;
            if (strcmp(value, "by_src") == 0) rule->track = TRACK_SRC;
            else if (strcmp(value, "by_dst") == 0) rule->track = TRACK_DST;
            else return false;
        } else if (strcmp(key, "count") == 0) {
            if ((seen & 2) || !number(value, 1, UINT32_MAX, &rule->count)) return false;
            seen |= 2;
        } else if (strcmp(key, "seconds") == 0) {
            if ((seen & 4) || !number(value, 1, UINT32_MAX, &rule->seconds)) return false;
            seen |= 4;
        } else return false;
        if (!comma) break;
        part = comma + 1;
    }
    return seen == 7;
}

static int parse_rule(char *text, unsigned line, Rule *rule, char *error, size_t es)
{
    memset(rule, 0, sizeof(*rule));
    rule->source_line = line;
    rule->rev = 1;
    rule->priority = 3;
    char *open = strchr(text, '('), *close = strrchr(text, ')');
    if (!open || !close || close < open || *trim(close + 1)) {
        fail(error, es, "line %u: expected one complete alert rule", line); return -1;
    }
    *open++ = 0; *close = 0;
    char *tokens[8] = {0}, *save = NULL;
    size_t nt = 0;
    for (char *s = strtok_r(text, " \t\r\n", &save); s; s = strtok_r(NULL, " \t\r\n", &save)) {
        if (nt >= 8) break;
        tokens[nt++] = s;
    }
    if (nt != 7 || strcmp(tokens[0], "alert") != 0) {
        fail(error, es, "line %u: header must be: alert PROTO SRC PORT -> DST PORT", line); return -1;
    }
    if (strcmp(tokens[1], "ip") == 0) rule->protocol = 0;
    else if (strcmp(tokens[1], "icmp") == 0) rule->protocol = 1;
    else if (strcmp(tokens[1], "tcp") == 0) rule->protocol = 6;
    else if (strcmp(tokens[1], "udp") == 0) rule->protocol = 17;
    else { fail(error, es, "line %u: supported protocols: ip, icmp, tcp, udp (IPv4)", line); return -1; }
    if (strcmp(tokens[4], "<>") == 0) rule->bidirectional = true;
    else if (strcmp(tokens[4], "->") != 0) { fail(error, es, "line %u: direction must be -> or <>", line); return -1; }
    if (!address_filter(tokens[2], &rule->source) || !address_filter(tokens[5], &rule->destination)) {
        fail(error, es, "line %u: use IPv4, IPv4/CIDR, !IPv4/CIDR, or any; variables/lists/IPv6 are unsupported", line); return -1;
    }
    if (!port_filter(tokens[3], &rule->source_port) || !port_filter(tokens[6], &rule->destination_port)) {
        fail(error, es, "line %u: invalid port (use any, 0..65535, or LOW:HIGH)", line); return -1;
    }
    if ((rule->protocol == 1 || rule->protocol == 0) && (!rule->source_port.any || !rule->destination_port.any)) {
        fail(error, es, "line %u: icmp/ip rules require any for both ports in this subset", line); return -1;
    }

    unsigned seen = 0;
    char *start = open;
    bool quoted = false, escaped = false;
    for (char *p = open;; p++) {
        char c = *p;
        if (c && escaped) { escaped = false; continue; }
        if (c == '\\' && quoted) { escaped = true; continue; }
        if (c == '"') { quoted = !quoted; continue; }
        if (c != 0 && (c != ';' || quoted)) continue;
        if (quoted || escaped) { fail(error, es, "line %u: unfinished quoted value", line); return -1; }
        *p = 0;
        char *option = trim(start);
        if (*option) {
            char *colon = strchr(option, ':');
            if (!colon) { fail(error, es, "line %u: missing ':' in option '%s'", line, option); return -1; }
            *colon++ = 0;
            char *key = trim(option), *value = trim(colon);
            unsigned bit = 0;
            bool good = true;
            if (strcmp(key, "msg") == 0) { bit = 1; good = message_value(value, rule->message, sizeof(rule->message)); }
            else if (strcmp(key, "sid") == 0) { bit = 2; good = number(value, 1, UINT32_MAX, &rule->sid); }
            else if (strcmp(key, "rev") == 0) { bit = 4; good = number(value, 1, UINT32_MAX, &rule->rev); }
            else if (strcmp(key, "dsize") == 0) { bit = 8; rule->has_dsize = true; good = predicate_parse(value, 65535, &rule->dsize, error, es); }
            else if (strcmp(key, "itype") == 0) { bit = 16; rule->has_itype = true; good = predicate_parse(value, 255, &rule->itype, error, es); }
            else if (strcmp(key, "icode") == 0) { bit = 32; rule->has_icode = true; good = predicate_parse(value, 255, &rule->icode, error, es); }
            else if (strcmp(key, "detection_filter") == 0) { bit = 64; rule->has_rate = true; good = rate_value(value, rule); }
            else if (strcmp(key, "classtype") == 0) {
                bit = 128; good = *value && strlen(value) < sizeof(rule->classtype);
                if (good) strcpy(rule->classtype, value);
            } else if (strcmp(key, "priority") == 0) { bit = 256; good = number(value, 1, 255, &rule->priority); }
            else if (strcmp(key, "reference") == 0) {
                /* Citation metadata only; never treated as a match condition. */
                good = *value && strchr(value, ',') != NULL;
            } else {
                fail(error, es, "line %u: unsupported rule keyword '%s' (not ignored)", line, key); return -1;
            }
            if (!good) { fail(error, es, "line %u: invalid or unsupported value for '%s'", line, key); return -1; }
            if (bit && (seen & bit)) { fail(error, es, "line %u: duplicate option '%s'", line, key); return -1; }
            seen |= bit;
        }
        if (!c) break;
        start = p + 1;
    }
    if (!(seen & 2)) { fail(error, es, "line %u: a positive sid is required", line); return -1; }
    if ((rule->has_itype || rule->has_icode) && rule->protocol != 0 && rule->protocol != 1) {
        fail(error, es, "line %u: itype/icode require an icmp or ip rule", line); return -1;
    }
    if (!(seen & 1)) snprintf(rule->message, sizeof(rule->message), "Packet rule %u", rule->sid);
    return 0;
}

/* Reject malformed UTF-8 so message fields always remain valid JSON. */
static bool valid_utf8(const unsigned char *s, size_t n)
{
    for (size_t i = 0; i < n;) {
        unsigned c = s[i++], extra = 0, cp = 0, min = 0;
        if (c < 0x80) continue;
        if (c >= 0xc2 && c <= 0xdf) { extra = 1; cp = c & 31; min = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { extra = 2; cp = c & 15; min = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { extra = 3; cp = c & 7; min = 0x10000; }
        else return false;
        if (i + extra > n) return false;
        while (extra--) { c = s[i++]; if ((c & 0xc0) != 0x80) return false; cp = (cp << 6) | (c & 63); }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}

int load_rules(const char *path, Rule *rules, size_t *count, char *error, size_t es)
{
    *count = 0;
    FILE *file = fopen(path, "rb");
    if (!file) { fail(error, es, "cannot read rules '%s': %s", path, strerror(errno)); return -1; }
    const size_t limit = 4 * 1024 * 1024;
    unsigned char *data = malloc(limit + 1);
    if (!data) { fclose(file); fail(error, es, "out of memory reading rules"); return -1; }
    size_t length = fread(data, 1, limit + 1, file);
    bool io_error = ferror(file);
    fclose(file);
    if (io_error || length > limit || memchr(data, 0, length) || !valid_utf8(data, length)) {
        free(data); fail(error, es, "rules must be valid UTF-8 text, no NUL, at most 4 MiB"); return -1;
    }
    char text[MAX_RULE_TEXT + 1];
    size_t used = 0, offset = 0;
    unsigned line = 1, start_line = 1, depth = 0;
    bool quoted = false, escaped = false, comment = false;
    int result = -1;
    if (length >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf) offset = 3;
    for (size_t i = offset; i < length; i++) {
        unsigned char c = data[i];
        if (c == '\n') line++;
        if (comment) { if (c != '\n') continue; comment = false; }
        if (!quoted && c == '#') { comment = true; continue; }
        if (!quoted && c == '\\' && i + 1 < length && (data[i + 1] == '\n' || data[i + 1] == '\r')) continue;
        if (!used && isspace(c)) continue;
        if (!used) start_line = line;
        if (used >= MAX_RULE_TEXT) { fail(error, es, "line %u: rule exceeds %d bytes", start_line, MAX_RULE_TEXT); goto done; }
        if (c < 32 && !isspace(c)) { fail(error, es, "line %u: control character in rules", line); goto done; }
        text[used++] = isspace(c) && !quoted ? ' ' : (char)c;
        if (escaped) { escaped = false; continue; }
        if (quoted && c == '\\') { escaped = true; continue; }
        if (c == '"') { quoted = !quoted; continue; }
        if (!quoted && c == '(') {
            if (++depth != 1) { fail(error, es, "line %u: nested parentheses are unsupported", line); goto done; }
        } else if (!quoted && c == ')') {
            if (depth != 1) { fail(error, es, "line %u: unmatched ')'", line); goto done; }
            depth = 0;
            text[used] = 0;
            if (*count >= MAX_RULES) { fail(error, es, "at most %d rules are supported", MAX_RULES); goto done; }
            if (parse_rule(text, start_line, &rules[*count], error, es) != 0) goto done;
            for (size_t r = 0; r < *count; r++) {
                if (rules[r].sid == rules[*count].sid) {
                    fail(error, es, "line %u: duplicate sid %u", start_line, rules[r].sid); goto done;
                }
            }
            (*count)++;
            used = 0;
        }
    }
    text[used] = 0;
    if (*trim(text) || quoted || depth) { fail(error, es, "line %u: incomplete rule", start_line); goto done; }
    if (!*count) { fail(error, es, "no rules found in '%s'", path); goto done; }
    result = 0;
done:
    free(data);
    return result;
}

int load_builtin_rule(Rule *rules, size_t *count, char *error, size_t es)
{
    char text[] = "alert icmp any any -> any any (msg:\"Large frequent ICMP echo\"; itype:8; dsize:>800; detection_filter:track by_src, count 10, seconds 1; sid:1000001; rev:1;)";
    int result = parse_rule(text, 1, rules, error, es);
    *count = result == 0 ? 1 : 0;
    return result;
}

static uint32_t ipv4_value(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static bool address_match(const AddressFilter *f, const uint8_t *address)
{
    if (f->any) return true;
    bool match = (ipv4_value(address) & f->mask) == f->network;
    return f->negate ? !match : match;
}

static bool port_match(const PortFilter *f, uint16_t port)
{
    if (f->any) return true;
    bool match = port >= f->low && port <= f->high;
    return f->negate ? !match : match;
}

bool rule_matches(const Rule *rule, const PacketView *p)
{
    if (p->ip_version != 4 || (rule->protocol && rule->protocol != p->protocol)) return false;
    bool header = address_match(&rule->source, p->src) && address_match(&rule->destination, p->dst)
        && port_match(&rule->source_port, p->src_port) && port_match(&rule->destination_port, p->dst_port);
    if (!header && rule->bidirectional) {
        header = address_match(&rule->source, p->dst) && address_match(&rule->destination, p->src)
            && port_match(&rule->source_port, p->dst_port) && port_match(&rule->destination_port, p->src_port);
    }
    if (!header) return false;
    if (rule->has_dsize && !extracted_dsize_match(p, &rule->dsize)) return false;
    if (rule->has_itype && !extracted_itype_match(p, &rule->itype)) return false;
    if (rule->has_icode && !extracted_icode_match(p, &rule->icode)) return false;
    return true;
}
