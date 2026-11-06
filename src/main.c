/* SPDX-License-Identifier: GPL-2.0-only
 * Standalone input, dispatch and logging for a Suricata-derived rule subset.
 * The classic detection_filter transition below is adapted from
 * Suricata src/detect-engine-threshold.c, Copyright (C) 2007-2024
 * Open Information Security Foundation, GPL version 2.
 */
#define _POSIX_C_SOURCE 200809L
#include "rules.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    bool used;
    uint16_t rule_index;
    uint32_t address;
    uint64_t first_ns, count;
} TrackEntry;

typedef struct { char name[80]; uint64_t count; } SkipCount;
typedef struct {
    Rule rules[MAX_RULES];
    size_t rule_count;
    TrackEntry *states;
    FILE *packets_file, *alerts_file, *events_file, *summary_file;
    uint64_t total_packets, decoded_packets, skipped_packets, alerts;
    uint64_t alerted_packets, last_timestamp;
    bool have_timestamp, quiet;
    SkipCount skipped_reasons[64];
    size_t skip_reason_count;
    char error[1024];
} Engine;

static void errorf(char *error, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(error, size, format, args);
    va_end(args);
}

static void json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (*p < 32) fprintf(f, "\\u%04x", *p);
                else fputc(*p, f);
        }
    }
    fputc('"', f);
}

static void csv_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"') fputc('"', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

static void timestamp_string(uint64_t ns, char *out, size_t size)
{
    snprintf(out, size, "%" PRIu64 ".%09" PRIu64,
             ns / UINT64_C(1000000000), ns % UINT64_C(1000000000));
}

static const char *protocol_name(uint8_t protocol)
{
    switch (protocol) { case 1: return "ICMP"; case 6: return "TCP"; case 17: return "UDP"; default: return "IP"; }
}

static uint32_t ip_number(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t mix(uint32_t a)
{
    a ^= a >> 16; a *= UINT32_C(0x7feb352d); a ^= a >> 15;
    a *= UINT32_C(0x846ca68b); a ^= a >> 16;
    return a;
}

/* Classic (not unique_on) detection_filter semantics from the uploaded
 * ThresholdSetup / ThresholdCheckUpdate. The first qualifying packet opens
 * the fixed window and has count 1. The right endpoint is inclusive, and the
 * first alert is count + 1. Storage, bounds and hash lookup are new here.
 */
static int rate_check(Engine *engine, size_t rule_index, const PacketView *p,
                      uint64_t *window_count)
{
    Rule *rule = &engine->rules[rule_index];
    if (!rule->has_rate) { *window_count = 0; return 1; }
    uint32_t address = ip_number(rule->track == TRACK_SRC ? p->src : p->dst);
    size_t index = mix(address ^ mix((uint32_t)rule_index)) % MAX_TRACK_STATES;
    TrackEntry *available = NULL;
    for (size_t n = 0; n < MAX_TRACK_STATES; n++) {
        TrackEntry *entry = &engine->states[(index + n) % MAX_TRACK_STATES];
        if (!entry->used) { if (!available) available = entry; break; }
        if (entry->rule_index == rule_index && entry->address == address) {
            uint64_t window = (uint64_t)rule->seconds * UINT64_C(1000000000);
            if (p->ts_ns - entry->first_ns <= window) {
                if (entry->count < UINT64_MAX) entry->count++;
                *window_count = entry->count;
                return entry->count > rule->count;
            }
            entry->first_ns = p->ts_ns;
            entry->count = 1;
            *window_count = 1;
            return 0;
        }
        uint64_t expiration = (uint64_t)engine->rules[entry->rule_index].seconds * UINT64_C(1000000000);
        if (!available && p->ts_ns >= entry->first_ns && p->ts_ns - entry->first_ns > expiration) available = entry;
    }
    if (!available) {
        errorf(engine->error, sizeof(engine->error),
               "all %u tracking states are active; stopped instead of silently losing rate counts", MAX_TRACK_STATES);
        return -1;
    }
    *available = (TrackEntry){ .used = true, .rule_index = (uint16_t)rule_index,
        .address = address, .first_ns = p->ts_ns, .count = 1 };
    *window_count = 1;
    return 0;
}

static void log_alert(Engine *engine, const Rule *r, const PacketView *p,
                      const char *timestamp, const char *source, const char *destination,
                      uint64_t window_count)
{
    fprintf(engine->alerts_file, "%" PRIu64 ",%s,%s,%s,%s,%u,%u,%u,%u,%u,",
        engine->total_packets, timestamp, source, destination, protocol_name(p->protocol),
        p->src_port, p->dst_port, p->payload_len, r->sid, r->rev);
    csv_string(engine->alerts_file, r->message);
    fprintf(engine->alerts_file, ",%" PRIu64 "\n", window_count);

    FILE *f = engine->events_file;
    fprintf(f, "{\"event_type\":\"alert\",\"engine\":\"suricata-derived-packet-subset\",\"packet_index\":%" PRIu64 ",\"timestamp\":", engine->total_packets);
    json_string(f, timestamp);
    fputs(",\"src_ip\":", f); json_string(f, source);
    fputs(",\"dest_ip\":", f); json_string(f, destination);
    fprintf(f, ",\"src_port\":%u,\"dest_port\":%u,\"proto\":", p->src_port, p->dst_port);
    json_string(f, protocol_name(p->protocol));
    fprintf(f, ",\"payload_bytes\":%u,\"window_count\":%" PRIu64 ",\"alert\":{\"signature_id\":%u,\"rev\":%u,\"signature\":",
            p->payload_len, window_count, r->sid, r->rev);
    json_string(f, r->message);
    fprintf(f, ",\"severity\":%u,\"category\":", r->priority);
    json_string(f, r->classtype);
    fputs("}}\n", f);
    if (!engine->quiet) {
        printf("[ALERT] packet=%" PRIu64 " sid=%u %s -> %s %s payload=%u window_count=%" PRIu64 " %s\n",
            engine->total_packets, r->sid, source, destination, protocol_name(p->protocol),
            p->payload_len, window_count, r->message);
    }
}

static void record_skip(Engine *engine, const char *reason)
{
    for (size_t i = 0; i < engine->skip_reason_count; i++) {
        if (strcmp(engine->skipped_reasons[i].name, reason) == 0) {
            engine->skipped_reasons[i].count++;
            return;
        }
    }
    if (engine->skip_reason_count < sizeof(engine->skipped_reasons) / sizeof(engine->skipped_reasons[0])) {
        SkipCount *entry = &engine->skipped_reasons[engine->skip_reason_count++];
        snprintf(entry->name, sizeof(entry->name), "%s", reason);
        entry->count = 1;
    }
}

static int process_packet(const uint8_t *data, size_t caplen, uint32_t wirelen,
    uint32_t linktype, uint64_t ts_ns, void *user)
{
    Engine *engine = user;
    if (engine->have_timestamp && ts_ns < engine->last_timestamp) {
        errorf(engine->error, sizeof(engine->error),
            "packet timestamps moved backwards at record %" PRIu64 "; use a capture ordered by timestamp", engine->total_packets + 1);
        return -1;
    }
    engine->have_timestamp = true;
    engine->last_timestamp = ts_ns;
    engine->total_packets++;
    char timestamp[40], source[INET_ADDRSTRLEN] = "", destination[INET_ADDRSTRLEN] = "";
    timestamp_string(ts_ns, timestamp, sizeof(timestamp));
    PacketView packet;
    const char *skip_reason = "unsupported";
    int decoded = decode_packet(data, caplen, wirelen, linktype, ts_ns, &packet, &skip_reason);
    bool processing_error = false;
    if (decoded != 1) {
        engine->skipped_packets++;
        record_skip(engine, skip_reason);
        fprintf(engine->packets_file, "%" PRIu64 ",%s,,,,,,,,,%zu,%u,skipped,",
                engine->total_packets, timestamp, caplen, wirelen);
        csv_string(engine->packets_file, skip_reason);
        fputs(",0,0\n", engine->packets_file);
    } else {
        engine->decoded_packets++;
        (void)inet_ntop(AF_INET, packet.src, source, sizeof(source));
        (void)inet_ntop(AF_INET, packet.dst, destination, sizeof(destination));
        unsigned matched_rules = 0, alerts = 0;
        for (size_t i = 0; i < engine->rule_count; i++) {
            Rule *rule = &engine->rules[i];
            if (!rule_matches(rule, &packet)) continue;
            matched_rules++;
            rule->matched_packets++;
            uint64_t window_count = 0;
            int result = rate_check(engine, i, &packet, &window_count);
            if (result < 0) { processing_error = true; break; }
            if (!result) continue;
            rule->alerts++;
            engine->alerts++;
            alerts++;
            log_alert(engine, rule, &packet, timestamp, source, destination, window_count);
        }
        if (alerts) engine->alerted_packets++;
        fprintf(engine->packets_file, "%" PRIu64 ",%s,%s,%s,%s,%u,%u,",
            engine->total_packets, timestamp, source, destination, protocol_name(packet.protocol),
            packet.src_port, packet.dst_port);
        if (packet.protocol == 1) fprintf(engine->packets_file, "%u,%u,", packet.icmp_type, packet.icmp_code);
        else fputs(",,", engine->packets_file);
        fprintf(engine->packets_file, "%u,%zu,%u,%s,%s,%u,%u\n",
                packet.payload_len, caplen, wirelen,
                processing_error ? "error" : "decoded",
                processing_error ? "rate_state_capacity" : "", matched_rules, alerts);
    }
    if (ferror(engine->packets_file) || ferror(engine->alerts_file) || ferror(engine->events_file)) {
        errorf(engine->error, sizeof(engine->error), "failed writing output files: %s", strerror(errno));
        return -1;
    }
    return processing_error ? -1 : 0;
}

static int make_directories(const char *path, char *error, size_t es)
{
    if (!*path || strlen(path) >= PATH_MAX) { errorf(error, es, "invalid output directory"); return -1; }
    char copy[PATH_MAX];
    strcpy(copy, path);
    size_t length = strlen(copy);
    while (length > 1 && copy[length - 1] == '/') copy[--length] = 0;
    for (char *p = copy + 1;; p++) {
        if (*p != '/' && *p != 0) continue;
        char saved = *p;
        *p = 0;
        if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
            errorf(error, es, "cannot create output directory '%s': %s", copy, strerror(errno)); return -1;
        }
        struct stat st;
        if (stat(copy, &st) != 0 || !S_ISDIR(st.st_mode)) {
            errorf(error, es, "output path '%s' is not a directory", copy); return -1;
        }
        *p = saved;
        if (!saved) break;
    }
    return 0;
}

static int open_logs(Engine *engine, const char *directory)
{
    if (make_directories(directory, engine->error, sizeof(engine->error)) != 0) return -1;
    const char *names[] = {"packets.csv", "alerts.csv", "eve.jsonl", "summary.json"};
    FILE **files[] = {&engine->packets_file, &engine->alerts_file, &engine->events_file, &engine->summary_file};
    char paths[4][PATH_MAX];
    for (size_t i = 0; i < 4; i++) {
        int n = snprintf(paths[i], sizeof(paths[i]), "%s/%s", directory, names[i]);
        if (n < 0 || (size_t)n >= sizeof(paths[i])) {
            errorf(engine->error, sizeof(engine->error), "output path is too long"); return -1;
        }
        struct stat st;
        if (lstat(paths[i], &st) == 0) {
            errorf(engine->error, sizeof(engine->error), "output already exists: %s; choose a new -l directory", paths[i]); return -1;
        }
        if (errno != ENOENT) {
            errorf(engine->error, sizeof(engine->error), "cannot inspect output '%s': %s", paths[i], strerror(errno)); return -1;
        }
    }
    size_t created = 0;
    for (; created < 4; created++) {
        int fd = open(paths[created], O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) break;
        *files[created] = fdopen(fd, "w");
        if (!*files[created]) { close(fd); unlink(paths[created]); break; }
        /* Promptly surface errors and make live alerts visible while running. */
        (void)setvbuf(*files[created], NULL, _IOLBF, 0);
    }
    if (created != 4) {
        errorf(engine->error, sizeof(engine->error), "cannot create output '%s': %s", paths[created], strerror(errno));
        for (size_t i = 0; i < created; i++) { fclose(*files[i]); *files[i] = NULL; unlink(paths[i]); }
        return -1;
    }
    fputs("packet_index,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,icmp_type,icmp_code,payload_bytes,captured_bytes,wire_bytes,status,reason,matched_rules,alerts\n", engine->packets_file);
    fputs("packet_index,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,payload_bytes,sid,rev,msg,window_count\n", engine->alerts_file);
    return 0;
}

static int write_summary(Engine *engine, const char *input, const char *mode,
                         const char *rules_path, const CaptureOptions *options,
                         const CaptureStats *stats, bool success)
{
    FILE *f = engine->summary_file;
    fputs("{\n  \"engine\": \"suricata-derived-packet-subset\",\n  \"version\": \"" DETECTOR_VERSION "\",\n  \"upstream_version\": \"uploaded 9.0.0-dev snapshot\",\n  \"status\": ", f);
    json_string(f, success ? "ok" : "error");
    fputs(",\n  \"error\": ", f); json_string(f, engine->error);
    fputs(",\n  \"mode\": ", f); json_string(f, mode);
    fputs(",\n  \"input\": ", f); json_string(f, input);
    fputs(",\n  \"rules_source\": ", f); json_string(f, rules_path ? rules_path : "built-in ICMP size/rate rule");
    fprintf(f, ",\n  \"total_packets\": %" PRIu64 ",\n  \"decoded_packets\": %" PRIu64 ",\n  \"skipped_packets\": %" PRIu64 ",\n  \"alerts\": %" PRIu64 ",\n  \"alerted_packets\": %" PRIu64 ",\n",
            engine->total_packets, engine->decoded_packets, engine->skipped_packets,
            engine->alerts, engine->alerted_packets);
    fprintf(f, "  \"packet_limit\": %" PRIu64 ",\n  \"include_outgoing\": %s,\n  \"promiscuous\": %s,\n  \"checksums_validated\": false,\n  \"tracking_capacity\": %u,\n",
        options->packet_limit, options->include_outgoing ? "true" : "false",
        options->promiscuous ? "true" : "false", MAX_TRACK_STATES);
    fputs("  \"kernel_received\": ", f);
    if (stats->kernel_stats_available) fprintf(f, "%" PRIu64, stats->kernel_received); else fputs("null", f);
    fputs(",\n  \"kernel_dropped\": ", f);
    if (stats->kernel_stats_available) fprintf(f, "%" PRIu64, stats->kernel_dropped); else fputs("null", f);
    fputs(",\n  \"skipped_reasons\": {", f);
    for (size_t i = 0; i < engine->skip_reason_count; i++) {
        if (i) fputc(',', f);
        fputs("\n    ", f); json_string(f, engine->skipped_reasons[i].name);
        fprintf(f, ": %" PRIu64, engine->skipped_reasons[i].count);
    }
    fputs("\n  },\n  \"rules\": [", f);
    for (size_t i = 0; i < engine->rule_count; i++) {
        const Rule *r = &engine->rules[i];
        if (i) fputc(',', f);
        fprintf(f, "\n    {\"sid\": %u, \"rev\": %u, \"msg\": ", r->sid, r->rev);
        json_string(f, r->message);
        fprintf(f, ", \"matched_packets\": %" PRIu64 ", \"alerts\": %" PRIu64 "}", r->matched_packets, r->alerts);
    }
    fputs("\n  ],\n  \"scope\": \"IPv4 TCP/UDP/selected ICMP packet predicates; no stream/app-layer detection or reassembly; not the full Suricata engine\"\n}\n", f);
    return fflush(f) == 0 && !ferror(f) ? 0 : -1;
}

static void help(FILE *out)
{
    fputs(
        "packet-detector " DETECTOR_VERSION " - Suricata-derived packet-rule subset\n"
        "Linux x86-64; passive IPv4 TCP/UDP/selected ICMP detection.\n"
        "\nUsage:\n"
        "  packet-detector -r FILE.pcap [-S FILE.rules] [-l DIRECTORY]\n"
        "  sudo packet-detector -i INTERFACE [-S FILE.rules] [-l DIRECTORY]\n"
        "  packet-detector -T [-S FILE.rules]\n"
        "  packet-detector --list-interfaces\n"
        "\nOptions:\n"
        "  -r, --read FILE          Classic PCAP input; no administrator required\n"
        "  -i, --interface NAME     Live Linux AF_PACKET input; needs CAP_NET_RAW\n"
        "  -S, --rules FILE         Strict rule subset; unknown options are errors\n"
        "  -l, --log-dir DIR        CSV/JSON output; existing files never overwritten\n"
        "  -T, --test              Validate rules, then exit without capturing\n"
        "  -c, --count N           Stop after N capture records (0 = unlimited)\n"
        "      --duration N        Stop live capture after N seconds (0 = unlimited)\n"
        "      --promisc           Request promiscuous mode for live capture\n"
        "      --include-outgoing  Include outgoing observations (default incoming only)\n"
        "      --list-interfaces   List local interface names\n"
        "  -q, --quiet             Suppress individual console alerts\n"
        "  -V, --version           Print version and scope\n"
        "  -h, --help              Show this help\n"
        "\nDefault rule: ICMP echo request, dsize > 800, >10 matches per source\n"
        "in a 1-second fixed window. Alert starts at the 11th qualifying packet.\n"
        "\nKeywords: msg, sid, rev, dsize, itype, icode, detection_filter,\n"
        "classtype, priority, reference. IPv4/CIDR/any, TCP/UDP port ranges.\n"
        "No content/flow/TLS/HTTP/IPv6/fragment reassembly/full-rule compatibility.\n"
        "PCAP timestamps must be nondecreasing. PCAPNG must be converted first:\n"
        "  editcap -F pcap input.pcapng output.pcap\n"
        "\nExamples:\n"
        "  ./bin/packet-detector -r samples/demo.pcap -l out-demo\n"
        "  sudo ./bin/packet-detector -i eth0 -l out-live\n", out);
}

static bool unsigned_argument(const char *s, uint64_t maximum, uint64_t *out)
{
    if (!*s) return false;
    uint64_t value = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        unsigned digit = (unsigned)(*s - '0');
        if (value > maximum / 10 || (value == maximum / 10 && digit > maximum % 10)) return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

int main(int argc, char **argv)
{
    const char *read_path = NULL, *interface_name = NULL, *rules_path = NULL, *output_dir = NULL;
    bool test_only = false, list_only = false, quiet = false;
    CaptureOptions options = {0};
    enum { OPT_DURATION = 1000, OPT_PROMISC, OPT_OUTGOING, OPT_INTERFACES };
    const struct option long_options[] = {
        {"read", required_argument, NULL, 'r'}, {"interface", required_argument, NULL, 'i'},
        {"rules", required_argument, NULL, 'S'}, {"log-dir", required_argument, NULL, 'l'},
        {"test", no_argument, NULL, 'T'}, {"count", required_argument, NULL, 'c'},
        {"duration", required_argument, NULL, OPT_DURATION}, {"promisc", no_argument, NULL, OPT_PROMISC},
        {"include-outgoing", no_argument, NULL, OPT_OUTGOING}, {"list-interfaces", no_argument, NULL, OPT_INTERFACES},
        {"quiet", no_argument, NULL, 'q'}, {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}
    };
    int option;
    while ((option = getopt_long(argc, argv, "r:i:S:l:Tc:qVh", long_options, NULL)) != -1) {
        uint64_t n;
        switch (option) {
            case 'r': read_path = optarg; break;
            case 'i': interface_name = optarg; break;
            case 'S': rules_path = optarg; break;
            case 'l': output_dir = optarg; break;
            case 'T': test_only = true; break;
            case 'c':
                if (!unsigned_argument(optarg, UINT64_MAX, &options.packet_limit)) {
                    fputs("error: count must be a nonnegative integer\n", stderr); return 2;
                }
                break;
            case OPT_DURATION:
                if (!unsigned_argument(optarg, UINT_MAX, &n)) {
                    fputs("error: duration must be a nonnegative integer of seconds\n", stderr); return 2;
                }
                options.duration_seconds = (unsigned)n; break;
            case OPT_PROMISC: options.promiscuous = true; break;
            case OPT_OUTGOING: options.include_outgoing = true; break;
            case OPT_INTERFACES: list_only = true; break;
            case 'q': quiet = true; break;
            case 'V': puts("packet-detector " DETECTOR_VERSION " (Suricata-derived subset, uploaded 9.0.0-dev; GPL-2.0-only)"); return 0;
            case 'h': help(stdout); return 0;
            default: help(stderr); return 2;
        }
    }
    if (optind != argc || (read_path && interface_name)) {
        fputs("error: choose exactly one input (-r or -i); unexpected positional argument\n", stderr); return 2;
    }
    if (list_only) {
        char error[1024] = "";
        if (capture_list_interfaces(stdout, error, sizeof(error)) != 0) { fprintf(stderr, "error: %s\n", error); return 2; }
        return 0;
    }
    if (!test_only && !read_path && !interface_name) { help(stderr); return 2; }
    if (read_path && (options.duration_seconds || options.promiscuous || options.include_outgoing)) {
        fputs("error: --duration, --promisc and --include-outgoing apply only to live capture\n", stderr); return 2;
    }
    Engine *engine = calloc(1, sizeof(*engine));
    if (!engine) { fputs("error: out of memory\n", stderr); return 2; }
    engine->quiet = quiet;
    int loaded = rules_path ? load_rules(rules_path, engine->rules, &engine->rule_count, engine->error, sizeof(engine->error))
        : load_builtin_rule(engine->rules, &engine->rule_count, engine->error, sizeof(engine->error));
    if (loaded != 0) { fprintf(stderr, "error: %s\n", engine->error); free(engine); return 2; }
    if (test_only) { printf("OK: %zu supported rule(s) validated.\n", engine->rule_count); free(engine); return 0; }
    engine->states = calloc(MAX_TRACK_STATES, sizeof(*engine->states));
    if (!engine->states) { fputs("error: out of memory allocating rate states\n", stderr); free(engine); return 2; }
    char default_output[128];
    if (!output_dir) {
        time_t now = time(NULL);
        struct tm utc;
        char stamp[32] = "time-unknown";
        if (gmtime_r(&now, &utc)) strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &utc);
        snprintf(default_output, sizeof(default_output), "detector-output-%s-%ld", stamp, (long)getpid());
        output_dir = default_output;
    }
    if (open_logs(engine, output_dir) != 0) {
        fprintf(stderr, "error: %s\n", engine->error); free(engine->states); free(engine); return 2;
    }
    if (!quiet) printf("Loaded %zu rule(s). Mode: %s. Output: %s\n", engine->rule_count,
                       read_path ? "offline PCAP" : "live IPv4 capture", output_dir);
    CaptureStats stats = {0};
    char capture_error[1024] = "";
    int result = read_path
        ? capture_file(read_path, &options, process_packet, engine, &stats, capture_error, sizeof(capture_error))
        : capture_live(interface_name, &options, process_packet, engine, &stats, capture_error, sizeof(capture_error));
    if (result != 0 && !*engine->error) snprintf(engine->error, sizeof(engine->error), "%s", capture_error);
    if (fflush(engine->packets_file) || fflush(engine->alerts_file) || fflush(engine->events_file)) {
        result = -1;
        errorf(engine->error, sizeof(engine->error), "failed flushing output files: %s", strerror(errno));
    }
    if (write_summary(engine, read_path ? read_path : interface_name, read_path ? "pcap" : "live",
                      rules_path, &options, &stats, result == 0) != 0) {
        result = -1;
        errorf(engine->error, sizeof(engine->error), "failed writing summary: %s", strerror(errno));
    }
    FILE *files[] = {engine->packets_file, engine->alerts_file, engine->events_file, engine->summary_file};
    for (size_t i = 0; i < 4; i++) {
        if (fclose(files[i]) != 0) {
            result = -1;
            errorf(engine->error, sizeof(engine->error), "failed closing output: %s", strerror(errno));
        }
    }
    printf("Packets: %" PRIu64 " | decoded: %" PRIu64 " | skipped: %" PRIu64 " | alerts: %" PRIu64 "\nOutput: %s\n",
        engine->total_packets, engine->decoded_packets, engine->skipped_packets, engine->alerts, output_dir);
    if (result != 0) fprintf(stderr, "error: %s\n", engine->error);
    free(engine->states);
    free(engine);
    return result == 0 ? 0 : 2;
}
