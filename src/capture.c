/* SPDX-License-Identifier: GPL-2.0-only
 * Independent, bounded input adapter: classic PCAP files and Linux AF_PACKET.
 * No libpcap dependency. Packet parsing and rule matching are separate modules.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "detector.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <arpa/inet.h>
#include <dirent.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#endif

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    if (error == NULL || error_size == 0)
        return;
    va_list ap;
    va_start(ap, format);
    (void)vsnprintf(error, error_size, format, ap);
    va_end(ap);
}

static uint16_t get16(const uint8_t *p, bool little_endian)
{
    if (little_endian)
        return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get32(const uint8_t *p, bool little_endian)
{
    if (little_endian)
        return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
               ((uint32_t)p[1] << 8) | p[0];
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static bool supported_linktype(uint32_t linktype)
{
    switch (linktype) {
        case 0: case 1: case 12: case 101: case 108:
        case 113: case 228: case 229: case 276:
            return true;
        default:
            return false;
    }
}

int capture_file(const char *path, const CaptureOptions *options,
                 CaptureCallback callback, void *user, CaptureStats *stats,
                 char *error, size_t error_size)
{
    CaptureStats local_stats;
    CaptureOptions defaults = {0};
    if (stats == NULL)
        stats = &local_stats;
    memset(stats, 0, sizeof(*stats));
    if (error != NULL && error_size > 0)
        error[0] = '\0';
    if (options == NULL)
        options = &defaults;
    if (path == NULL || path[0] == '\0' || callback == NULL) {
        set_error(error, error_size, "A PCAP filename and packet callback are required.");
        return -1;
    }
    FILE *input = fopen(path, "rb");
    if (input == NULL) {
        set_error(error, error_size, "Cannot open PCAP '%s': %s", path, strerror(errno));
        return -1;
    }

    int result = -1;
    uint8_t *buffer = NULL;
    uint8_t header[24];
    size_t got = fread(header, 1, sizeof(header), input);
    if (got >= 4 && memcmp(header, "\x0a\x0d\x0d\x0a", 4) == 0) {
        set_error(error, error_size,
                  "PCAPNG is not supported. Convert it with: "
                  "editcap -F pcap input.pcapng output.pcap");
        goto cleanup;
    }
    if (got != sizeof(header)) {
        set_error(error, error_size, "PCAP global header is missing or truncated%s.",
                  ferror(input) ? " (read error)" : "");
        goto cleanup;
    }

    bool little_endian;
    bool nanoseconds;
    if (memcmp(header, "\xd4\xc3\xb2\xa1", 4) == 0) {
        little_endian = true;
        nanoseconds = false;
    } else if (memcmp(header, "\xa1\xb2\xc3\xd4", 4) == 0) {
        little_endian = false;
        nanoseconds = false;
    } else if (memcmp(header, "\x4d\x3c\xb2\xa1", 4) == 0) {
        little_endian = true;
        nanoseconds = true;
    } else if (memcmp(header, "\xa1\xb2\x3c\x4d", 4) == 0) {
        little_endian = false;
        nanoseconds = true;
    } else {
        set_error(error, error_size, "Unrecognized PCAP magic; a classic PCAP file is required.");
        goto cleanup;
    }
    if (get16(header + 4, little_endian) != 2 ||
        get16(header + 6, little_endian) != 4) {
        set_error(error, error_size, "Only classic PCAP format version 2.4 is supported.");
        goto cleanup;
    }
    uint32_t snaplen = get32(header + 16, little_endian);
    /* The upper 16 bits may carry standard additional link-layer information
     * (e.g. FCS metadata). IP total length excludes Ethernet padding/FCS. */
    uint32_t linktype = get32(header + 20, little_endian) & 0xffffU;
    if (snaplen == 0) {
        set_error(error, error_size, "Invalid PCAP snapshot length of zero.");
        goto cleanup;
    }
    if (!supported_linktype(linktype)) {
        set_error(error, error_size, "Unsupported PCAP linktype %" PRIu32
                  "; use Ethernet, Linux SLL/SLL2, raw IP, or NULL/LOOP.", linktype);
        goto cleanup;
    }
    size_t capacity = snaplen < PACKET_BUFFER_SIZE ? snaplen : PACKET_BUFFER_SIZE;
    buffer = malloc(capacity);
    if (buffer == NULL) {
        set_error(error, error_size, "Cannot allocate the bounded PCAP packet buffer.");
        goto cleanup;
    }

    for (;;) {
        if (options->packet_limit != 0 && stats->delivered >= options->packet_limit)
            break;
        uint8_t record[16];
        got = fread(record, 1, sizeof(record), input);
        if (got == 0 && feof(input) && !ferror(input))
            break;
        uint64_t packet_number = stats->delivered + 1;
        if (got != sizeof(record)) {
            set_error(error, error_size, "PCAP record %" PRIu64
                      " has a truncated header%s.", packet_number,
                      ferror(input) ? " (read error)" : "");
            goto cleanup;
        }
        uint32_t seconds = get32(record, little_endian);
        uint32_t fraction = get32(record + 4, little_endian);
        uint32_t captured_length = get32(record + 8, little_endian);
        uint32_t original_length = get32(record + 12, little_endian);
        uint32_t fraction_limit = nanoseconds ? 1000000000U : 1000000U;
        if (fraction >= fraction_limit) {
            set_error(error, error_size, "PCAP record %" PRIu64
                      " has an invalid timestamp fraction.", packet_number);
            goto cleanup;
        }
        if (captured_length > snaplen || captured_length > original_length) {
            set_error(error, error_size, "PCAP record %" PRIu64
                      " has inconsistent captured, original, or snapshot lengths.", packet_number);
            goto cleanup;
        }
        if (captured_length > capacity) {
            set_error(error, error_size, "PCAP record %" PRIu64
                      " exceeds the %u-byte packet buffer limit.", packet_number,
                      (unsigned)PACKET_BUFFER_SIZE);
            goto cleanup;
        }
        if (fread(buffer, 1, captured_length, input) != captured_length) {
            set_error(error, error_size, "PCAP record %" PRIu64
                      " has truncated packet data%s.", packet_number,
                      ferror(input) ? " (read error)" : "");
            goto cleanup;
        }
        uint64_t timestamp = (uint64_t)seconds * UINT64_C(1000000000) +
                             (uint64_t)fraction * (nanoseconds ? 1U : 1000U);
        stats->delivered++;
        if (callback(buffer, captured_length, original_length, linktype, timestamp, user) != 0) {
            set_error(error, error_size, "Packet processing failed at PCAP record %" PRIu64 ".",
                      packet_number);
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    free(buffer);
    if (fclose(input) != 0 && result == 0) {
        set_error(error, error_size, "Error closing PCAP input: %s", strerror(errno));
        result = -1;
    }
    return result;
}

#ifdef __linux__
static volatile sig_atomic_t live_stop_requested;

static void request_live_stop(int signal_number)
{
    (void)signal_number;
    live_stop_requested = 1;
}

static int timespec_ns(const struct timespec *value, uint64_t *result)
{
    if (value->tv_sec < 0 || value->tv_nsec < 0 || value->tv_nsec >= 1000000000L)
        return -1;
    uint64_t sec = (uint64_t)value->tv_sec;
    uint64_t frac = (uint64_t)value->tv_nsec;
    if (sec > (UINT64_MAX - frac) / UINT64_C(1000000000))
        return -1;
    *result = sec * UINT64_C(1000000000) + frac;
    return 0;
}

static int clock_ns(clockid_t clock_id, uint64_t *result)
{
    struct timespec value;
    if (clock_gettime(clock_id, &value) != 0)
        return -1;
    return timespec_ns(&value, result);
}

static int list_interfaces_sysfs(FILE *output, int query_error,
                                 char *error, size_t error_size)
{
    /* Some confined Linux runtimes deny netlink interface enumeration while
     * exposing the kernel's read-only network-interface inventory in sysfs.
     * Only names enumerated in this fixed directory are used, and only their
     * numeric ifindex files are read; no user-supplied paths are accepted. */
    DIR *directory = opendir("/sys/class/net");
    if (directory == NULL) {
        int sysfs_error = errno;
        char query_message[128];
        (void)snprintf(query_message, sizeof(query_message), "%s", strerror(query_error));
        set_error(error, error_size,
                  "Cannot list interfaces: network query failed (%s); "
                  "cannot read /sys/class/net (%s).",
                  query_message, strerror(sysfs_error));
        return -1;
    }
    size_t emitted = 0;
    int result = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                set_error(error, error_size, "Cannot enumerate /sys/class/net: %s", strerror(errno));
                result = -1;
            }
            break;
        }
        const char *name = entry->d_name;
        size_t name_length = strlen(name);
        if (name_length == 0 || name_length >= IFNAMSIZ ||
            strcmp(name, ".") == 0 || strcmp(name, "..") == 0 || strchr(name, '/') != NULL)
            continue;
        char path[sizeof("/sys/class/net/") + IFNAMSIZ + sizeof("/ifindex")];
        int path_length = snprintf(path, sizeof(path), "/sys/class/net/%s/ifindex", name);
        if (path_length < 0 || (size_t)path_length >= sizeof(path))
            continue;
        FILE *index_file = fopen(path, "r");
        if (index_file == NULL)
            continue; /* The interface can disappear during enumeration. */
        char index_text[64];
        bool read_ok = fgets(index_text, sizeof(index_text), index_file) != NULL;
        if (fclose(index_file) != 0)
            read_ok = false;
        if (!read_ok || index_text[0] < '0' || index_text[0] > '9')
            continue;
        char *end;
        errno = 0;
        unsigned long index = strtoul(index_text, &end, 10);
        if (errno != 0 || index == 0 || index > UINT_MAX)
            continue;
        if (*end == '\n')
            ++end;
        if (*end != '\0')
            continue;
        if ((emitted == 0 && fprintf(output, "index\tinterface\n") < 0) ||
            fprintf(output, "%u\t%s\n", (unsigned)index, name) < 0) {
            set_error(error, error_size, "Cannot write the interface list.");
            result = -1;
            break;
        }
        emitted++;
    }
    if (closedir(directory) != 0 && result == 0) {
        set_error(error, error_size, "Cannot finish reading /sys/class/net: %s", strerror(errno));
        result = -1;
    }
    if (result == 0 && emitted == 0) {
        set_error(error, error_size,
                  "Cannot list interfaces: network query failed (%s), "
                  "and /sys/class/net has no readable interface indices.", strerror(query_error));
        result = -1;
    }
    return result;
}

int capture_list_interfaces(FILE *output, char *error, size_t error_size)
{
    if (error != NULL && error_size > 0)
        error[0] = '\0';
    if (output == NULL) {
        set_error(error, error_size, "An interface-list output stream is required.");
        return -1;
    }
    struct if_nameindex *interfaces = if_nameindex();
    if (interfaces == NULL)
        return list_interfaces_sysfs(output, errno != 0 ? errno : EIO, error, error_size);
    int result = 0;
    if (fprintf(output, "index\tinterface\n") < 0)
        result = -1;
    for (struct if_nameindex *entry = interfaces;
         result == 0 && entry->if_index != 0 && entry->if_name != NULL; ++entry) {
        if (fprintf(output, "%u\t%s\n", entry->if_index, entry->if_name) < 0)
            result = -1;
    }
    if_freenameindex(interfaces);
    if (result != 0)
        set_error(error, error_size, "Cannot write the interface list.");
    return result;
}

int capture_live(const char *interface_name, const CaptureOptions *options,
                 CaptureCallback callback, void *user, CaptureStats *stats,
                 char *error, size_t error_size)
{
    CaptureStats local_stats;
    CaptureOptions defaults = {0};
    if (stats == NULL)
        stats = &local_stats;
    memset(stats, 0, sizeof(*stats));
    if (error != NULL && error_size > 0)
        error[0] = '\0';
    if (options == NULL)
        options = &defaults;
    if (interface_name == NULL || interface_name[0] == '\0' ||
        strlen(interface_name) >= IFNAMSIZ || callback == NULL) {
        set_error(error, error_size, "A valid Linux interface name and packet callback are required.");
        return -1;
    }
    unsigned interface_index = if_nametoindex(interface_name);
    if (interface_index == 0) {
        set_error(error, error_size, "Cannot find interface '%s': %s. Use --list-interfaces.",
                  interface_name, strerror(errno));
        return -1;
    }
    /* Protocol zero leaves capture inactive until the interface-specific bind,
     * so traffic from unrelated interfaces cannot queue before that bind. */
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        set_error(error, error_size,
                  "Cannot open live capture on '%s': %s. Linux live capture needs sudo "
                  "or CAP_NET_RAW; offline PCAP reading does not need root.",
                  interface_name, strerror(errno));
        return -1;
    }

    int result = -1;
    uint8_t *buffer = NULL;
    bool signal_handlers_installed = false;
    struct sigaction old_interrupt;
    struct sigaction old_terminate;
    struct ifreq interface_request;
    memset(&interface_request, 0, sizeof(interface_request));
    memcpy(interface_request.ifr_name, interface_name, strlen(interface_name) + 1);
    if (ioctl(fd, SIOCGIFHWADDR, &interface_request) != 0) {
        set_error(error, error_size, "Cannot determine interface link type: %s", strerror(errno));
        goto cleanup;
    }
    uint32_t linktype;
    switch (interface_request.ifr_hwaddr.sa_family) {
        case ARPHRD_ETHER:
        case ARPHRD_LOOPBACK:
            linktype = 1;
            break;
        case ARPHRD_PPP:
        case ARPHRD_NONE:
#ifdef ARPHRD_RAWIP
        case ARPHRD_RAWIP:
#endif
            linktype = 101;
            break;
        default:
            set_error(error, error_size, "Unsupported live interface link type %u on '%s'.",
                      (unsigned)interface_request.ifr_hwaddr.sa_family, interface_name);
            goto cleanup;
    }
    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = (int)interface_index;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        set_error(error, error_size, "Cannot bind capture to '%s': %s", interface_name, strerror(errno));
        goto cleanup;
    }
    if (options->promiscuous) {
        struct packet_mreq membership;
        memset(&membership, 0, sizeof(membership));
        membership.mr_ifindex = (int)interface_index;
        membership.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &membership, sizeof(membership)) != 0) {
            set_error(error, error_size, "Cannot enable promiscuous capture: %s", strerror(errno));
            goto cleanup;
        }
    }
    int enabled = 1;
#ifdef PACKET_IGNORE_OUTGOING
    if (!options->include_outgoing) {
        /* Older kernels may reject this optimization. The receive loop also
         * filters PACKET_OUTGOING, so that fallback preserves the contract. */
        (void)setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enabled, sizeof(enabled));
    }
#endif
    (void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled));
    buffer = malloc(PACKET_BUFFER_SIZE);
    if (buffer == NULL) {
        set_error(error, error_size, "Cannot allocate the bounded live packet buffer.");
        goto cleanup;
    }

    struct sigaction handler;
    memset(&handler, 0, sizeof(handler));
    handler.sa_handler = request_live_stop;
    sigemptyset(&handler.sa_mask);
    live_stop_requested = 0;
    if (sigaction(SIGINT, &handler, &old_interrupt) != 0) {
        set_error(error, error_size, "Cannot install capture interrupt handler: %s", strerror(errno));
        goto cleanup;
    }
    if (sigaction(SIGTERM, &handler, &old_terminate) != 0) {
        int saved_errno = errno;
        (void)sigaction(SIGINT, &old_interrupt, NULL);
        set_error(error, error_size, "Cannot install capture termination handler: %s", strerror(saved_errno));
        goto cleanup;
    }
    signal_handlers_installed = true;
    uint64_t start;
    if (clock_ns(CLOCK_MONOTONIC, &start) != 0) {
        set_error(error, error_size, "Cannot read the monotonic capture clock.");
        goto cleanup;
    }
    uint64_t duration = (uint64_t)options->duration_seconds * UINT64_C(1000000000);

    while (!live_stop_requested) {
        if (options->packet_limit != 0 && stats->delivered >= options->packet_limit)
            break;
        int timeout_ms = 250;
        if (duration != 0) {
            uint64_t now;
            if (clock_ns(CLOCK_MONOTONIC, &now) != 0 || now < start) {
                set_error(error, error_size, "Cannot read the monotonic capture clock.");
                goto cleanup;
            }
            uint64_t elapsed = now - start;
            if (elapsed >= duration)
                break;
            uint64_t remaining_ms = (duration - elapsed + 999999) / 1000000;
            if (remaining_ms < (uint64_t)timeout_ms)
                timeout_ms = (int)remaining_ms;
        }
        struct pollfd poll_descriptor = { .fd = fd, .events = POLLIN, .revents = 0 };
        int ready = poll(&poll_descriptor, 1, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            set_error(error, error_size, "Capture polling failed: %s", strerror(errno));
            goto cleanup;
        }
        if (ready == 0)
            continue;
        if ((poll_descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            set_error(error, error_size, "Capture interface became unavailable (poll flags %#x).",
                      (unsigned)poll_descriptor.revents);
            goto cleanup;
        }
        if ((poll_descriptor.revents & POLLIN) == 0)
            continue;

        struct sockaddr_ll sender;
        memset(&sender, 0, sizeof(sender));
        struct iovec vector = { .iov_base = buffer, .iov_len = PACKET_BUFFER_SIZE };
        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(sizeof(struct timespec))];
        } control;
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.bytes;
        message.msg_controllen = sizeof(control.bytes);
        ssize_t received = recvmsg(fd, &message, MSG_TRUNC);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            set_error(error, error_size, "Packet receive failed: %s", strerror(errno));
            goto cleanup;
        }
        if (sender.sll_ifindex != (int)interface_index)
            continue;
        if (!options->include_outgoing && sender.sll_pkttype == PACKET_OUTGOING)
            continue;
        if ((uint64_t)received > UINT32_MAX) {
            set_error(error, error_size, "Received a packet with an unrepresentable wire length.");
            goto cleanup;
        }
        uint64_t timestamp = 0;
        bool have_timestamp = false;
        if ((message.msg_flags & MSG_CTRUNC) == 0) {
            for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
                 cmsg = CMSG_NXTHDR(&message, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct timespec))) {
                    struct timespec received_at;
                    memcpy(&received_at, CMSG_DATA(cmsg), sizeof(received_at));
                    have_timestamp = timespec_ns(&received_at, &timestamp) == 0;
                    break;
                }
            }
        }
        if (!have_timestamp && clock_ns(CLOCK_REALTIME, &timestamp) != 0) {
            set_error(error, error_size, "Cannot timestamp received packet.");
            goto cleanup;
        }
        size_t captured = (uint64_t)received > PACKET_BUFFER_SIZE
                              ? PACKET_BUFFER_SIZE : (size_t)received;
        stats->delivered++;
        if (callback(buffer, captured, (uint32_t)received, linktype, timestamp, user) != 0) {
            set_error(error, error_size, "Packet processing failed during live capture.");
            goto cleanup;
        }
    }
    result = 0;

cleanup:
    {
        struct tpacket_stats packet_stats;
        socklen_t stats_length = sizeof(packet_stats);
        memset(&packet_stats, 0, sizeof(packet_stats));
        if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &packet_stats, &stats_length) == 0 &&
            stats_length >= sizeof(packet_stats)) {
            stats->kernel_stats_available = true;
            stats->kernel_received = packet_stats.tp_packets;
            stats->kernel_dropped = packet_stats.tp_drops;
        }
    }
    if (signal_handlers_installed) {
        (void)sigaction(SIGINT, &old_interrupt, NULL);
        (void)sigaction(SIGTERM, &old_terminate, NULL);
    }
    free(buffer);
    (void)close(fd); /* Also drops any PACKET_MR_PROMISC membership. */
    return result;
}
#else
int capture_list_interfaces(FILE *output, char *error, size_t error_size)
{
    (void)output;
    set_error(error, error_size, "Interface listing is available only on Linux.");
    return -1;
}

int capture_live(const char *interface_name, const CaptureOptions *options,
                 CaptureCallback callback, void *user, CaptureStats *stats,
                 char *error, size_t error_size)
{
    (void)interface_name;
    (void)options;
    (void)callback;
    (void)user;
    if (stats != NULL)
        memset(stats, 0, sizeof(*stats));
    set_error(error, error_size, "Live capture is available only on Linux; use a PCAP file here.");
    return -1;
}
#endif
