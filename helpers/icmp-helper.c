/*
 * ICMP helper for Linux
 * Sends ICMP Echo Requests and receives Echo Replies
 * Requires CAP_NET_RAW or root
 * 
 * Protocol (text-based, line-oriented):
 * - Request (stdin):  REQ <dst_ip> <id> <seq> <payload_hex>\n
 * - Response (stdout): REP <src_ip> <id> <seq> <ttl> <payload_hex>\n
 * - Timeout (stdout):  TIMEOUT <id> <seq>\n
 * - Error (stderr):    ERROR <message>\n
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define MAX_PACKET_SIZE 65536
#define RECV_TIMEOUT_MS 3000
#define MAX_LINE 4096
#define MAX_PENDING 256

typedef struct {
    int active;
    uint16_t id;
    uint16_t seq;
    struct timeval sent_time;
    struct in_addr dst;
} pending_request_t;

static int sock_fd = -1;
static volatile int running = 1;
static pending_request_t pending[MAX_PENDING];
static int pending_count = 0;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

uint16_t checksum(void *data, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = data;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)~sum;
}

int hex_to_bytes(const char *hex, uint8_t *out, int max_len) {
    int len = 0;
    while (*hex && *(hex + 1) && len < max_len) {
        char byte_str[3] = { hex[0], hex[1], 0 };
        out[len++] = (uint8_t)strtol(byte_str, NULL, 16);
        hex += 2;
    }
    return len;
}

void bytes_to_hex(const uint8_t *data, int len, char *out) {
    for (int i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

int find_pending(uint16_t id, uint16_t seq) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].active && pending[i].id == id && pending[i].seq == seq) {
            return i;
        }
    }
    return -1;
}

int add_pending(uint16_t id, uint16_t seq, struct in_addr dst) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending[i].active) {
            pending[i].active = 1;
            pending[i].id = id;
            pending[i].seq = seq;
            pending[i].dst = dst;
            gettimeofday(&pending[i].sent_time, NULL);
            pending_count++;
            return i;
        }
    }
    return -1;
}

void remove_pending(int idx) {
    if (idx >= 0 && idx < MAX_PENDING && pending[idx].active) {
        pending[idx].active = 0;
        pending_count--;
    }
}

void check_timeouts(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].active) {
            long elapsed_ms = (now.tv_sec - pending[i].sent_time.tv_sec) * 1000 +
                             (now.tv_usec - pending[i].sent_time.tv_usec) / 1000;
            
            if (elapsed_ms > RECV_TIMEOUT_MS) {
                printf("TIMEOUT %u %u\n", pending[i].id, pending[i].seq);
                fflush(stdout);
                remove_pending(i);
            }
        }
    }
}

int send_icmp_request(const char *dst_ip, uint16_t id, uint16_t seq, 
                      const uint8_t *payload, int payload_len) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    if (inet_pton(AF_INET, dst_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "ERROR Invalid IP: %s\n", dst_ip);
        return -1;
    }
    
    uint8_t packet[MAX_PACKET_SIZE];
    struct icmphdr *icmp = (struct icmphdr *)packet;
    
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(id);
    icmp->un.echo.sequence = htons(seq);
    
    if (payload_len > 0 && payload_len < MAX_PACKET_SIZE - sizeof(struct icmphdr)) {
        memcpy(packet + sizeof(struct icmphdr), payload, payload_len);
    }
    
    int packet_len = sizeof(struct icmphdr) + payload_len;
    icmp->checksum = checksum(packet, packet_len);
    
    if (sendto(sock_fd, packet, packet_len, 0, 
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ERROR sendto failed: %s\n", strerror(errno));
        return -1;
    }
    
    add_pending(id, seq, addr.sin_addr);
    return 0;
}

void handle_icmp_reply(void) {
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    
    int len = recvfrom(sock_fd, buffer, sizeof(buffer), 0,
                       (struct sockaddr *)&from, &from_len);
    
    if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "ERROR recvfrom: %s\n", strerror(errno));
        }
        return;
    }
    
    if (len < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr))) {
        return;
    }
    
    struct iphdr *ip = (struct iphdr *)buffer;
    int ip_hdr_len = ip->ihl * 4;
    
    if (len < ip_hdr_len + (int)sizeof(struct icmphdr)) {
        return;
    }
    
    struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_hdr_len);
    
    if (icmp->type != ICMP_ECHOREPLY) {
        return;
    }
    
    uint16_t id = ntohs(icmp->un.echo.id);
    uint16_t seq = ntohs(icmp->un.echo.sequence);
    
    int idx = find_pending(id, seq);
    if (idx < 0) {
        return;
    }
    
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, src_ip, sizeof(src_ip));
    
    int payload_len = len - ip_hdr_len - sizeof(struct icmphdr);
    uint8_t *payload = buffer + ip_hdr_len + sizeof(struct icmphdr);
    
    char payload_hex[MAX_PACKET_SIZE * 2 + 1];
    if (payload_len > 0) {
        bytes_to_hex(payload, payload_len, payload_hex);
    } else {
        payload_hex[0] = '\0';
    }
    
    printf("REP %s %u %u %u %s\n", src_ip, id, seq, ip->ttl, payload_hex);
    fflush(stdout);
    
    remove_pending(idx);
}

void process_stdin_line(char *line) {
    char cmd[16];
    char dst_ip[64];
    unsigned int id, seq;
    char payload_hex[MAX_LINE];
    
    payload_hex[0] = '\0';
    
    int n = sscanf(line, "%15s %63s %u %u %s", cmd, dst_ip, &id, &seq, payload_hex);
    
    if (n < 4) {
        fprintf(stderr, "ERROR Invalid command format\n");
        return;
    }
    
    if (strcmp(cmd, "REQ") != 0) {
        fprintf(stderr, "ERROR Unknown command: %s\n", cmd);
        return;
    }
    
    uint8_t payload[MAX_PACKET_SIZE];
    int payload_len = 0;
    
    if (strlen(payload_hex) > 0) {
        payload_len = hex_to_bytes(payload_hex, payload, sizeof(payload));
    }
    
    send_icmp_request(dst_ip, (uint16_t)id, (uint16_t)seq, payload, payload_len);
}

int main(void) {
    char line_buffer[MAX_LINE];
    int line_pos = 0;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    memset(pending, 0, sizeof(pending));
    
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0) {
        fprintf(stderr, "ERROR Failed to create raw socket: %s\n", strerror(errno));
        fprintf(stderr, "ERROR Run with root or set CAP_NET_RAW\n");
        return 1;
    }
    
    int flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
    
    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    fprintf(stderr, "READY\n");
    fflush(stderr);
    
    fd_set read_fds;
    int max_fd = (sock_fd > STDIN_FILENO) ? sock_fd : STDIN_FILENO;
    
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (FD_ISSET(sock_fd, &read_fds)) {
            handle_icmp_reply();
        }
        
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char buf[1024];
            int n = read(STDIN_FILENO, buf, sizeof(buf));
            
            if (n == 0) {
                running = 0;
                break;
            }
            
            if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    running = 0;
                }
                continue;
            }
            
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n') {
                    line_buffer[line_pos] = '\0';
                    if (line_pos > 0) {
                        process_stdin_line(line_buffer);
                    }
                    line_pos = 0;
                } else if (line_pos < MAX_LINE - 1) {
                    line_buffer[line_pos++] = buf[i];
                }
            }
        }
        
        check_timeouts();
    }
    
    if (sock_fd >= 0) {
        close(sock_fd);
    }
    
    return 0;
}
