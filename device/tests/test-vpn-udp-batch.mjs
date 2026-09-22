// Compile the production UDP drain against real datagram sockets: boundaries,
// bounded work, oversize/empty rejection and nonblocking exhaustion.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

const production = fs.readFileSync(new URL('../components/meshvpn_vpn/meshvpn_vpn.c', import.meta.url), 'utf8');
function section(from, to) {
  const begin = production.indexOf(from), end = production.indexOf(to, begin);
  if (begin < 0 || end < begin) throw Error(`Production UDP section not found: ${from}`);
  return production.slice(begin, end);
}

const source = `
#define _DEFAULT_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define MESHVPN_VPN_MTU 1400
#define MESHVPN_VPN_UDP_RX_BATCH_FRAMES 32
#define MESHVPN_VPN_UDP_RX_BATCH_US 4000
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#define COUNT(field) (++s.field)
static struct { unsigned rx_invalid; } s;
static int64_t now, clock_step = 1;
static int64_t esp_timer_get_time(void) { return now += clock_step; }
${section('#define MESHVPN_VPN_SOCKET_RX_BYTES ', 'static packet_t *s_queue;')}
${section('static bool receive_packet(', 'int meshvpn_vpn_dns_socket(')}
int main(void) {
  int fd[2]; assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fd) == 0);
  assert(fcntl(fd[1], F_SETFL, O_NONBLOCK) == 0);
  uint8_t packet[100] = {0}, rx[MESHVPN_VPN_MTU + 1] = {0};
  rx_batch_t batch = {0};
  for (unsigned i = 0; i < MESHVPN_VPN_UDP_RX_BATCH_FRAMES + 4; i++) {
    packet[0] = (uint8_t)i;
    assert(send(fd[0], packet, sizeof(packet), 0) == sizeof(packet));
  }
  assert(receive_udp_batch(fd[1], rx, &batch) == 0);
  assert(batch.count == MESHVPN_VPN_UDP_RX_BATCH_FRAMES &&
         batch.used == MESHVPN_VPN_UDP_RX_BATCH_FRAMES * 100);
  for (unsigned i = 0; i < batch.count; i++)
    assert(batch.lengths[i] == 100 && batch.data[batch.offsets[i]] == i);
  batch.count = batch.used = 0;
  assert(receive_udp_batch(fd[1], rx, &batch) == 0);
  assert(batch.count == 4 && batch.used == 400);
  for (unsigned i = 0; i < batch.count; i++)
    assert(batch.data[batch.offsets[i]] == i + MESHVPN_VPN_UDP_RX_BATCH_FRAMES);
  batch.count = batch.used = 0;
  assert(receive_udp_batch(fd[1], rx, &batch) == 0 && !batch.count);
  uint8_t oversized[MESHVPN_VPN_MTU + 1] = {0};
  assert(send(fd[0], oversized, sizeof(oversized), 0) == sizeof(oversized));
  assert(send(fd[0], packet, 0, 0) == 0);
  packet[0] = 0xa5;
  assert(send(fd[0], packet, sizeof(packet), 0) == sizeof(packet));
  assert(receive_udp_batch(fd[1], rx, &batch) == 0);
  assert(s.rx_invalid == 2 && batch.count == 1 && batch.data[0] == 0xa5);
  batch.count = batch.used = 0;
  for (unsigned i = 0; i < 5; i++) {
    packet[0] = (uint8_t)i;
    assert(send(fd[0], packet, sizeof(packet), 0) == sizeof(packet));
  }
  clock_step = MESHVPN_VPN_UDP_RX_BATCH_US / 2;
  assert(receive_udp_batch(fd[1], rx, &batch) == 0 && batch.count == 2);
  clock_step = 1;
  batch.count = batch.used = 0;
  assert(receive_udp_batch(fd[1], rx, &batch) == 0 && batch.count == 3);
  assert(receive_udp_batch(-1, rx, &batch) == EBADF);
  close(fd[0]); close(fd[1]);
  puts("UDP RX: frame/time-bounded drain, datagram order, invalid sizes and EAGAIN passed");
}
`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'meshpn-vpn-udp-batch-'));
const file = path.join(dir, 'test.c'), binary = path.join(dir, 'test');
fs.writeFileSync(file, source);
execFileSync(process.env.CC || 'cc', ['-std=c11', '-Wall', '-Wextra', '-Werror',
  '-fsanitize=address,undefined', file, '-o', binary], {stdio: 'inherit'});
execFileSync(binary, {stdio: 'inherit'});
