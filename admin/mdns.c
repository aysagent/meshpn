// Publish one interface-scoped alias through Avahi. Never change system hostname.
#define _GNU_SOURCE
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/address.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>

static AvahiSimplePoll *poller;
static AvahiEntryGroup *group;
static int failed, iface;
static char hostname[80];
static AvahiAddress address;
static AvahiProtocol protocol = AVAHI_PROTO_INET;
#include "mdns-negative.c.inc"
static void group_state(AvahiEntryGroup *g, AvahiEntryGroupState s, void *data) {
  (void)g; (void)data;
  established = s == AVAHI_ENTRY_GROUP_ESTABLISHED;
  if (s == AVAHI_ENTRY_GROUP_COLLISION || s == AVAHI_ENTRY_GROUP_FAILURE) { failed = 1; avahi_simple_poll_quit(poller); }
  printf("{\"state\":%d,\"hostname\":\"%s\"}\n", (int)s, hostname); fflush(stdout);
}
static void client_state(AvahiClient *client, AvahiClientState state, void *data) {
  (void)data;
  if (state == AVAHI_CLIENT_S_RUNNING) {
    if (!group) group = avahi_entry_group_new(client, group_state, NULL);
    if (!group || avahi_entry_group_add_address(group, iface, protocol,
          AVAHI_PUBLISH_NO_REVERSE, hostname, &address) < 0 || avahi_entry_group_commit(group) < 0) {
      failed = 1; avahi_simple_poll_quit(poller);
    }
  } else if (state == AVAHI_CLIENT_FAILURE) { established=0; failed = 1; avahi_simple_poll_quit(poller); }
  else if (group && (state == AVAHI_CLIENT_S_REGISTERING || state == AVAHI_CLIENT_S_COLLISION)) { established=0; avahi_entry_group_reset(group); }
}
int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--capabilities") == 0) {
    puts("{\"interface_scoped\":true,\"dual_stack_transport\":true,\"ipv4_alias_negative_aaaa\":true}"); return 0;
  }
  if (argc == 5 && strcmp(argv[4], "dual-stack") == 0) protocol = AVAHI_PROTO_UNSPEC;
  else if (argc != 4) return 1;
  if (!(iface = if_nametoindex(argv[1])) || strlen(argv[2]) < 1 || strlen(argv[2]) > 63 ||
      !avahi_address_parse(argv[3], AVAHI_PROTO_INET, &address)) return 1;
  for (const char *p = argv[2]; *p; ++p) if (!(*p >= 'a' && *p <= 'z') && !isdigit((unsigned char)*p) && *p != '-') return 1;
  if (argv[2][0] == '-' || argv[2][strlen(argv[2])-1] == '-') return 1;
  snprintf(hostname, sizeof hostname, "%s.local", argv[2]);
  poller = avahi_simple_poll_new(); if (!poller) return 1;
  int error = 0;
  AvahiClient *client = avahi_client_new(avahi_simple_poll_get(poller), 0, client_state, NULL, &error);
  if (!client) { avahi_simple_poll_free(poller); return 1; }
  // The default USB alias is deliberately IPv4-only. Management's dual-stack
  // publication retains its existing behavior until it has separate acceptance.
  if (protocol == AVAHI_PROTO_INET && negative_start(argv[3]) < 0) fprintf(stderr,"mdns_negative_unavailable\n");
  avahi_simple_poll_loop(poller);
  negative_stop();
  avahi_client_free(client); avahi_simple_poll_free(poller); return failed;
}
