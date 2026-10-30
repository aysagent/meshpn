/* Inserted into the build copy of lwIP, after the existing NAPT helpers.
 * Incoming errors restore the quoted outgoing tuple and outer destination.
 * Outgoing errors translate the quoted incoming tuple and outer source.
 * Both directions require a matching NAPT flow; ICMP carries no ports itself.
 * Copy bounded headers so chained pbufs and short TCP quotations are safe. */
static int
meshpn_napt_icmp_error_map(struct pbuf *p, struct ip_hdr *iphdr, const u32_t *external)
{
  const int outbound = external != NULL;
  const unsigned address_offset = outbound ? 16 : 12;
  const unsigned port_offset = outbound ? 2 : 0;
  u8_t header[148], previous[80];
  u16_t outer = IPH_HL(iphdr) * 4;
  u16_t total = lwip_ntohs(IPH_LEN(iphdr));
  if (outer < 20 || outer > 60 || total > p->tot_len || total < outer + 8 + 20 + 8)
    return 0;
  if (pbuf_copy_partial(p, header, outer + 8 + 20, 0) != outer + 8 + 20)
    return 0;
  u8_t *icmp = header + outer, *quote = icmp + 8;
  if (icmp[0] != 3 && icmp[0] != 11 && icmp[0] != 12) return 0;
  u16_t ihl = (quote[0] & 15) * 4;
  u16_t quoted_total = ((u16_t)quote[2] << 8) | quote[3];
  if ((quote[0] >> 4) != 4 || ihl < 20 || ihl > 60 ||
      quoted_total < ihl + 8 || total < outer + 8 + ihl + 8 ||
      (quote[6] & 0x1f) || quote[7] || memcmp(quote + address_offset, outbound ? &iphdr->src.addr : &iphdr->dest.addr, 4)) return 0;
  u16_t available = total - outer - 8;
  if (available > quoted_total) available = quoted_total;
  if (available > ihl + 20) available = ihl + 20;
  available &= (u16_t)~1; /* checksumadjust consumes complete 16-bit words */
  if (pbuf_copy_partial(p, header, outer + 8 + available, 0) != outer + 8 + available ||
      inet_chksum(quote, ihl)) return 0;
  u8_t *l4 = quote + ihl;
  u32_t remote;
  u16_t port, mapped;
  memcpy(&remote, quote + (outbound ? 12 : 16), 4);
  if (outbound && remote != iphdr->dest.addr) return 0;
  if (quote[9] == IP_PROTO_TCP || quote[9] == IP_PROTO_UDP) {
    memcpy(&mapped, l4 + port_offset, 2); memcpy(&port, l4 + (outbound ? 0 : 2), 2);
  } else if (quote[9] == IP_PROTO_ICMP && l4[0] == (outbound ? 0 : 8)) {
    memcpy(&mapped, l4 + 4, 2); port = mapped;
  } else return 0;
  struct ip_napt_entry *entry;
  if (outbound) {
    u32_t local; memcpy(&local, quote + 16, 4);
    entry = ip_napt_find(quote[9], local, mapped, 0, 0);
    /* Source-side lookup alone is insufficient: require the quoted remote
     * tuple too, so one mapping cannot translate another flow's error. */
    if (!entry || entry->dest != remote || entry->dport != port) return 0;
  } else entry = ip_napt_find(quote[9], remote, port, mapped, 1);
  if (!entry) return 0;
  u32_t translated_address = outbound ? *external : entry->src;
  u16_t translated_port = outbound ? entry->mport : entry->sport;
  memcpy(previous, quote, available);
  if (quote[9] == IP_PROTO_TCP || quote[9] == IP_PROTO_UDP) {
    u16_t offset = quote[9] == IP_PROTO_TCP ? 16 : 6;
    if (available >= ihl + offset + 2 &&
        (quote[9] != IP_PROTO_UDP || l4[offset] || l4[offset + 1])) {
      checksumadjust(l4 + offset, quote + address_offset, 4, (u8_t *)&translated_address, 4);
      checksumadjust(l4 + offset, l4 + port_offset, 2, (u8_t *)&translated_port, 2);
      if (quote[9] == IP_PROTO_UDP && !l4[offset] && !l4[offset + 1])
        l4[offset] = l4[offset + 1] = 0xff;
    }
    memcpy(l4 + port_offset, &translated_port, 2);
  } else {
    checksumadjust(l4 + 2, l4 + 4, 2, (u8_t *)&translated_port, 2);
    memcpy(l4 + 4, &translated_port, 2);
  }
  checksumadjust(quote + 10, quote + address_offset, 4, (u8_t *)&translated_address, 4);
  memcpy(quote + address_offset, &translated_address, 4);
  checksumadjust(icmp + 2, previous, available, quote, available);
  struct ip_hdr *outer_header = (struct ip_hdr *)header;
  ip_napt_modify_addr(outer_header, outbound ? &outer_header->src : &outer_header->dest, translated_address);
  return pbuf_take_at(p, header, outer + 8 + available, 0) == ERR_OK;
}

static int
meshpn_napt_icmp_error(struct pbuf *p, struct ip_hdr *iphdr)
{
  return meshpn_napt_icmp_error_map(p, iphdr, NULL);
}
