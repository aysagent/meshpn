/* Inserted into the build copy of lwIP, after the existing NAPT helpers.
 * ICMP errors quote the translated outgoing tuple, including the NAT port.
 * Restore both that tuple and the outer destination before local delivery.
 * Copy bounded headers so chained pbufs and short TCP quotations are safe. */
static int
meshpn_napt_icmp_error(struct pbuf *p, struct ip_hdr *iphdr)
{
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
      (quote[6] & 0x1f) || quote[7] || memcmp(quote + 12, &iphdr->dest.addr, 4)) return 0;
  u16_t available = total - outer - 8;
  if (available > quoted_total) available = quoted_total;
  if (available > ihl + 20) available = ihl + 20;
  available &= (u16_t)~1; /* checksumadjust consumes complete 16-bit words */
  if (pbuf_copy_partial(p, header, outer + 8 + available, 0) != outer + 8 + available ||
      inet_chksum(quote, ihl)) return 0;
  u8_t *l4 = quote + ihl;
  u32_t remote;
  u16_t port, mapped;
  memcpy(&remote, quote + 16, 4);
  if (quote[9] == IP_PROTO_TCP || quote[9] == IP_PROTO_UDP) {
    memcpy(&mapped, l4, 2); memcpy(&port, l4 + 2, 2);
  } else if (quote[9] == IP_PROTO_ICMP && l4[0] == 8) {
    memcpy(&mapped, l4 + 4, 2); port = mapped;
  } else return 0;
  struct ip_napt_entry *entry = ip_napt_find(quote[9], remote, port, mapped, 1);
  if (!entry) return 0;
  memcpy(previous, quote, available);
  if (quote[9] == IP_PROTO_TCP || quote[9] == IP_PROTO_UDP) {
    u16_t offset = quote[9] == IP_PROTO_TCP ? 16 : 6;
    if (available >= ihl + offset + 2 &&
        (quote[9] != IP_PROTO_UDP || l4[offset] || l4[offset + 1])) {
      checksumadjust(l4 + offset, quote + 12, 4, (u8_t *)&entry->src, 4);
      checksumadjust(l4 + offset, l4, 2, (u8_t *)&entry->sport, 2);
      if (quote[9] == IP_PROTO_UDP && !l4[offset] && !l4[offset + 1])
        l4[offset] = l4[offset + 1] = 0xff;
    }
    memcpy(l4, &entry->sport, 2);
  } else {
    checksumadjust(l4 + 2, l4 + 4, 2, (u8_t *)&entry->sport, 2);
    memcpy(l4 + 4, &entry->sport, 2);
  }
  checksumadjust(quote + 10, quote + 12, 4, (u8_t *)&entry->src, 4);
  memcpy(quote + 12, &entry->src, 4);
  checksumadjust(icmp + 2, previous, available, quote, available);
  struct ip_hdr *outer_header = (struct ip_hdr *)header;
  ip_napt_modify_addr(outer_header, &outer_header->dest, entry->src);
  return pbuf_take_at(p, header, outer + 8 + available, 0) == ERR_OK;
}
