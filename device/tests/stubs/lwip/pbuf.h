#pragma once
#include <stdint.h>
struct pbuf { uint16_t tot_len; uint16_t len; struct pbuf *next; void *payload; };
uint16_t pbuf_copy_partial(const struct pbuf *p, void *out, uint16_t len, uint16_t offset);
void pbuf_free(struct pbuf *p);
