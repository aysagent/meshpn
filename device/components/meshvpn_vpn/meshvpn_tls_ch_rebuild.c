#include "meshvpn_tls_ch_rebuild.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"

typedef struct {
    size_t hostname_start;
    size_t hostname_len;
    size_t sni_list_len_pos;
    size_t sni_ext_len_pos;
    size_t extensions_total_len_pos;
} sni_layout_t;

static bool find_sni_layout(const uint8_t *ch, size_t ch_len, sni_layout_t *layout, char *origin, size_t origin_cap)
{
    size_t o = 34;
    if (ch_len < o + 1) {
        return false;
    }
    uint8_t sid_len = ch[o++];
    o += sid_len;
    if (ch_len < o + 2) {
        return false;
    }
    uint16_t cs_len = (uint16_t)((ch[o] << 8) | ch[o + 1]);
    o += 2 + cs_len;
    if (ch_len < o + 1) {
        return false;
    }
    uint8_t comp_len = ch[o++];
    o += comp_len;
    if (ch_len < o + 2) {
        return false;
    }

    layout->extensions_total_len_pos = o;
    uint16_t ext_len = (uint16_t)((ch[o] << 8) | ch[o + 1]);
    o += 2;
    size_t ext_block_start = o;
    size_t ext_end = ext_block_start + ext_len;
    if (ch_len < ext_end) {
        return false;
    }

    size_t eo = ext_block_start;
    while (eo + 4 <= ext_end) {
        uint16_t et = (uint16_t)((ch[eo] << 8) | ch[eo + 1]);
        uint16_t el = (uint16_t)((ch[eo + 2] << 8) | ch[eo + 3]);
        size_t body = eo + 4;
        eo = body + el;
        if (et != 0 || el < 2) {
            continue;
        }
        size_t so = body + 2;
        if (so + 3 > body + el) {
            continue;
        }
        uint8_t nt = ch[so];
        uint16_t nl = (uint16_t)((ch[so + 1] << 8) | ch[so + 2]);
        so += 3;
        if (nt != 0 || so + nl > body + el) {
            continue;
        }
        layout->hostname_start = so;
        layout->hostname_len = nl;
        layout->sni_list_len_pos = body;
        layout->sni_ext_len_pos = eo - el - 2;
        if (origin && origin_cap > nl) {
            memcpy(origin, ch + so, nl);
            origin[nl] = '\0';
        }
        return true;
    }
    return false;
}

esp_err_t meshvpn_tls_ch_replace_sni(const uint8_t *tcp_buf, size_t tcp_len,
                                     const char *new_hostname,
                                     uint8_t **out_buf, size_t *out_len,
                                     char *origin_sni, size_t origin_cap)
{
    if (tcp_len < 5 || tcp_buf[0] != 0x16) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t rec_len = ((size_t)tcp_buf[3] << 8) | tcp_buf[4];
    if (tcp_len < 5 + rec_len || rec_len < 4) {
        return ESP_ERR_INVALID_SIZE;
    }

    const uint8_t *hs = tcp_buf + 5;
    if (hs[0] != 0x01) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    size_t ch_len = ((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3];
    if (rec_len < 4 + ch_len) {
        return ESP_ERR_INVALID_SIZE;
    }
    const uint8_t *ch = hs + 4;

    sni_layout_t layout;
    if (!find_sni_layout(ch, ch_len, &layout, origin_sni, origin_cap)) {
        return ESP_ERR_NOT_FOUND;
    }

    size_t new_hlen = strlen(new_hostname);
    if (new_hlen == 0 || new_hlen > 253) {
        return ESP_ERR_INVALID_ARG;
    }

    int delta = (int)new_hlen - (int)layout.hostname_len;
    size_t new_ch_len = ch_len + (size_t)(delta >= 0 ? delta : -delta);
    uint8_t *new_ch = malloc(new_ch_len);
    if (!new_ch) {
        return ESP_ERR_NO_MEM;
    }

    memcpy(new_ch, ch, layout.hostname_start);
    memcpy(new_ch + layout.hostname_start, new_hostname, new_hlen);
    memcpy(new_ch + layout.hostname_start + new_hlen,
           ch + layout.hostname_start + layout.hostname_len,
           ch_len - layout.hostname_start - layout.hostname_len);

    new_ch[layout.hostname_start - 2] = (uint8_t)(new_hlen >> 8);
    new_ch[layout.hostname_start - 1] = (uint8_t)(new_hlen);

    uint16_t list_len = (uint16_t)((new_ch[layout.sni_list_len_pos] << 8) | new_ch[layout.sni_list_len_pos + 1]);
    list_len = (uint16_t)(list_len + delta);
    new_ch[layout.sni_list_len_pos] = (uint8_t)(list_len >> 8);
    new_ch[layout.sni_list_len_pos + 1] = (uint8_t)(list_len);

    uint16_t sni_ext = (uint16_t)((new_ch[layout.sni_ext_len_pos] << 8) | new_ch[layout.sni_ext_len_pos + 1]);
    sni_ext = (uint16_t)(sni_ext + delta);
    new_ch[layout.sni_ext_len_pos] = (uint8_t)(sni_ext >> 8);
    new_ch[layout.sni_ext_len_pos + 1] = (uint8_t)(sni_ext);

    uint16_t ext_total = (uint16_t)((new_ch[layout.extensions_total_len_pos] << 8) |
                                    new_ch[layout.extensions_total_len_pos + 1]);
    ext_total = (uint16_t)(ext_total + delta);
    new_ch[layout.extensions_total_len_pos] = (uint8_t)(ext_total >> 8);
    new_ch[layout.extensions_total_len_pos + 1] = (uint8_t)(ext_total);

    size_t hs_plain_len = 4 + new_ch_len;
    size_t prefix_len = 5 + hs_plain_len;
    size_t tail_len = tcp_len - (5 + rec_len);
    uint8_t *prefix = malloc(prefix_len);
    if (!prefix) {
        free(new_ch);
        return ESP_ERR_NO_MEM;
    }

    prefix[0] = 0x16;
    prefix[1] = tcp_buf[1];
    prefix[2] = tcp_buf[2];
    prefix[3] = (uint8_t)(hs_plain_len >> 8);
    prefix[4] = (uint8_t)(hs_plain_len);
    prefix[5] = 0x01;
    prefix[6] = (uint8_t)(new_ch_len >> 16);
    prefix[7] = (uint8_t)(new_ch_len >> 8);
    prefix[8] = (uint8_t)(new_ch_len);
    memcpy(prefix + 9, new_ch, new_ch_len);
    free(new_ch);

    *out_buf = prefix;
    *out_len = prefix_len;
    (void)tail_len;
    return ESP_OK;
}
