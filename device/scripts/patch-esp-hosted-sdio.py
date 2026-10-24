#!/usr/bin/env python3
"""Reserve ESP-Hosted SDIO streaming DMA memory before network traffic.

The pinned esp_hosted 1.4.7 driver grows two internal DMA buffers while RX is
active, then asserts if a large aligned allocation fails. Use one reserved
buffer and process each stream before the next read. This fits the slave's
20 x 1536-byte send queue without increasing the total 32 KiB DMA reserve.
CPU-owned RX packet/payload copies use PSRAM; validate stream bounds before
calling the header/checksum validator.
"""

import argparse
from pathlib import Path


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("ESP-Hosted SDIO source changed; re-audit the RX buffer patch")
    return source.replace(old, new, 1)


GET_BUFFER = """\t// (re)allocate a write buffer big enough to contain the data stream
\tint index = double_buf.write_index;
\tuint8_t ** buf = &double_buf.buffer[index].buf;

\tif (len > double_buf.buffer[index].buf_size) {
\t\tif (*buf) {
\t\t\t// free already allocated memory
\t\t\tg_h.funcs->_h_free(*buf);
\t\t}
\t\t*buf = (uint8_t *)MEM_ALLOC(len);
\t\tassert(*buf);
\t\tdouble_buf.buffer[index].buf_size = len;
\t\tESP_LOGD(TAG, "buf %d size: %ld", index, double_buf.buffer[index].buf_size);
\t}
\treturn *buf;
"""

GET_BUFFER_FIXED = """\t// The DMA buffer was reserved before Wi-Fi starts. Never grow it
\t// during RX, when the internal heap can be fragmented by packet buffers.
\tint index = double_buf.write_index;
\tif (len > double_buf.buffer[index].buf_size) {
\t\tESP_LOGE(TAG, "SDIO RX stream too large: %" PRIu32 " > %" PRIu32,
\t\t         len, double_buf.buffer[index].buf_size);
\t\treturn NULL;
\t}
\treturn double_buf.buffer[index].buf;
"""

INIT = """\tdouble_buf.read_index = -1; // indicates we are not reading anything
\tdouble_buf.write_index = 0; // we will write into the first buffer
"""

INIT_FIXED = INIT + """
#if H_SDIO_HOST_RX_MODE == H_SDIO_HOST_STREAMING_MODE
\t// The C6 slave has a 20-packet send queue at up to 1536 bytes each.
\t// Processing each read synchronously lets one 32 KiB buffer cover it.
\tdouble_buf.buffer[0].buf = MEM_ALLOC(32 * 1024);
\tassert(double_buf.buffer[0].buf);
\tdouble_buf.buffer[0].buf_size = 32 * 1024;
#endif
"""

READ = """\t\t/* Allocate rx buffer */
\t\trxbuff = sdio_rx_get_buffer(len_from_slave);
\t\tassert(rxbuff);

\t\tdata_left = len_from_slave;
"""

READ_FIXED = """\t\t/* The stream is larger than the reserved DMA buffer. Drain it in
\t\t * bounded chunks to keep the slave byte counter synchronized, then
\t\t * discard it instead of asserting or writing past the buffer. */
\t\trxbuff = sdio_rx_get_buffer(len_from_slave);
\t\tif (!rxbuff) {
\t\t\tuint32_t capacity = double_buf.buffer[double_buf.write_index].buf_size;
\t\t\tuint8_t *discard = double_buf.buffer[double_buf.write_index].buf;
\t\t\tdata_left = len_from_slave;
\t\t\tret = ESP_OK;
\t\t\twhile (data_left) {
\t\t\t\tlen_to_read = data_left > capacity ? capacity : data_left;
\t\t\t\tuint32_t transfer_len = ((len_to_read + ESP_BLOCK_SIZE - 1) / ESP_BLOCK_SIZE) * ESP_BLOCK_SIZE;
\t\t\t\tret = g_h.funcs->_h_sdio_read_block(sdio_handle,
\t\t\t\t        ESP_SLAVE_CMD53_END_ADDR - data_left, discard,
\t\t\t\t        transfer_len, ACQUIRE_LOCK);
\t\t\t\tif (ret) break;
\t\t\t\tdata_left -= len_to_read;
\t\t\t}
\t\t\tSDIO_DRV_UNLOCK();
\t\t\tsdio_rx_byte_count = (sdio_rx_byte_count + len_from_slave - data_left) % ESP_RX_BYTE_MAX;
\t\t\tif (ret) ESP_LOGE(TAG, "failed to drain oversized SDIO RX stream: %d", ret);
\t\t\tcontinue;
\t\t}

\t\tdata_left = len_from_slave;
"""

RX_PACKET = """\t\t/* Allocate rx buffer */
\t\tpkt_rxbuff = sdio_buffer_alloc(MEMSET_REQUIRED);
\t\tassert(pkt_rxbuff);

\t\tpacket_size = len + offset;
\t\tif (packet_size > buf_len) {
\t\t\tESP_LOGE(TAG, "packet size too big for remaining stream data");
\t\t\treturn ESP_FAIL;
\t\t}
\t\tmemcpy(pkt_rxbuff, buf, packet_size);
"""

RX_PACKET_SAFE = """\t\tpacket_size = len + offset;
\t\tif (packet_size > buf_len) {
\t\t\tESP_LOGE(TAG, "packet size too big for remaining stream data");
\t\t\treturn ESP_FAIL;
\t\t}
\t\t/* A temporary packet allocation failure drops a frame, not the host. */
\t\tpkt_rxbuff = sdio_buffer_alloc(MEMSET_REQUIRED);
\t\tif (!pkt_rxbuff) {
\t\t\tESP_LOGD(TAG, "SDIO RX packet dropped: no packet memory");
\t\t\tbuf_len -= packet_size;
\t\t\tbuf += packet_size;
\t\t\tcontinue;
\t\t}
\t\tmemcpy(pkt_rxbuff, buf, packet_size);
"""

RX_COPY = """\t\t\t\tuint8_t * copy_payload = (uint8_t *)g_h.funcs->_h_malloc(buf_handle->payload_len);
\t\t\t\tassert(copy_payload);
"""

RX_COPY_SAFE = """\t\t\t\tuint8_t * copy_payload = (uint8_t *)g_h.funcs->_h_malloc(buf_handle->payload_len);
\t\t\t\tif (!copy_payload) {
\t\t\t\t\tH_FREE_PTR_WITH_FUNC(buf_handle->free_buf_handle, buf_handle->priv_buffer_handle);
\t\t\t\t\tESP_LOGD(TAG, "SDIO RX payload dropped: no memory");
\t\t\t\t\tcontinue;
\t\t\t\t}
"""

RX_COMPLETE = """\t\tif (double_buf.read_index < 0) {
\t\t\tdouble_buf.read_index = double_buf.write_index;
\t\t\tdouble_buf.read_data_len = len_from_slave;
\t\t\tdouble_buf.write_index = (double_buf.write_index) ? 0 : 1;
\t\t\t// trigger task to copy data to queue
\t\t\tg_h.funcs->_h_post_semaphore(sem_double_buf_xfer_data);
\t\t} else {
\t\t\t// error: task to copy data to queue still running
\t\t\tESP_LOGE(TAG, "task still writing Rx data to queue!");
\t\t\t// don't send data to task, or update write_index
\t\t}
"""

RX_COMPLETE_SYNC = """\t\t// Process before reusing the only DMA buffer. The SDIO lock is
\t\t// already released; the packet queue owns its copied frames.
\t\tif (sdio_push_data_to_queue(rxbuff, len_from_slave))
\t\t\tESP_LOGE(TAG, "Failed to push data to rx queue");
"""


def patch(source: str) -> str:
    source = replace_once(source, GET_BUFFER, GET_BUFFER_FIXED)
    source = replace_once(source, INIT, INIT_FIXED)
    source = replace_once(source, READ, READ_FIXED)
    source = replace_once(source, RX_PACKET, RX_PACKET_SAFE)
    source = replace_once(source, RX_COPY, RX_COPY_SAFE)
    source = replace_once(source, "\t\t\tassert(sendbuf);\n", "")
    source = replace_once(source, RX_COMPLETE, RX_COMPLETE_SYNC)
    # The upstream validator reads the header and optionally checksums the
    # declared packet before seeing the remaining stream length. Bound both
    # accesses first, including a truncated header after a valid packet.
    source = replace_once(source,
                          "\tdo {\n\t\tif (!is_valid_sdio_rx_packet(buf, &len, &offset)) {",
                          "\tdo {\n"
                          "\t\tif (buf_len < sizeof(struct esp_payload_header)) {\n"
                          "\t\t\tmeshvpn_hosted_rx_drop(2, buf_len);\n\t\t\treturn ESP_FAIL;\n\t\t}\n"
                          "\t\tconst struct esp_payload_header *header = (const struct esp_payload_header *)buf;\n"
                          "\t\tif ((uint32_t)le16toh(header->len) + le16toh(header->offset) > buf_len) {\n"
                          "\t\t\tmeshvpn_hosted_rx_drop(2, buf_len);\n\t\t\treturn ESP_FAIL;\n\t\t}\n"
                          "\t\tif (!is_valid_sdio_rx_packet(buf, &len, &offset)) {\n"
                          "\t\t\tmeshvpn_hosted_rx_drop(2, buf_len);")
    # Only the stream read buffer needs SDIO DMA. Queue-owned packet copies
    # and delivered Wi-Fi payloads are CPU data; do not exhaust internal DMA
    # memory while USB/lwIP retain several packets in parallel.
    source = replace_once(source, "\t\tpkt_rxbuff = sdio_buffer_alloc(MEMSET_REQUIRED);",
                          "\t\tpkt_rxbuff = heap_caps_malloc(packet_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);")
    source = replace_once(source, "\tbuf_handle.free_buf_handle    = sdio_buffer_free;",
                          "#if H_SDIO_HOST_RX_MODE == H_SDIO_HOST_STREAMING_MODE\n"
                          "\tbuf_handle.free_buf_handle    = heap_caps_free;\n"
                          "#else\n\tbuf_handle.free_buf_handle    = sdio_buffer_free;\n#endif")
    source = replace_once(source, "uint8_t * copy_payload = (uint8_t *)g_h.funcs->_h_malloc(buf_handle->payload_len);",
                          "uint8_t * copy_payload = heap_caps_malloc(buf_handle->payload_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);")
    source = replace_once(source, "\t\tif (!rxbuff) {\n",
                          "\t\tif (!rxbuff) {\n\t\t\tmeshvpn_hosted_rx_drop(1, len_from_slave);\n")
    source = replace_once(source, "\t\tif (packet_size > buf_len) {\n",
                          "\t\tif (packet_size > buf_len) {\n\t\t\tmeshvpn_hosted_rx_drop(2, buf_len);\n")
    source = replace_once(source, "\t\tif (!pkt_rxbuff) {\n",
                          "\t\tif (!pkt_rxbuff) {\n\t\t\tmeshvpn_hosted_rx_drop(0, packet_size);\n")
    source = replace_once(source, "\t\t\t\tif (!copy_payload) {\n",
                          "\t\t\t\tif (!copy_payload) {\n\t\t\t\t\tmeshvpn_hosted_rx_drop(3, buf_handle->payload_len);\n")
    source = "/* MeshPN bounded SDIO drop accounting; no payload retained. */\n#include \"esp_heap_caps.h\"\nextern void meshvpn_hosted_rx_drop(unsigned reason, unsigned bytes);\n" + source
    return source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite managed_components")
    result = patch(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != result:
        args.output.write_text(result)


if __name__ == "__main__":
    main()
