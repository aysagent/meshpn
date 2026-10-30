# Owned-tunnel TCP recovery experiment

This is an opt-in diagnostic, **not an accepted performance fix**. Normal builds
use the unmodified ESP-IDF TCP sources. The 30 October hardware comparison did
not establish a sustained upload improvement; larger TX buffering also made
queue loss worse. See `../../reports/2026-10-30-vpn-night.md`.

`MESHPN_EXPERIMENT_SACK=1` generates a build-local copy of the pinned IDF
`tcp_in.c`, accepting new SACK high-water evidence even when a duplicate ACK
changes the window or carries data. `MESHPN_EXPERIMENT_PARTIAL=1` additionally
experiments with partial-ACK fast recovery. Both are restricted to the exact
current owned boring-tls connection, never arbitrary forwarded TCP flows.
The SDK checkout and PCB ABI are unchanged. Clear all three experiment environment variables
and reconfigure before a normal build.

`MESHPN_EXPERIMENT_BURST=1` (requires SACK and PARTIAL) adds a bounded,
experimental missing-segment repair pass at `tcp_output`. It tracks at most four
validated SACK ranges and 128 repair entries, sends at most two eligible whole
segments per pass, and conservatively accounts for both originals and repairs
against congestion credit. It does not free unacknowledged data. Busy pbufs,
failed output, receive-window limits, wraparound and the RTO fallback are covered
by the actual-core ASan/UBSan harness. The measured gaps became shorter, but
sustained upload did **not** improve; this remains disabled in normal firmware.

The experiment is deliberately not described as a complete SACK scoreboard,
RACK, or full RFC 6582 implementation. Evidence parsing rejects malformed,
unsent and DSACK-only ranges. The deterministic host harness exercises the
actual pinned IDF TCP sources with and without the patches, including loss,
reordering, wraparound, timer handling and failed retransmission preparation:

```
IDF_PATH="$HOME/esp/esp-idf-meshpn-v5.5.5" python3 experiments/tcp-sack/host/run.py
```

The harness derives from [lwIP PR 110](https://github.com/lwip-tcpip/lwip/pull/110)
commit `580d4e7f34ba3685e59da99e834ba976274ce150`; its BSD attribution/license are
retained in `host/`. New SACK information as duplicate-ACK evidence is discussed
in [RFC 5681 section 2](https://www.rfc-editor.org/rfc/rfc5681.html#section-2).
