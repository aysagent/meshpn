#!/usr/bin/env python3
"""Return a Wi-Fi TX memory error instead of asserting in ESP-Hosted 1.4.7."""

import argparse
from pathlib import Path


def patch(source: str) -> str:
    for interface in ("STA", "AP"):
        old = (f"copy_buff = mempool_alloc(((struct mempool*)chan_arr[ESP_{interface}_IF]->memp), "
               "MAX_TRANSPORT_BUFFER_SIZE, true);\n\tassert(copy_buff);")
        new = old.replace("\tassert(copy_buff);", "\tif (!copy_buff) return ESP_ERR_ESP_NETIF_NO_MEM;")
        if source.count(old) != 1:
            raise ValueError(f"ESP-Hosted {interface} TX source changed; re-audit the memory patch")
        source = source.replace(old, new, 1)
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
