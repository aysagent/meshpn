#!/usr/bin/env python3
"""Fix interface selection in the pinned ESP-Hosted 1.4.7 protocol getter."""
import argparse
from pathlib import Path


def patch(source: str) -> str:
    old = "\tresp = wifi_get_protocol(req);"
    if source.count(old) != 1:
        raise ValueError("ESP-Hosted protocol getter changed; re-audit the interface patch")
    return source.replace(old, "\treq->u.wifi_protocol.ifx = ifx;\n" + old, 1)


if __name__ == "__main__":
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
