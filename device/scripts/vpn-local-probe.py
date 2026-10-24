"""Unprivileged, interface-bound UDP/DF probe for the synthetic device lab."""
import argparse
import json
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", default="198.18.0.1")
    parser.add_argument("--port", type=int, default=7)
    parser.add_argument("--size", type=int, default=1373)
    parser.add_argument("--df", action="store_true")
    parser.add_argument("--timeout", type=float, default=2)
    args = parser.parse_args()
    if not 0 <= args.size <= 4096 or not 1 <= args.port <= 65535 or not 0 < args.timeout <= 10:
        parser.error("size 0..4096, port 1..65535, timeout (0,10]")
    for address in [args.source, args.target]:
        socket.inet_pton(socket.AF_INET, address)
    result = {"payload_bytes": args.size, "ip_bytes": args.size + 28, "df": args.df}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((args.source, 0))
        if sys.platform == "darwin":
            sock.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(args.interface))  # IP_BOUND_IF
            if args.df:
                sock.setsockopt(socket.IPPROTO_IP, 28, 1)  # IP_DONTFRAG
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode() + b"\0")
            if args.df:
                sock.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER / IP_PMTUDISC_DO
        sock.settimeout(args.timeout)
        try:
            sock.connect((args.target, args.port))
            payload = b"Z" * args.size
            sock.send(payload)
            received = sock.recv(8192)
            result.update(reply=True, matches=received == payload, received_bytes=len(received))
        except OSError as error:
            result.update(reply=False, error=error.errno, reason=type(error).__name__)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
