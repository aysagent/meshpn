#!/usr/bin/env python3
"""Fix interface selection and failed-response reads in ESP-Hosted 1.4.7."""
import argparse
from pathlib import Path


def patch(source: str) -> str:
    changes = [
        ("\tresp = wifi_get_protocol(req);",
         "\treq->u.wifi_protocol.ifx = ifx;\n\tresp = wifi_get_protocol(req);"),
        ("\tg_h.funcs->_h_memcpy(conf, &resp->u.wifi_config.u, sizeof(wifi_config_t));",
         "\tif (resp && resp->resp_event_status == SUCCESS) {\n"
         "\t\tg_h.funcs->_h_memcpy(conf, &resp->u.wifi_config.u, sizeof(wifi_config_t));\n\t}"),
        ("\t}\n\tsta->num = resp->u.wifi_ap_sta_list.num;",
         "\t\tsta->num = resp->u.wifi_ap_sta_list.num;\n\t}"),
    ]
    for old, new in changes:
        if source.count(old) != 1:
            raise ValueError("ESP-Hosted RPC getters changed; re-audit the response/interface patches")
        source = source.replace(old, new, 1)
    return source


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
