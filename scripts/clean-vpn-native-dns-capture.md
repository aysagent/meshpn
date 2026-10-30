# Disposable DNS capture

`clean-vpn-native-dns-capture.py` is a diagnostic companion to the packet WAN
lab, not a host capture service. It needs Python 3 and Linux CAP_NET_RAW.
It does not configure interfaces, routes, firewall or promiscuous mode.

Inside the existing disposable lab namespace, with an existing empty/private
0700 output directory:

```sh
python3 scripts/clean-vpn-native-dns-capture.py \
  --parent-netns='net:[ORIGINAL_HOST_NAMESPACE_INODE]' \
  --directory=/run/TRIAL/dns-capture --seconds=60
```

The parent namespace identity must come from the original host before `nsenter`.
The helper refuses that namespace, PID 1's namespace, and any namespace whose
interface set is not exactly `lo` and `cvpw0`. Keep it in the bounded trial's
transient systemd cgroup; never attach it to the daily VPN namespace.

Output is `lo.pcap` and `cvpw0.pcap`, each created exclusively with mode 0600.
AF_PACKET/SOCK_DGRAM removes link headers; both files use DLT_RAW (101).
ETH_P_ALL permits both directions, but only complete unfragmented IPv4 TCP/UDP
packets with source or destination port 1055 are written. Loopback may contain
duplicates for outgoing/incoming observations. TCP handshakes/FINs are retained;
fragmented IP traffic and non-DNS traffic are excluded. This is not a general
DNS packet sniffer or a proof of absence of other DNS traffic.

Defaults: 60 seconds, 20,000 matching packets, 16 MiB aggregate output. Maximums:
300 seconds, 100,000 packets, 64 MiB. SIGTERM/SIGINT stop capture and close files.
Summary events contain counts, stop reason and kernel packet drops, no queries.
The private pcap does contain fixture DNS names/answers; do not publish it blindly.

Validation: `python3 scripts/test-native-dns-capture.py` tests malformed lengths,
fragments, both protocols/directions and namespace refusal. The opt-in
`test-native-dns-capture-linux.py` creates a nested disposable namespace and a TUN,
checks real loopback TCP/UDP and TUN UDP capture, port exclusion and file modes.
Run that test only inside a fresh privileged, network-none Linux lab container.
