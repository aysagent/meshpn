# Thirty-minute Alpine combo soak

The ARM64 musl build completed 30 minutes of concurrent packet and HTTPS relay
traffic from four clients with separate keys and LANs. **14013 successful mixed
rounds**, 3501–3506 per client. There were 319 resource samples and no native
engine restart. [Exact snapshot and evidence](../fixtures/clean-vpn-native-alpine-soak-20261030.json).

The exit global relay limit was 128, with 64 per authenticated client. Holding
all 64 slots for one identity prevented that identity from opening another
relay, while each of the other clients completed eight packet and eight relay
probes without rejection. This establishes the tested single-client quota
isolation; it is not a weighted fair scheduler or a guarantee against multiple
cooperating identities filling the global limit.

Native RSS medians decreased by 232–264 KiB between the first and final thirds
of the run. Observed native RSS peaks were about 5.7–6.1 MiB. After releasing
held sessions, file descriptors and thread counts returned to their baseline;
there were no zombies. All native PID1 processes exited cleanly on SIGTERM.
Owned test containers, volumes and networks were removed.

This run used native snapshot `a9cb8bd`, SHA256
`88228c10f55c9991b98f03d4cddacc60b0602560be97528322fa696dd40561a7`.
It includes private-DNS-capable code, but `private_peer_dns` was not enabled
in this workload. It precedes the separate address-discovery implementation.
Newer modes have their own acceptance gates; this result must not be presented
as a 30-minute test of those modes. Native RSS is not whole-container memory.

Reproduction on the existing isolated rootful Linux lab, from repository root:

```sh
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=YOUR_ARM64_ALPINE_RUNTIME \
CVPN_MULTI_CLIENTS=4 CVPN_MULTI_SECONDS=1800 \
node scripts/clean-vpn-native-multi-client-lab.mjs /NEW/private/soak.json
```

The image must contain matching native/runtime code. The script creates fresh
internal bridges and role-specific credentials; do not run concurrently with
another copy using the same test subnets. It tests local stability and bounded
resource recovery, not Internet throughput, long WAN behavior or physical
Radxa/VPS deployment. The separate 15-minute fixture also exercises a fully
occupied global relay limit with slow readers.
