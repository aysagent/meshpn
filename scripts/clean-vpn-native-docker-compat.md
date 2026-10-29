# Docker Compose compatibility gate

The managed VPN/admin stack also passed the real Docker daemon gate on
2026-10-30: **11/11**, with the optional private peer DNS sidecar.
[Machine-readable evidence](../fixtures/clean-vpn-native-docker-compose-20261030.json).

The final musl image with authenticated address discovery then passed **12/12**:
[discovery follow-up](../fixtures/clean-vpn-native-docker-address-20261030.json).
The client source omits `peer_ipv4`, receives `.3` from exit and reports the
verified effective address through the broker; restart and SIGKILL preserve the
same assignment. Source configuration remains unchanged. This also reruns the
private DNS, TUN and admin lifecycle checks with the newer native implementation.

Docker Engine 28.5.2 and Compose 2.40.3 ran inside a disposable, NIC-less Linux
systemd container in the existing Podman VM. Docker had its own Unix socket,
vfs image store and delegated systemd cgroups. The tested images were imported
from the existing cache; no VM-wide Docker service, networking or binfmt change
was made. The Mac and daily Radxa/VPS services were untouched.

The gate exercised both supervised engines, real TUN packets, private UDP/TCP
DNS and NSS, a public DNS positive control, pending-transaction SERVFAIL,
add/revoke without changing exit PID, resolver outage/recovery, both web APIs,
authentication, certificate diagnostics, verified TLS browser capture, stopped
engine guard, direct port-53 refusal, restart and SIGKILL recovery. The test
removed all of its containers, volumes and user-created networks.

## Reproduction on an existing disposable Docker host

Build the runtime/admin images using the managed-container instructions first.
This harness creates only temporary test resources, but requires rootful Docker
and a Linux kernel with TUN/netfilter. It is intended for a lab, not a daily host.

```sh
CVPN_CONTAINER_COMMAND='["docker"]' \
CVPN_COMPOSE_COMMAND='["docker","compose"]' \
CVPN_MANAGED_PRIVATE_DNS=1 \
CVPN_MANAGED_ADDRESS_DISCOVERY=1 \
CVPN_MANAGED_IMAGE=YOUR_MANAGED_IMAGE \
CVPN_ADMIN_IMAGE=YOUR_ADMIN_IMAGE \
node scripts/test-native-managed-compose.mjs /NEW/private/docker-report.json
```

Run from the repository root. The report path must not exist; the test needs
Node and OpenSSL locally. The source repository supplies the Compose files and
fixtures; images must contain the matching control plane/native implementation.
Only the generated role-specific volumes are passed to VPN/admin containers.

The first plain nested dockerd attempt could execute unlimited containers but
could not apply domain memory controls in its threaded cgroup subtree. We did
not weaken the production Compose memory limits: the replacement lab used its
own systemd delegation. This distinction follows the kernel's
[cgroup v2 domain/threaded rules](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

This is ARM64 Linux daemon compatibility, not Docker Desktop, amd64, rootless,
cold reboot or physical deployment acceptance. The first report uses fixed
addresses; the second records the explicit discovery overlay. After both runs,
the nested daemon and its entire disposable outer container were removed.
