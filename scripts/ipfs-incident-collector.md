# IPFS incident collector

This is a read-only live-triage collector for an unexpected `ipfs-storage`
and `ipfs-storage-agent` installation. It is meant to answer, as far as the
remaining host evidence permits:

- which Unix users exist and which user each service runs as;
- when the unit, agent and IPFS binary appeared or changed;
- how the agent starts IPFS and which persistence mechanism enables it;
- which SSH accounts and source IP addresses authenticated during the chosen
  time window;
- which related commands remain in shell history or system journals;
- which objects and bytes exist in the IPFS repository, including unpinned
  blocks that a normal `ipfs pin ls` does not show;
- whether other recently-created services, cron jobs, users or authorized SSH
  keys deserve investigation.

Run it as soon as possible, ideally after taking a provider disk snapshot:

```bash
git pull
sudo bash scripts/ipfs-incident-collector.sh --days=60
```

The default performs a SHA-256 pass over every regular file in
`/var/lib/ipfs-storage`. On this host that means reading roughly 2.2 GB. To get
a faster metadata-only collection, add `--no-deep`. The collector can make
read-only POST requests to the Kubo API bound to `127.0.0.1:5001`; add
`--no-local-api` if even this small interaction with the running daemon is not
desired. It never contacts an external address.

The final terminal block names three results:

- `REPORT_ARCHIVE`: review copy containing metadata, logs, IP addresses and
  redacted extracts;
- `PRIVATE_ARCHIVE`: exact service scripts, unit files, shell histories and
  selected original logs;
- `ARCHIVE_HASHES`: SHA-256 checksums for both archives.

Send `SUMMARY.txt`, `ssh-ip-summary.txt`, and preferably `REPORT_ARCHIVE` for
analysis. Do not send `PRIVATE_ARCHIVE`: commands or service scripts may hold
tokens and the original logs/histories contain sensitive information. Keep the
private archive and its hash unchanged for later investigation.

## What it does not prove

This is not a forensic disk image, a memory capture or a chain-of-custody
system. A live collection changes access times on some files, generates local
audit/journal activity and observes a system that continues changing. File
birth/change timestamps, authentication logs and histories can establish a
timeline only when those records still exist and have not been altered.

The host cannot recover provider-side console access, firewall flow logs or
account audit events. Export those separately from the VPS provider for the
same UTC window. If unauthorized access is confirmed, rebuild the machine from
a known-good image and rotate credentials from another trusted device; do not
treat removal of the two systemd services as remediation.
