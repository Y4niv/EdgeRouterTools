# EdgeRouter DNSSEC Root Trust-Anchor Updater

A single bash script for Ubiquiti **EdgeRouter** (EdgeOS 3.x) that keeps the **DNSSEC root trust anchors** of the router's DNS forwarder (dnsmasq, `service dns forwarding`) up to date.

## Why

When DNSSEC validation is enabled, dnsmasq validates answers against root trust anchors that are stored in the router configuration. dnsmasq does not implement RFC 5011 automatic anchor updates, so when the root zone introduces a new key (a KSK rollover) and the matching anchor is missing, **DNS answers start failing and the internet appears to be down**. This script adds new anchors automatically, ahead of time.

## What it does

1. **Locks and tidies.** Prevents two copies from running at once, trims its own log, and removes temp folders left behind by killed runs.
2. **Preflight.** Checks the required tools (`curl`, `openssl`, `vbash`, `python`) and that the router clock is sane (certificate and date checks depend on it).
3. **Loads the ICANN Root CA.** Uses `icann-root-ca.pem` from the script folder if present, otherwise the certificate embedded in the script. It logs warnings when the certificate is within 180 days of expiry or already expired.
4. **Downloads** IANA's `root-anchors.xml` and its detached signature `root-anchors.p7s`, with fallbacks:
   - `https` through the router's own DNS;
   - if that fails (typical when the missing anchor is breaking DNS), the IP of `data.iana.org` is looked up directly from fallback DNS servers (1.1.1.1, 9.9.9.9, 8.8.8.8) using a tiny built-in DNS client, and the script connects to that IP (the hostname is kept for TLS);
   - then the same two steps over plain `http` (optional, safe because of the signature check).
5. **Verifies the signature** (`openssl smime`, with an `openssl cms` fallback) against the ICANN Root CA **before reading any data**. Because of this, the download path does not need to be trusted. On failure it logs a specific diagnosis: certificate problem, wrong clock, or data/signature mismatch.
6. **Parses the signed XML** and selects anchors whose `validFrom` date is today or within the next `LOOKAHEAD_DAYS` (default 30) days and that are not expired. Malformed records are skipped, and digest lengths are validated.
7. **Compares with the router.** Reads the *running* configuration through `vbash` and the *saved* `/config/config.boot`, and works out which anchors are missing from the running config, or running but not saved.
8. **Reports expired anchors** that are still configured (log notice only; nothing is ever deleted).
9. **Applies (only with `--apply`).** Adds missing anchors in one `vbash` session: `set ... ; commit && save`. A watchdog stops a hung `vbash`. It then re-reads both the running and saved configuration to confirm every anchor is present, checks that `config.boot` still belongs to group `vyattacfg`, and runs an informational DNS test (`ad=1` means DNSSEC-validated).
10. **Cleans up.** Temp files and the lock are removed on every exit path, including normal exit, errors and signals (HUP/INT/TERM).

### Safety properties

- **Only adds** anchors. It never removes or changes existing configuration.
- Any download, verification, parsing or config-read problem means **no change** is made.
- Adding an anchor early is harmless: an anchor for a key that is not in use yet is ignored by dnsmasq.
- Warnings and errors are written to the log file **and** to syslog (`grep root-anchors /var/log/messages`), and can optionally trigger your own command (`NOTIFY_CMD`).

## Requirements

- EdgeRouter with EdgeOS 3.x (developed for an EdgeRouter 12 on EdgeOS 3.0.1)
- Tools already present on EdgeOS: `bash`, `curl`, `openssl`, `vbash`, Python 2.7 or 3. No `dig`, `nslookup` or `timeout` needed.
- DNSSEC enabled in the DNS forwarding options (the script only manages the `trust-anchor=` entries).
- Correct router time (NTP).

## Installation (step by step)

All commands are run on the router over SSH. Replace `<user>` and `<router-ip>`.

**1. Create the script folder** (it lives under `/config`, which survives reboots and firmware upgrades):

```bash
sudo mkdir -p /config/scripts/trust-anchors-updater
```

**2. Copy the script to the router.** From your PC:

```bash
scp update-root-trust-anchors.sh <user>@<router-ip>:/tmp/
```

Then on the router:

```bash
sudo mv /tmp/update-root-trust-anchors.sh /config/scripts/trust-anchors-updater/
```

**3. Set line endings, ownership and permissions:**

```bash
cd /config/scripts/trust-anchors-updater
sudo sed -i 's/\r$//' update-root-trust-anchors.sh     # removes Windows line endings, if any
sudo chown root:root update-root-trust-anchors.sh
sudo chmod 755 update-root-trust-anchors.sh
bash -n update-root-trust-anchors.sh && echo "syntax ok"
```

**4. Test without changing anything:**

```bash
sudo /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --check
```

Read the table of anchors it prints. If anchors you already have configured are reported as "missing", the config matching needs a look. Open an issue with the log output.

Optional extra tests (none of them change the config):

```bash
# Test the fallback download path (bypasses the router's own DNS)
sudo FORCE_FALLBACK=1 /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --check

# See how far-future anchors would be treated
sudo LOOKAHEAD_DAYS=3650 /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --check

# Run with the bare environment the scheduler uses
sudo env -i /bin/sh -c '/config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --check'
```

**5. (Recommended) Test the write path once.** `--test-apply` adds one harmless fake anchor (key tag 65000), commits, saves and verifies. dnsmasq restarts briefly:

```bash
sudo /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --test-apply
ls -l /config/config.boot      # group should be vyattacfg (shown as "vyattacf")
```

Remove the fake anchor with the `delete` command printed at the end of the log, in this form:

```
configure
delete service dns forwarding options trust-anchor=.,65000,8,2,0000000000000000000000000000000000000000000000000000000000000000
commit
save
exit
```

**6. Schedule it weekly** with the EdgeOS task scheduler (this example runs every Sunday at 04:30):

```
configure
set system task-scheduler task root-anchors crontab-spec '30 4 * * 0'
set system task-scheduler task root-anchors executable path /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh
set system task-scheduler task root-anchors executable arguments --apply
commit
save
exit
```

> Without `--apply` the script only reports and never changes anything.

**7. Check the results** after the first scheduled run:

```bash
cat /var/log/update-root-trust-anchors.log
grep root-anchors /var/log/messages
```

After a firmware upgrade, confirm the schedule still exists: `show configuration commands | grep task-scheduler`.

## Command-line options

| Option | Effect |
|---|---|
| `--check` (default) | Download, verify, compare and report. No changes. |
| `--apply` | Add missing anchors (`commit` + `save`) and verify. |
| `--test-apply` | Like `--apply`, plus one harmless fake anchor to test the write path. |

Exit codes: `0` success or nothing to do, `1` error (nothing changed), `2` usage error.

## Settings

All settings are in a commented block at the top of the script. Each can be changed there, or overridden for one run, for example `LOOKAHEAD_DAYS=60 ./update-root-trust-anchors.sh --check`.

| Setting | Default | Meaning |
|---|---|---|
| `LOOKAHEAD_DAYS` | `30` | Add anchors this many days before their `validFrom` date. Keep it at least 3x your schedule interval. |
| `LOG` | `/var/log/update-root-trust-anchors.log` | Log file (trimmed automatically). |
| `LOG_MAX_LINES` / `LOG_KEEP_LINES` | `2000` / `1000` | Trim the log to the last 1000 lines when it exceeds 2000. |
| `FALLBACK_DNS_SERVERS` | `1.1.1.1 9.9.9.9 8.8.8.8` | DNS servers used to find `data.iana.org` when the router's DNS is broken. |
| `ALLOW_HTTP_FALLBACK` | `1` | Also try plain `http` if `https` fails (safe: signature-verified). |
| `CURL_MAX_TIME` | `40` | Seconds per download attempt. |
| `CA_OVERRIDE_FILE` | `/config/scripts/trust-anchors-updater/icann-root-ca.pem` | Replacement ICANN CA certificate, used instead of the embedded one if present. |
| `CA_WARN_DAYS` | `180` | Warn this many days before the CA certificate expires. |
| `USE_SG` | `0` | `1` = run `vbash` via `sg vyattacfg`. Use only if `config.boot` ends up with the wrong group. |
| `VBASH_TIMEOUT` | `120` | Seconds before a hung `vbash` call is aborted. |
| `SAVED_CFG` | `/config/config.boot` | Saved configuration file. |
| `ENABLE_DNS_TEST` | `1` | Run a DNS test after applying changes. |
| `DNS_TEST_SERVER` / `DNS_TEST_NAME` | `127.0.0.1` / `iana.org` | What the DNS test queries. Use the router's LAN IP if dnsmasq does not listen on 127.0.0.1. |
| `REPORT_STALE` | `1` | Log a notice for configured anchors that IANA marks as expired. |
| `NOTIFY_CMD` | empty | Command called with the message on every warning or error. |
| `MIN_CLOCK_YEAR` | `2025` | Refuse to run if the router clock shows an earlier year. |

## When the ICANN certificate is replaced

The embedded ICANN Root CA certificate is valid until **2029-12-18**. If ICANN replaces it or it expires, signature verification fails, nothing is changed, and the log and syslog show a clear message:

```
ERROR: CERTIFICATE PROBLEM: the ICANN root CA ... no longer validates IANA's signature ...
```

To fix it, you do **not** need to edit the script. Save the current ICANN root CA certificate (PEM) from IANA's trust-anchor publication page as:

```
/config/scripts/trust-anchors-updater/icann-root-ca.pem
```

The script uses that file automatically instead of the embedded certificate. From 180 days before expiry the script also logs a warning on every run.

## Troubleshooting (log messages)

| Message | Meaning / action |
|---|---|
| `CERTIFICATE PROBLEM` | The ICANN CA certificate is expired or replaced. See the section above. |
| `certificate is 'not yet valid'` / `System clock looks wrong` | Router clock is wrong. Check NTP. |
| `does not match its signature` | Corrupted download or tampering. The next run retries. No change was made. |
| `Could not download root-anchors.xml` | No route to IANA, even via the fallback DNS servers. No change was made. |
| `NOT saved (would be lost at reboot)` | An anchor was in the running config but not saved. `--apply` saves it. |
| `does not belong to group vyattacfg` | Set `USE_SG=1` or run `chgrp vyattacfg /config/config.boot`. |
| `NOTICE: expired anchor still configured` | Harmless. The log shows the `delete` command if you want to tidy up. |
| `DNS test ... rcode=2` | SERVFAIL from dnsmasq. DNSSEC validation may still be failing. Check the anchors. |

## Uninstall

```
configure
delete system task-scheduler task root-anchors
commit
save
exit
```

```bash
sudo rm -r /config/scripts/trust-anchors-updater
```

The trust anchors already added to your configuration are left in place. They are harmless.

## License / disclaimer

Provided as is, without warranty. It modifies your router's DNS configuration when run with `--apply`. Review the script and run `--check` before scheduling it.
