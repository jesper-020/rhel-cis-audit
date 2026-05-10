# rhel-cis-audit

Read-only bash script for triaging RHEL 6/7/8 servers against CIS Benchmark
Level 1 controls. Single file, no dependencies beyond standard coreutils.

**This is not a substitute for CIS-CAT Pro or OpenSCAP** use those for
compliance reporting. This script is for the *"I just SSH'd into a server,
how bad is it?"* moment: disaster recovery, ad-hoc audits, post-restore
sanity checks, or assessing an unfamiliar host before deciding what to fix.

## What it does

- ~150 checks across CIS sections 1–6: filesystem hardening, services,
  network sysctls, SSH, password policy, audit, logging, file permissions,
  user accounts.
- RHEL major version detection (auto or manual), with version-specific
  checks for RHEL 6 (iptables, pam_cracklib, tcp_wrappers), RHEL 7
  (firewalld), and RHEL 8 (crypto-policies, faillock.conf, journald,
  authselect).
- Coloured terminal output with PASS / FAIL / WARN / SKIP status per check.
- Optional CSV report (RFC 4180) for tracking, diffing, or feeding into
  other tools.
- NFS-safe: hangs on stale mounts are bounded with per-operation timeouts,
  so the script always finishes.

## What it deliberately doesn't do

- It does **not** modify anything. No `--fix` flag, no remediation, no
  config changes. Read-only by design.
- It does **not** claim conformance to a specific CIS Benchmark revision.
  The control IDs (e.g. `1.1.cramfs`, `5.2.PermitRootLogin`) are
  human-readable identifiers, not 1:1 mappings to a numbered benchmark
  rule. For an auditable report mapped to a specific revision, use
  CIS-CAT Pro or OpenSCAP with `scap-security-guide`.
- It does **not** cover every CIS rule. Roughly 150 of the most useful
  controls; not the full 200+. Some Level 2 controls and most
  organisation-specific items (banners content, GDM config, named user
  policies) are intentionally excluded or downgraded to WARN.

## Requirements

- bash 4+ (RHEL 6 ships bash 4.1, RHEL 7+ bash 4.2+).
- Standard utilities: `awk`, `grep`, `sed`, `stat`, `find`, `rpm`,
  `sysctl`, `systemctl` (or `chkconfig` on RHEL 6), `modprobe`, `lsmod`.
- `timeout(1)` from coreutils, used for NFS-safe stat/find. If absent,
  the script falls back to unbounded calls (only an issue on hosts with
  hung remote mounts).
- Root for full coverage. Without root, ~10 checks SKIP cleanly with a
  preflight notice explaining which.

## Usage

```bash
chmod +x cis_audit.sh

# Interactive (prompts for RHEL version)
sudo ./cis_audit.sh

# Specify version explicitly
sudo ./cis_audit.sh -v 8

# Auto-detect from /etc/redhat-release
sudo ./cis_audit.sh -a

# Write CSV report
sudo ./cis_audit.sh -v 8 -o report.csv

# Help
./cis_audit.sh -h
```

### Tunable timeouts (environment variables)

| Variable        | Default | Purpose                                           |
|-----------------|---------|---------------------------------------------------|
| `SAFE_TIMEOUT`  | `10`    | Timeout (seconds) for individual `stat`/`test`    |
| `FIND_TIMEOUT`  | `120`   | Timeout (seconds) per filesystem for `find` calls |

Set lower for fast-fail on troubled hosts:

```bash
SAFE_TIMEOUT=3 FIND_TIMEOUT=30 sudo ./cis_audit.sh -v 8 -o report.csv
```

## Exit codes

- `0` — all checks PASSed (no FAILs)
- `1` — at least one FAIL
- `2` — usage error (bad arguments, unsupported version)

WARN and SKIP do not affect the exit code.

## Output format

Terminal output groups checks by section with coloured status indicators:

```
=== 1.1 Filesystem kernel modules ===
  [PASS] 1.1.cramfs                Disable unused filesystem: cramfs
  [FAIL] 1.1.udf                   Disable unused filesystem: udf
         -> Module is currently loaded
  [WARN] 1.1.hfs                   Disable unused filesystem: hfs
         -> Not loaded but no install/blacklist rule found
```

CSV output is RFC 4180-compliant (commas as separators, fields with commas
or quotes are properly escaped):

```csv
id,status,description,detail
1.1.cramfs,PASS,Disable unused filesystem: cramfs,
1.3./dev/shm.nodev,FAIL,/dev/shm mounted with nodev,"Current options: rw,noexec,nosuid"
```

Loads cleanly into Excel, LibreOffice, `pandas.read_csv()`, etc.

## Status meanings

| Status | Meaning                                                            |
|--------|--------------------------------------------------------------------|
| PASS   | Control verified compliant.                                        |
| FAIL   | Control verified non-compliant.                                    |
| WARN   | Probably non-compliant, or partial config; needs human judgement.  |
| SKIP   | Could not evaluate (missing tool, missing file, requires root).    |

WARN is used when CIS recommends multiple acceptable approaches and only
one is detected (e.g. modprobe `install` directive vs `blacklist`),
or when a default value applies and we can't tell whether it's
intentional. WARNs deserve a look but aren't necessarily problems.

## Limitations and caveats

- **Sampling.** SUID/SGID RPM-verify checks the first 50 binaries found.
  Most servers have fewer than 50 anyway, but on hosts with custom
  software in `/opt` or `/usr/local` the sample may not be exhaustive.
- **`find` runtime.** On large filesystems, world-writable / unowned /
  SUID checks can take minutes. Tune `FIND_TIMEOUT` if needed.
- **No diff between scans.** Run twice and `diff` the CSV files yourself,
  or use a more capable tool.
- **Not a CIS-CAT replacement.** Worth saying again. If you need a
  signed compliance report, use the proper tooling.

## Comparison with alternatives

| | rhel-cis-audit | OpenSCAP + SSG | CIS-CAT Pro |
|---|---|---|---|
| Cost | free | free | paid (SecureSuite Membership) |
| Install needed | none | `dnf install openscap-scanner scap-security-guide` | Java + Pro download |
| RHEL 6 support | yes | no (SSG starts at RHEL 7) | limited |
| Authoritative | no | yes | yes (official CIS content) |
| Remediation scripts | no | yes (Ansible/bash via `oscap`) | yes (Build Kits) |
| Works on a host you can't install anything on | yes | only if already installed | no |
| Sufficient for an external audit | no | yes | yes |
| Time-to-first-result | seconds | 5–15 min setup | hours |

Recommended workflow: this script first (triage), then OpenSCAP or
CIS-CAT once the host is stable and a real report is needed.

## Coverage by section

- **1.x Initial Setup**: filesystem modules, separate partitions, mount
  options, sticky bit, AIDE, bootloader perms, core dumps, ASLR, GPG,
  sudo, crypto-policies (RHEL 8).
- **2.x Services**: time sync (chrony/ntp), X Window, unused services
  (avahi, cups, dhcpd, slapd, nfs, rpcbind, named, vsftpd, httpd, etc.),
  unused client packages.
- **3.x Network**: IPv4/IPv6 sysctl hardening, firewalld (RHEL 7/8),
  iptables (RHEL 6), nftables (RHEL 8), protocol modules.
- **4.x Logging and Auditing**: auditd, audit rules coverage (time-change,
  identity, system-locale, MAC-policy, logins, session, perm_mod, access,
  mounts, delete, modules), rsyslog, journald (RHEL 8).
- **5.x Access, Authentication, Authorization**: cron, SSH config + host
  keys, password policy (login.defs, pwquality, faillock, pam_wheel),
  default umask, securetty.
- **6.x System Maintenance**: file permissions for passwd/shadow/group,
  world-writable / unowned / ungrouped files, SUID/SGID RPM verification,
  user home directories, dotfile permissions, .netrc/.rhosts/.forward,
  duplicate UIDs/GIDs/usernames, root PATH integrity.
