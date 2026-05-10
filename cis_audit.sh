#!/bin/bash
# cis_audit.sh
# CIS Red Hat Enterprise Linux Benchmark audit — RHEL 6, 7 and 8
#
# Single-file, native bash/awk/grep/sed/stat/rpm/sysctl/systemctl/modprobe/find.
# No external dependencies, no package installs needed.
#
# Usage:
#   sudo ./cis_audit.sh                        # interactive (prompt for version)
#   sudo ./cis_audit.sh -v 7                   # specify version
#   sudo ./cis_audit.sh -a                     # auto-detect from /etc/redhat-release
#   sudo ./cis_audit.sh -v 8 -o report.csv     # write CSV report
#   sudo ./cis_audit.sh -h                     # help
#
# Exit code: 0 when no FAILs, 1 otherwise.
#
# NOTE: read-only audit. The script does not modify anything on the host.
# NOTE: find-based checks (world-writable, unowned, SUID/SGID) iterate over
#       ALL local mounts (not just /), so separate /home, /var etc. are covered.

set -u

# =============================================================================
#   GLOBALS / OUTPUT
# =============================================================================

PASS=0
FAIL=0
WARN=0
SKIP=0
RESULTS=()
RHEL_VERSION=""
OUTFILE=""
AUTO_DETECT=0

if [ -t 1 ]; then
    C_RED=$'\033[0;31m'
    C_GRN=$'\033[0;32m'
    C_YEL=$'\033[0;33m'
    C_BLU=$'\033[0;34m'
    C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi

report() {
    local id="$1" status="$2" desc="$3" detail="${4:-}"
    case "$status" in
        PASS) PASS=$((PASS+1)); printf "  %s[PASS]%s %-26s %s\n" "$C_GRN" "$C_RST" "$id" "$desc" ;;
        FAIL) FAIL=$((FAIL+1)); printf "  %s[FAIL]%s %-26s %s\n" "$C_RED" "$C_RST" "$id" "$desc"
              [ -n "$detail" ] && printf "         -> %s\n" "$detail" ;;
        WARN) WARN=$((WARN+1)); printf "  %s[WARN]%s %-26s %s\n" "$C_YEL" "$C_RST" "$id" "$desc"
              [ -n "$detail" ] && printf "         -> %s\n" "$detail" ;;
        SKIP) SKIP=$((SKIP+1)); printf "  %s[SKIP]%s %-26s %s\n" "$C_BLU" "$C_RST" "$id" "$desc"
              [ -n "$detail" ] && printf "         -> %s\n" "$detail" ;;
    esac
    # RFC 4180 CSV: quote fields containing comma, double-quote, CR or LF;
    # escape embedded double-quotes by doubling them.
    local csv_line="" field
    for field in "$id" "$status" "$desc" "$detail"; do
        if [[ "$field" == *[,\"]* || "$field" == *$'\n'* || "$field" == *$'\r'* ]]; then
            csv_line+=",\"${field//\"/\"\"}\""
        else
            csv_line+=",${field}"
        fi
    done
    RESULTS+=("${csv_line:1}")
}

section() { printf "\n%s=== %s ===%s\n" "$C_BLU" "$1" "$C_RST"; }

# =============================================================================
#   USAGE / ARG PARSING / VERSION PROMPT
# =============================================================================

usage() {
    cat <<EOF
Usage: $0 [options]
  -v <6|7|8>   Specify RHEL major version
  -a           Auto-detect from /etc/redhat-release
  -o <file>    Write CSV report to <file>
  -h           Show this help

Without -v or -a, the script will prompt interactively.
EOF
}

while getopts "v:ao:h" opt; do
    case "$opt" in
        v) RHEL_VERSION="$OPTARG" ;;
        a) AUTO_DETECT=1 ;;
        o) OUTFILE="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done

auto_detect_version() {
    if [ ! -f /etc/redhat-release ]; then
        echo "ERROR: /etc/redhat-release not found; cannot auto-detect." >&2
        return 1
    fi
    local major
    major=$(sed -nE 's/.*release ([0-9]+)\..*/\1/p' /etc/redhat-release)
    if [ -z "$major" ]; then
        echo "ERROR: could not parse /etc/redhat-release: $(cat /etc/redhat-release)" >&2
        return 1
    fi
    RHEL_VERSION="$major"
    echo "Auto-detected RHEL major version: $RHEL_VERSION"
}

prompt_version() {
    echo
    echo "Which RHEL version should be audited?"
    echo "  [1] Auto-detect from /etc/redhat-release"
    echo "  [6] RHEL 6"
    echo "  [7] RHEL 7"
    echo "  [8] RHEL 8"
    echo
    local choice
    while true; do
        read -r -p "Choice [1/6/7/8]: " choice
        case "$choice" in
            1) auto_detect_version && break ;;
            6|7|8) RHEL_VERSION="$choice"; break ;;
            "") ;;
            *) echo "Invalid choice." ;;
        esac
    done
}

if [ "$AUTO_DETECT" -eq 1 ]; then
    auto_detect_version || exit 1
fi

if [ -z "$RHEL_VERSION" ]; then
    if [ -t 0 ]; then
        prompt_version
    else
        echo "ERROR: no version specified and stdin is not a TTY. Use -v or -a." >&2
        exit 2
    fi
fi

case "$RHEL_VERSION" in
    6|7|8) ;;
    *) echo "ERROR: unsupported RHEL version '$RHEL_VERSION'. Supported: 6, 7, 8." >&2; exit 2 ;;
esac

# =============================================================================
#   HELPER FUNCTIONS
# =============================================================================

is_root() { [ "$(id -u)" -eq 0 ]; }

pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }

svc_enabled() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-enabled "$1" 2>/dev/null | grep -qE '^enabled$|^enabled-runtime$'
    else
        chkconfig --list "$1" 2>/dev/null | grep -qE '3:on|5:on'
    fi
}

svc_active() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active "$1" >/dev/null 2>&1
    else
        service "$1" status >/dev/null 2>&1
    fi
}

# A module is truly "disabled" per CIS when modprobe is redirected to /bin/true
# or /bin/false. modprobe -n -v shows exactly that — it reflects both
# install-directives AND the lack thereof, so this one check is authoritative.
module_disabled() {
    local mod="$1" out
    out=$(modprobe -n -v "$mod" 2>/dev/null)
    echo "$out" | grep -Eq 'install[[:space:]]+/(bin|usr/bin)/(true|false)'
}

module_blacklisted() {
    local mod="$1"
    grep -rEh "^[[:space:]]*blacklist[[:space:]]+${mod}([[:space:]]|$)" \
        /etc/modprobe.conf /etc/modprobe.d/ 2>/dev/null | grep -q .
}

module_loaded() { lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$1"; }

# Wrap a potentially hanging command (stat/find on NFS, /net, /home) with a
# hard timeout. On RHEL 6/7/8 coreutils provides timeout(1); if not present we
# fall back to the raw command.
SAFE_TIMEOUT="${SAFE_TIMEOUT:-10}"
FIND_TIMEOUT="${FIND_TIMEOUT:-120}"

safe_run() {
    # Usage: safe_run <seconds> <cmd> [args...]
    local t="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --preserve-status "$t" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

safe_stat() {
    # Usage: safe_stat <stat-format> <path>
    local fmt="$1" path="$2"
    safe_run "$SAFE_TIMEOUT" stat -L -c "$fmt" "$path"
}

sysctl_is() {
    local current
    current=$(sysctl -n "$1" 2>/dev/null)
    [ -n "$current" ] && [ "$current" = "$2" ]
}

# Return true if permission string $1 has no group/other bits set (i.e. ≤ 700).
# Uses 8# prefix so bash treats the digits as OCTAL, fixing the classic
# "stat returns 600 -> bash reads as decimal" bug.
perms_no_world_group() {
    local p="$1"
    [ -n "$p" ] || return 1
    # Guard against unexpected non-digit input.
    case "$p" in ''|*[!0-7]*) return 1 ;; esac
    [ "$((8#${p} & 8#077))" -eq 0 ]
}

# Return true if actual perms are at most (i.e. as strict as or stricter than)
# the given maximum.
perms_at_most() {
    local actual="$1" max="$2"
    [ -n "$actual" ] && [ -n "$max" ] || return 1
    case "$actual" in ''|*[!0-7]*) return 1 ;; esac
    case "$max"    in ''|*[!0-7]*) return 1 ;; esac
    [ "$((8#${actual} & ~8#${max} & 8#7777))" -eq 0 ]
}

# Parse "key = value" or "key=value" from a config file. Returns the first
# numeric or string value for the requested key.
conf_get() {
    local key="$1" file="$2"
    [ -f "$file" ] || return 1
    awk -v k="$key" '
        # strip inline comments
        { sub(/#.*/, "") }
        # normalise: split on whitespace and "="
        {
            # collapse "key =" or "key=" variants
            line=$0
            gsub(/^[[:space:]]+/, "", line)
            if (line ~ "^"k"([[:space:]]|=)") {
                # Remove the key, then any leading whitespace/=
                sub("^"k, "", line)
                gsub(/^[[:space:]]*=?[[:space:]]*/, "", line)
                gsub(/[[:space:]]+$/, "", line)
                # return first whitespace-separated token
                split(line, a, /[[:space:]]+/)
                if (a[1] != "") { print a[1]; exit }
            }
        }
    ' "$file"
}

# Iterate over all LOCAL mount points (excluding pseudo, virtual, and remote
# filesystems). Reads /proc/mounts directly instead of `df --local`, because
# df itself can hang indefinitely on a stale NFS mount — exactly the situation
# a DR server may be in. Pseudo-fs (proc/sys/etc.), tmpfs, and network FSes
# (nfs, cifs, ceph, gluster, sshfs, davfs) are all excluded.
local_mountpoints() {
    awk '
        $3 ~ /^(proc|sysfs|tmpfs|devtmpfs|devpts|cgroup|cgroup2|pstore|bpf|tracefs|debugfs|securityfs|hugetlbfs|mqueue|configfs|fusectl|autofs|binfmt_misc|rpc_pipefs|selinuxfs|efivarfs|ramfs)$/ { next }
        $3 ~ /^(nfs|nfs4|cifs|smb|smb2|smb3|ceph|glusterfs|fuse\.sshfs|davfs|afs|coda)$/ { next }
        { print $2 }
    ' /proc/mounts 2>/dev/null
}

find_all_local() {
    # Args: find-expression... (passed after "-xdev")
    # Runs find on every local mount point. Each mount is wrapped in a
    # per-mount timeout so one unresponsive FS cannot stall the whole scan.
    local mps mp
    mps=$(local_mountpoints)
    [ -n "$mps" ] || return 0
    for mp in $mps; do
        safe_run "$FIND_TIMEOUT" find "$mp" -xdev "$@"
    done
}

preflight() {
    if ! is_root; then
        printf "\n%s================================================================%s\n" \
            "$C_YEL" "$C_RST" >&2
        printf "%sWARNING: not running as root.%s\n" "$C_YEL" "$C_RST" >&2
        printf "The following checks will be SKIPped or WARNed for this reason:\n" >&2
        printf "  - SSH effective config (sshd -T) -> file-parse fallback used\n" >&2
        printf "  - auditd.conf and audit.rules (/etc/audit is 750 root:root)\n" >&2
        printf "  - Bootloader password on EFI systems (/boot/efi is restricted)\n" >&2
        printf "  - Root PATH integrity\n" >&2
        printf "  - SUID/SGID RPM-verify\n" >&2
        printf "Re-run with %ssudo%s for a complete assessment.\n" "$C_YEL" "$C_RST" >&2
        printf "%s================================================================%s\n\n" \
            "$C_YEL" "$C_RST" >&2
    fi
    if [ -f /etc/redhat-release ]; then
        local detected
        detected=$(sed -nE 's/.*release ([0-9]+)\..*/\1/p' /etc/redhat-release)
        if [ -n "$detected" ] && [ "$detected" != "$RHEL_VERSION" ]; then
            printf "%sWARNING:%s selected RHEL %s but /etc/redhat-release shows RHEL %s.\n" \
                "$C_YEL" "$C_RST" "$RHEL_VERSION" "$detected" >&2
        fi
    fi
}

# =============================================================================
#   SHARED CIS CHECKS
# =============================================================================

check_filesystem_modules() {
    section "1.1 Filesystem kernel modules"
    # Module lists per CIS major. vfat is only flagged on RHEL 6 (later versions
    # removed the recommendation because /boot/efi needs it).
    local mods
    case "$RHEL_VERSION" in
        6) mods="cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat" ;;
        7) mods="cramfs freevxfs jffs2 hfs hfsplus squashfs udf" ;;
        8) mods="cramfs freevxfs jffs2 hfs hfsplus squashfs udf" ;;
    esac
    for mod in $mods; do
        if module_loaded "$mod"; then
            report "1.1.${mod}" "FAIL" "Disable unused filesystem: $mod" "Module is currently loaded"
        elif module_disabled "$mod" || module_blacklisted "$mod"; then
            report "1.1.${mod}" "PASS" "Disable unused filesystem: $mod"
        else
            report "1.1.${mod}" "WARN" "Disable unused filesystem: $mod" \
                "Not loaded but no install/blacklist rule found"
        fi
    done
}

check_separate_partitions() {
    section "1.2 Filesystem partitioning"
    for mp in /tmp /var /var/tmp /var/log /var/log/audit /home /dev/shm; do
        if awk '{print $2}' /proc/mounts 2>/dev/null | grep -qx "$mp"; then
            report "1.2.${mp}" "PASS" "Separate mount for $mp"
        else
            # /dev/shm should always be a separate tmpfs; the others are
            # recommended but not always possible after-the-fact.
            if [ "$mp" = "/dev/shm" ]; then
                report "1.2.${mp}" "FAIL" "Separate mount for $mp" "Not a separate mount"
            else
                report "1.2.${mp}" "WARN" "Separate mount for $mp" "Not a separate mount"
            fi
        fi
    done
}

check_mount_options() {
    section "1.3 Mount options (nodev/nosuid/noexec)"
    # Map: mountpoint -> required options (comma separated)
    local mp opts required opt
    for mp in /tmp /var/tmp /home /dev/shm; do
        # Determine which opts CIS requires per mountpoint.
        case "$mp" in
            /tmp|/var/tmp|/dev/shm) required="nodev nosuid noexec" ;;
            /home)                  required="nodev" ;;
        esac
        if ! awk '{print $2}' /proc/mounts 2>/dev/null | grep -qx "$mp"; then
            for opt in $required; do
                report "1.3.${mp}.${opt}" "SKIP" "$mp mount option: $opt" "$mp is not a separate mount"
            done
            continue
        fi
        opts=$(awk -v m="$mp" '$2==m{print $4; exit}' /proc/mounts 2>/dev/null)
        for opt in $required; do
            if echo ",${opts}," | grep -q ",${opt},"; then
                report "1.3.${mp}.${opt}" "PASS" "$mp mounted with $opt"
            else
                report "1.3.${mp}.${opt}" "FAIL" "$mp mounted with $opt" "Current options: $opts"
            fi
        done
    done
}

check_sticky_bit_world_writable_dirs() {
    section "1.4 Sticky bit on world-writable directories"
    local offenders
    offenders=$(find_all_local -type d -perm -0002 \! -perm -1000 | head -n 5)
    if [ -z "$offenders" ]; then
        report "1.4.sticky" "PASS" "No world-writable dirs without sticky bit"
    else
        report "1.4.sticky" "FAIL" "Sticky bit on world-writable dirs" \
            "Examples: $(echo "$offenders" | tr '\n' ' ')"
    fi
}

check_aide() {
    section "1.5 Filesystem integrity (AIDE)"
    if pkg_installed aide; then
        report "1.5.1" "PASS" "AIDE installed"
        local scheduled=0
        if crontab -u root -l 2>/dev/null | grep -q aide; then scheduled=1; fi
        if grep -rq aide /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                /etc/cron.weekly /etc/cron.monthly /var/spool/cron/ 2>/dev/null; then
            scheduled=1
        fi
        if command -v systemctl >/dev/null 2>&1 && \
           systemctl list-timers --all 2>/dev/null | grep -qi aide; then
            scheduled=1
        fi
        if [ "$scheduled" -eq 1 ]; then
            report "1.5.2" "PASS" "AIDE is scheduled"
        else
            report "1.5.2" "FAIL" "AIDE is scheduled" "No cron/timer entry found for aide"
        fi
    else
        report "1.5.1" "FAIL" "AIDE installed" "Package 'aide' is not installed"
    fi
}

check_bootloader_perms() {
    section "1.6 Bootloader"
    local grub_cfg=""
    for candidate in /boot/grub2/grub.cfg \
                     /boot/efi/EFI/redhat/grub.cfg \
                     /boot/efi/EFI/centos/grub.cfg \
                     /boot/efi/EFI/rocky/grub.cfg \
                     /boot/efi/EFI/almalinux/grub.cfg \
                     /boot/grub/grub.conf; do
        [ -f "$candidate" ] && { grub_cfg="$candidate"; break; }
    done
    if [ -z "$grub_cfg" ]; then
        # EFI grub.cfg often lives under /boot/efi/EFI/*/ which is typically
        # 700 root:root (FAT mountpoint). If we're not root we can't even see
        # whether it's there — that's a SKIP, not a real "missing".
        if ! is_root && [ -d /boot/efi ]; then
            report "1.6.1" "SKIP" "Bootloader config permissions" \
                "Requires root to inspect /boot/efi (EFI system)"
        else
            report "1.6.1" "SKIP" "Bootloader config permissions" "No grub config found"
        fi
        return
    fi
    local perms owner
    perms=$(stat -c "%a" "$grub_cfg" 2>/dev/null)
    owner=$(stat -c "%U:%G" "$grub_cfg" 2>/dev/null)
    if [ "$owner" = "root:root" ] && perms_no_world_group "$perms"; then
        report "1.6.1" "PASS" "Bootloader config ($grub_cfg: $perms $owner)"
    else
        report "1.6.1" "FAIL" "Bootloader config perms" \
            "$grub_cfg is $perms $owner; expected 600 or stricter, root:root"
    fi
    # GRUB password — warn only; not all environments want it.
    local gpass_found=0
    if grep -Rqs '^\s*GRUB2_PASSWORD' /boot/grub2/user.cfg 2>/dev/null; then gpass_found=1; fi
    if grep -Rqs 'password_pbkdf2' /boot/grub2/ /etc/grub.d/ 2>/dev/null; then gpass_found=1; fi
    if grep -qs 'password' /boot/grub/grub.conf 2>/dev/null; then gpass_found=1; fi
    if [ "$gpass_found" -eq 1 ]; then
        report "1.6.2" "PASS" "Bootloader password set"
    else
        if ! is_root; then
            report "1.6.2" "SKIP" "Bootloader password set" "Requires root to read grub config files"
        else
            report "1.6.2" "WARN" "Bootloader password set" \
                "No GRUB2_PASSWORD / password_pbkdf2 / password line found"
        fi
    fi
}

check_core_dumps() {
    section "1.7 Core dumps"
    if grep -rqs '^[[:space:]]*\*[[:space:]]\+hard[[:space:]]\+core[[:space:]]\+0' \
            /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null; then
        report "1.7.1" "PASS" "Hard core dump limit = 0"
    else
        report "1.7.1" "FAIL" "Hard core dump limit = 0" \
            "No '* hard core 0' in /etc/security/limits.*"
    fi
    if sysctl_is fs.suid_dumpable 0; then
        report "1.7.2" "PASS" "fs.suid_dumpable = 0"
    else
        report "1.7.2" "FAIL" "fs.suid_dumpable = 0" \
            "Current: $(sysctl -n fs.suid_dumpable 2>/dev/null)"
    fi
}

check_aslr() {
    section "1.8 ASLR"
    if sysctl_is kernel.randomize_va_space 2; then
        report "1.8.1" "PASS" "kernel.randomize_va_space = 2"
    else
        report "1.8.1" "FAIL" "kernel.randomize_va_space = 2" \
            "Current: $(sysctl -n kernel.randomize_va_space 2>/dev/null)"
    fi
}

check_network_sysctl() {
    section "3.x Network sysctl hardening"
    local key want current
    # IPv4
    for kv in \
        "net.ipv4.ip_forward=0" \
        "net.ipv4.conf.all.send_redirects=0" \
        "net.ipv4.conf.default.send_redirects=0" \
        "net.ipv4.conf.all.accept_source_route=0" \
        "net.ipv4.conf.default.accept_source_route=0" \
        "net.ipv4.conf.all.accept_redirects=0" \
        "net.ipv4.conf.default.accept_redirects=0" \
        "net.ipv4.conf.all.secure_redirects=0" \
        "net.ipv4.conf.default.secure_redirects=0" \
        "net.ipv4.conf.all.log_martians=1" \
        "net.ipv4.conf.default.log_martians=1" \
        "net.ipv4.icmp_echo_ignore_broadcasts=1" \
        "net.ipv4.icmp_ignore_bogus_error_responses=1" \
        "net.ipv4.conf.all.rp_filter=1" \
        "net.ipv4.conf.default.rp_filter=1" \
        "net.ipv4.tcp_syncookies=1"; do
        key="${kv%=*}"; want="${kv#*=}"
        if sysctl_is "$key" "$want"; then
            report "3.${key}" "PASS" "$key = $want"
        else
            current=$(sysctl -n "$key" 2>/dev/null)
            report "3.${key}" "FAIL" "$key = $want" "Current: ${current:-unset}"
        fi
    done
    # IPv6: only enforce if ipv6 is NOT disabled
    if sysctl_is net.ipv6.conf.all.disable_ipv6 1; then
        report "3.ipv6.disabled" "PASS" "IPv6 disabled — redirect/ra checks skipped"
    else
        for kv in \
            "net.ipv6.conf.all.accept_ra=0" \
            "net.ipv6.conf.default.accept_ra=0" \
            "net.ipv6.conf.all.accept_redirects=0" \
            "net.ipv6.conf.default.accept_redirects=0"; do
            key="${kv%=*}"; want="${kv#*=}"
            if sysctl_is "$key" "$want"; then
                report "3.${key}" "PASS" "$key = $want"
            else
                current=$(sysctl -n "$key" 2>/dev/null)
                report "3.${key}" "FAIL" "$key = $want" "Current: ${current:-unset}"
            fi
        done
    fi
}

check_unused_services() {
    section "2.x Unused services"
    # Note: rsh.socket / telnet.socket only exist on RHEL 7/8 (systemd).
    # On RHEL 6 svc_enabled returns false for missing units → PASS.
    local svcs="avahi-daemon cups dhcpd slapd nfs nfs-server rpcbind named vsftpd httpd \
dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket \
telnet.socket tftp.socket rsyncd autofs xinetd"
    for svc in $svcs; do
        if svc_enabled "$svc" 2>/dev/null || svc_active "$svc" 2>/dev/null; then
            report "2.${svc}" "FAIL" "Disable service: $svc" "Service is enabled or active"
        else
            report "2.${svc}" "PASS" "Disable service: $svc"
        fi
    done
}

check_unused_clients() {
    section "2.3 Unused client packages"
    for pkg in ypbind rsh talk telnet openldap-clients; do
        if pkg_installed "$pkg"; then
            report "2.3.${pkg}" "FAIL" "Remove client: $pkg" "Package is installed"
        else
            report "2.3.${pkg}" "PASS" "Remove client: $pkg"
        fi
    done
}

check_time_sync() {
    section "2.2.1 Time synchronization"
    if pkg_installed chrony; then
        if svc_active chronyd; then
            report "2.2.1" "PASS" "chrony installed and running"
        else
            report "2.2.1" "FAIL" "chrony installed and running" "chronyd is not active"
        fi
        # Chrony must have a server or pool line
        if [ -f /etc/chrony.conf ] && \
           grep -Eq '^[[:space:]]*(server|pool)[[:space:]]+' /etc/chrony.conf; then
            report "2.2.1.conf" "PASS" "chrony has server/pool configured"
        else
            report "2.2.1.conf" "FAIL" "chrony server/pool in /etc/chrony.conf"
        fi
    elif pkg_installed ntp; then
        if svc_active ntpd; then
            report "2.2.1" "PASS" "ntp installed and running"
        else
            report "2.2.1" "FAIL" "ntp installed and running" "ntpd is not active"
        fi
    else
        report "2.2.1" "FAIL" "Time synchronization" "Neither chrony nor ntp is installed"
    fi
}

check_xwindows() {
    section "2.2.2 X Window System"
    if pkg_installed xorg-x11-server-common; then
        report "2.2.2" "FAIL" "X Window System not installed" "xorg-x11-server-common installed"
    else
        report "2.2.2" "PASS" "X Window System not installed"
    fi
}

check_ssh_config() {
    section "5.2 SSH server configuration"
    local sshd=/etc/ssh/sshd_config
    if [ ! -f "$sshd" ]; then
        report "5.2" "SKIP" "SSH config" "No $sshd file"
        return
    fi
    local perms owner
    perms=$(stat -c "%a" "$sshd" 2>/dev/null)
    owner=$(stat -c "%U:%G" "$sshd" 2>/dev/null)
    if [ "$owner" = "root:root" ] && perms_at_most "$perms" 600; then
        report "5.2.1" "PASS" "$sshd = $perms $owner"
    else
        report "5.2.1" "FAIL" "$sshd permissions" \
            "Current: $perms $owner; expected 600 or stricter, root:root"
    fi

    # SSH host keys
    local k owner_k perms_k
    for k in /etc/ssh/ssh_host_*_key; do
        [ -f "$k" ] || continue
        perms_k=$(stat -c "%a" "$k" 2>/dev/null)
        owner_k=$(stat -c "%U:%G" "$k" 2>/dev/null)
        # RHEL 8 default is root:ssh_keys 640, RHEL 6/7 historically root:root 600.
        if { [ "$owner_k" = "root:root" ] || [ "$owner_k" = "root:ssh_keys" ]; } && \
           perms_at_most "$perms_k" 640; then
            report "5.2.privkey.${k##*/}" "PASS" "$k = $perms_k $owner_k"
        else
            report "5.2.privkey.${k##*/}" "FAIL" "$k private key perms" \
                "Current: $perms_k $owner_k; expected 600/640, root:root or root:ssh_keys"
        fi
    done
    for k in /etc/ssh/ssh_host_*_key.pub; do
        [ -f "$k" ] || continue
        perms_k=$(stat -c "%a" "$k" 2>/dev/null)
        owner_k=$(stat -c "%U:%G" "$k" 2>/dev/null)
        if [ "$owner_k" = "root:root" ] && perms_at_most "$perms_k" 644; then
            report "5.2.pubkey.${k##*/}" "PASS" "$k = $perms_k $owner_k"
        else
            report "5.2.pubkey.${k##*/}" "FAIL" "$k public key perms" \
                "Current: $perms_k $owner_k; expected 644 or stricter, root:root"
        fi
    done

    # Use sshd -T for effective config if possible (requires root).
    local cfg_dump=""
    if command -v sshd >/dev/null 2>&1 && is_root; then
        cfg_dump=$(sshd -T 2>/dev/null || true)
    fi
    if [ -z "$cfg_dump" ] && command -v sshd >/dev/null 2>&1; then
        if is_root; then
            report "5.2.effective" "WARN" "sshd -T effective config" \
                "sshd -T returned empty (config parse error or missing hostkey). Falling back to file parsing."
        else
            report "5.2.effective" "SKIP" "sshd -T effective config" \
                "Requires root. Falling back to file parsing of sshd_config + sshd_config.d/*.conf."
        fi
    fi

    # Build the fallback search path: main sshd_config plus any drop-ins under
    # /etc/ssh/sshd_config.d/. On RHEL 8+ most defaults (Ciphers, MACs,
    # PermitRootLogin, etc.) come from 50-redhat.conf in the drop-in dir —
    # ignoring it gives a flood of false "Option not set" warnings.
    local sshd_files=("$sshd")
    local d
    for d in /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$d" ] && sshd_files+=("$d")
    done

    get_sshd_opt() {
        local key="$1"
        if [ -n "$cfg_dump" ]; then
            echo "$cfg_dump" | awk -v k="$key" 'BEGIN{IGNORECASE=1} tolower($1)==tolower(k){$1=""; sub(/^ /,""); print; exit}'
        else
            # sshd processes files in order; FIRST match wins per option.
            # Scan main config first, then drop-ins (drop-ins are included
            # from the top of sshd_config via "Include" on RHEL 8+).
            # To reflect that, concatenate the files and take the first match.
            local f
            for f in "${sshd_files[@]}"; do
                local hit
                hit=$(grep -Ei "^[[:space:]]*${key}[[:space:]]+" "$f" 2>/dev/null | head -n1)
                if [ -n "$hit" ]; then
                    echo "$hit" | awk '{$1=""; sub(/^ /,""); print}'
                    return 0
                fi
            done
        fi
    }

    # Expected: simple string match (case-insensitive)
    local -A ssh_expected=(
        [PermitRootLogin]=no
        [PermitEmptyPasswords]=no
        [HostbasedAuthentication]=no
        [IgnoreRhosts]=yes
        [X11Forwarding]=no
        [PermitUserEnvironment]=no
        [UsePAM]=yes
        [ClientAliveCountMax]=0
        [LogLevel]=INFO
        [AllowTcpForwarding]=no
    )
    local key val exp
    for key in "${!ssh_expected[@]}"; do
        exp="${ssh_expected[$key]}"
        val=$(get_sshd_opt "$key")
        val="${val%% *}"   # first token only
        if [ -z "$val" ]; then
            report "5.2.${key}" "WARN" "SSH $key = $exp" "Option not set (default may apply)"
            continue
        fi
        if [ "${val,,}" = "${exp,,}" ]; then
            report "5.2.${key}" "PASS" "SSH $key = $val"
        else
            report "5.2.${key}" "FAIL" "SSH $key = $exp" "Current: $val"
        fi
    done

    # Numeric comparisons: MaxAuthTries <= 4, LoginGraceTime in (0,60], ClientAliveInterval in (0,300]
    val=$(get_sshd_opt MaxAuthTries); val="${val%% *}"
    if [ -n "$val" ] && [ "$val" -le 4 ] 2>/dev/null; then
        report "5.2.MaxAuthTries" "PASS" "SSH MaxAuthTries = $val (<= 4)"
    else
        report "5.2.MaxAuthTries" "FAIL" "SSH MaxAuthTries <= 4" "Current: ${val:-unset}"
    fi
    val=$(get_sshd_opt LoginGraceTime); val="${val%% *}"
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null && [ "$val" -le 60 ] 2>/dev/null; then
        report "5.2.LoginGraceTime" "PASS" "SSH LoginGraceTime = $val"
    else
        report "5.2.LoginGraceTime" "FAIL" "SSH LoginGraceTime in (0,60]" "Current: ${val:-unset}"
    fi
    val=$(get_sshd_opt ClientAliveInterval); val="${val%% *}"
    if [ -n "$val" ] && [ "$val" -gt 0 ] 2>/dev/null && [ "$val" -le 300 ] 2>/dev/null; then
        report "5.2.ClientAliveInterval" "PASS" "SSH ClientAliveInterval = $val"
    else
        report "5.2.ClientAliveInterval" "FAIL" "SSH ClientAliveInterval in (0,300]" "Current: ${val:-unset}"
    fi

    # Protocol is only meaningful on RHEL 6/old OpenSSH.
    if [ "$RHEL_VERSION" = "6" ]; then
        val=$(get_sshd_opt Protocol); val="${val%% *}"
        if [ "$val" = "2" ]; then
            report "5.2.Protocol" "PASS" "SSH Protocol = 2"
        else
            report "5.2.Protocol" "FAIL" "SSH Protocol = 2" "Current: ${val:-unset}"
        fi
    fi

    # Banner
    val=$(get_sshd_opt Banner); val="${val%% *}"
    if [ "$val" = "/etc/issue.net" ] || [ "$val" = "/etc/issue" ]; then
        report "5.2.Banner" "PASS" "SSH Banner = $val"
    else
        report "5.2.Banner" "WARN" "SSH Banner = /etc/issue.net" "Current: ${val:-unset}"
    fi

    # Crypto hygiene (MACs, Ciphers, KexAlgorithms) — weak ones should be absent.
    local ciphers macs kex
    ciphers=$(get_sshd_opt Ciphers)
    macs=$(get_sshd_opt MACs)
    kex=$(get_sshd_opt KexAlgorithms)
    if [ -n "$ciphers" ]; then
        if echo ",$ciphers," | grep -Eqi '(3des-cbc|-cbc|arcfour|blowfish|cast128)'; then
            report "5.2.ciphers" "FAIL" "SSH strong ciphers" "Weak cipher in: $ciphers"
        else
            report "5.2.ciphers" "PASS" "SSH ciphers OK"
        fi
    fi
    if [ -n "$macs" ]; then
        if echo ",$macs," | grep -Eqi '(hmac-md5|hmac-sha1[^-]|hmac-ripemd160|umac-64)'; then
            report "5.2.macs" "FAIL" "SSH strong MACs" "Weak MAC in: $macs"
        else
            report "5.2.macs" "PASS" "SSH MACs OK"
        fi
    fi
    if [ -n "$kex" ]; then
        if echo ",$kex," | grep -Eqi '(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|gss-gex-sha1|gss-group1-sha1|gss-group14-sha1)'; then
            report "5.2.kex" "FAIL" "SSH strong KEX" "Weak KEX in: $kex"
        else
            report "5.2.kex" "PASS" "SSH KEX OK"
        fi
    fi
}

check_password_aging() {
    section "5.4 Password aging policy"
    local defs=/etc/login.defs
    [ -f "$defs" ] || { report "5.4" "SKIP" "login.defs" "$defs not found"; return; }
    local val
    val=$(awk '$1=="PASS_MAX_DAYS"{print $2; exit}' "$defs")
    if [ -n "$val" ] && [ "$val" -le 365 ] 2>/dev/null && [ "$val" -gt 0 ] 2>/dev/null; then
        report "5.4.MAX" "PASS" "PASS_MAX_DAYS = $val (<= 365)"
    else
        report "5.4.MAX" "FAIL" "PASS_MAX_DAYS <= 365 and > 0" "Current: ${val:-unset}"
    fi
    val=$(awk '$1=="PASS_MIN_DAYS"{print $2; exit}' "$defs")
    if [ -n "$val" ] && [ "$val" -ge 1 ] 2>/dev/null; then
        report "5.4.MIN" "PASS" "PASS_MIN_DAYS = $val (>= 1)"
    else
        report "5.4.MIN" "FAIL" "PASS_MIN_DAYS >= 1" "Current: ${val:-unset}"
    fi
    val=$(awk '$1=="PASS_WARN_AGE"{print $2; exit}' "$defs")
    if [ -n "$val" ] && [ "$val" -ge 7 ] 2>/dev/null; then
        report "5.4.WARN" "PASS" "PASS_WARN_AGE = $val (>= 7)"
    else
        report "5.4.WARN" "FAIL" "PASS_WARN_AGE >= 7" "Current: ${val:-unset}"
    fi
}

check_inactive_lockout() {
    section "5.5 Inactive account lockout"
    local inactive
    # useradd -D reads /etc/default/useradd which is world-readable.
    inactive=$(useradd -D 2>/dev/null | awk -F= '/^INACTIVE/{print $2; exit}')
    if [ -z "$inactive" ] && [ -f /etc/default/useradd ]; then
        inactive=$(awk -F= '/^INACTIVE/{print $2; exit}' /etc/default/useradd)
    fi
    if [ -n "$inactive" ] && [ "$inactive" -ge 1 ] 2>/dev/null && \
       [ "$inactive" -le 30 ] 2>/dev/null; then
        report "5.5.1" "PASS" "Default INACTIVE = $inactive"
    else
        report "5.5.1" "FAIL" "Default INACTIVE in [1..30]" "Current: ${inactive:-unset}"
    fi
}

check_root_uid() {
    section "6.2 Root UID/GID"
    local root_uids
    root_uids=$(awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
    if [ "$(echo "$root_uids" | wc -w)" -eq 1 ] && \
       [ "$(echo "$root_uids" | tr -d ' ')" = "root" ]; then
        report "6.2.uid0" "PASS" "Only 'root' has UID 0"
    else
        report "6.2.uid0" "FAIL" "Only 'root' has UID 0" "Users with UID 0: $root_uids"
    fi
    # root's default GID should be 0
    local root_gid
    root_gid=$(awk -F: '$1=="root"{print $4; exit}' /etc/passwd 2>/dev/null)
    if [ "$root_gid" = "0" ]; then
        report "6.2.rootgid" "PASS" "root GID = 0"
    else
        report "6.2.rootgid" "FAIL" "root GID = 0" "Current: ${root_gid:-unset}"
    fi
}

check_world_writable_files() {
    section "6.1 World-writable files"
    local ww
    ww=$(find_all_local -type f -perm -0002 | head -n 10)
    if [ -z "$ww" ]; then
        report "6.1.ww" "PASS" "No world-writable files found"
    else
        report "6.1.ww" "FAIL" "World-writable files" \
            "Examples: $(echo "$ww" | tr '\n' ' ')"
    fi
}

check_unowned_files() {
    section "6.1 Unowned / ungrouped files"
    local unowned ungroup
    unowned=$(find_all_local -nouser | head -n 10)
    ungroup=$(find_all_local -nogroup | head -n 10)
    if [ -z "$unowned" ]; then
        report "6.1.unowned" "PASS" "No unowned files found"
    else
        report "6.1.unowned" "FAIL" "Unowned files" \
            "Examples: $(echo "$unowned" | tr '\n' ' ')"
    fi
    if [ -z "$ungroup" ]; then
        report "6.1.ungroup" "PASS" "No ungrouped files found"
    else
        report "6.1.ungroup" "FAIL" "Ungrouped files" \
            "Examples: $(echo "$ungroup" | tr '\n' ' ')"
    fi
}

check_passwd_shadow_perms() {
    section "6.1.3 /etc/passwd, /etc/shadow, /etc/group permissions"
    # Expected maximum perms per file.
    declare -A expect_perms=(
        [/etc/passwd]=644
        [/etc/shadow]=000
        [/etc/group]=644
        [/etc/gshadow]=000
        [/etc/passwd-]=644
        [/etc/shadow-]=000
        [/etc/group-]=644
        [/etc/gshadow-]=000
    )
    local f got_perms got_owner exp
    for f in "${!expect_perms[@]}"; do
        [ -f "$f" ] || continue
        got_perms=$(stat -c "%a" "$f" 2>/dev/null)
        got_owner=$(stat -c "%U:%G" "$f" 2>/dev/null)
        exp="${expect_perms[$f]}"
        # shadow/gshadow on RHEL 8 may be 000 or 0; accept either strict variant.
        # RHEL 8 also sometimes has 0640 with root:root, which CIS accepts. We
        # accept any perm stricter-or-equal to the maximum documented.
        if [ "$got_owner" = "root:root" ] && perms_at_most "$got_perms" "$exp"; then
            report "6.1.${f##*/}" "PASS" "$f = $got_perms $got_owner"
        else
            # Special-case shadow files with root:root 640 — also CIS-acceptable
            if [ "$f" = "/etc/shadow" ] || [ "$f" = "/etc/gshadow" ] || \
               [ "$f" = "/etc/shadow-" ] || [ "$f" = "/etc/gshadow-" ]; then
                if [ "$got_owner" = "root:root" ] && perms_at_most "$got_perms" 640; then
                    report "6.1.${f##*/}" "PASS" "$f = $got_perms $got_owner (<=640)"
                    continue
                fi
            fi
            report "6.1.${f##*/}" "FAIL" "$f <= $exp root:root" \
                "Current: $got_perms $got_owner"
        fi
    done
}

check_passwd_shadow_consistency() {
    section "6.2 passwd / shadow / group consistency"
    # No empty password fields in shadow
    local empty
    empty=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$empty" ]; then
        report "6.2.shadow.empty" "PASS" "No empty password fields in shadow"
    else
        report "6.2.shadow.empty" "FAIL" "No empty password fields" \
            "Users: $(echo "$empty" | tr '\n' ' ')"
    fi
    # No legacy NIS '+' entries
    local f
    for f in /etc/passwd /etc/shadow /etc/group; do
        [ -f "$f" ] || continue
        if grep -q '^\+:' "$f" 2>/dev/null; then
            report "6.2.nis.${f##*/}" "FAIL" "No legacy '+' entries in $f"
        else
            report "6.2.nis.${f##*/}" "PASS" "No legacy '+' entries in $f"
        fi
    done
    # No duplicate UIDs / GIDs / usernames / groupnames
    local n_uid n_uniq_uid
    n_uid=$(cut -d: -f3 /etc/passwd 2>/dev/null | wc -l)
    n_uniq_uid=$(cut -d: -f3 /etc/passwd 2>/dev/null | sort -u | wc -l)
    if [ "$n_uid" -eq "$n_uniq_uid" ]; then
        report "6.2.dup.uid" "PASS" "No duplicate UIDs"
    else
        report "6.2.dup.uid" "FAIL" "No duplicate UIDs" "$n_uid lines, $n_uniq_uid unique"
    fi
    local n_gid n_uniq_gid
    n_gid=$(cut -d: -f3 /etc/group 2>/dev/null | wc -l)
    n_uniq_gid=$(cut -d: -f3 /etc/group 2>/dev/null | sort -u | wc -l)
    if [ "$n_gid" -eq "$n_uniq_gid" ]; then
        report "6.2.dup.gid" "PASS" "No duplicate GIDs"
    else
        report "6.2.dup.gid" "FAIL" "No duplicate GIDs" "$n_gid lines, $n_uniq_gid unique"
    fi
    local n_un n_uniq_un
    n_un=$(cut -d: -f1 /etc/passwd 2>/dev/null | wc -l)
    n_uniq_un=$(cut -d: -f1 /etc/passwd 2>/dev/null | sort -u | wc -l)
    if [ "$n_un" -eq "$n_uniq_un" ]; then
        report "6.2.dup.user" "PASS" "No duplicate usernames"
    else
        report "6.2.dup.user" "FAIL" "No duplicate usernames"
    fi
    local n_gn n_uniq_gn
    n_gn=$(cut -d: -f1 /etc/group 2>/dev/null | wc -l)
    n_uniq_gn=$(cut -d: -f1 /etc/group 2>/dev/null | sort -u | wc -l)
    if [ "$n_gn" -eq "$n_uniq_gn" ]; then
        report "6.2.dup.group" "PASS" "No duplicate group names"
    else
        report "6.2.dup.group" "FAIL" "No duplicate group names"
    fi
    # Groups referenced in passwd exist in group
    local missing_gids
    missing_gids=$(awk -F: 'NR==FNR{g[$3]=1; next} !($4 in g){print $4}' \
        /etc/group /etc/passwd 2>/dev/null | sort -u | tr '\n' ' ')
    if [ -z "$missing_gids" ]; then
        report "6.2.grp.consistency" "PASS" "All GIDs in passwd exist in group"
    else
        report "6.2.grp.consistency" "FAIL" "GIDs in passwd missing from group" \
            "GIDs: $missing_gids"
    fi
    # Root PATH integrity
    check_root_path
}

check_root_path() {
    # CIS: no empty entries, no trailing colon, no '.', each dir is a root-owned
    # directory with no group/other write.
    #
    # If we are not root, SKIP. Earlier versions tried `su -l root` to read
    # root's PATH but that can hang on a password prompt; not worth it.
    if ! is_root; then
        report "6.2.root.path" "SKIP" "Root PATH integrity" "Requires root"
        return
    fi
    local path_str="${PATH:-}"
    if [ -z "$path_str" ]; then
        report "6.2.root.path" "SKIP" "Root PATH integrity" "PATH is empty"
        return
    fi
    local issues=""
    case "$path_str" in
        *::*) issues="${issues}empty-entry " ;;
    esac
    case "$path_str" in
        *:) issues="${issues}trailing-colon " ;;
    esac
    local IFS_SAVE="$IFS"
    IFS=':'
    local dir mode owner
    for dir in $path_str; do
        if [ "$dir" = "." ]; then issues="${issues}has-dot "; continue; fi
        [ -z "$dir" ] && continue
        if [ ! -d "$dir" ]; then issues="${issues}missing:${dir} "; continue; fi
        mode=$(safe_stat "%a" "$dir")
        owner=$(safe_stat "%U" "$dir")
        if [ -z "$mode" ] || [ -z "$owner" ]; then
            issues="${issues}unreadable:${dir} "
            continue
        fi
        if [ "$owner" != "root" ]; then issues="${issues}non-root:${dir} "; fi
        case "$mode" in ''|*[!0-7]*) ;; *)
            if [ "$((8#${mode} & 8#022))" -ne 0 ]; then
                issues="${issues}world-or-group-writable:${dir} "
            fi ;;
        esac
    done
    IFS="$IFS_SAVE"
    if [ -z "$issues" ]; then
        report "6.2.root.path" "PASS" "Root PATH integrity OK"
    else
        report "6.2.root.path" "FAIL" "Root PATH integrity" "$issues"
    fi
}

check_home_dirs() {
    section "6.2 User home directories"
    local bad_perms="" missing="" wrong_owner="" unreadable=""
    local user uid home shell mode owner
    while IFS=: read -r user _ uid _ _ home shell; do
        # Skip system accounts and special users.
        [ "$uid" -lt 1000 ] 2>/dev/null && continue
        [ "$user" = "nfsnobody" ] && continue
        if [ "$shell" = "/sbin/nologin" ] || [ "$shell" = "/bin/false" ] || \
           [ "$shell" = "/usr/sbin/nologin" ]; then
            continue
        fi
        [ -z "$home" ] && continue
        # Bounded directory existence check — tests a test-d via timeout to
        # prevent hangs on stale NFS home mounts.
        if ! safe_run "$SAFE_TIMEOUT" test -d "$home"; then
            # Distinguish "does not exist" from "unreadable/hanging"
            if [ ! -e "$home" ] 2>/dev/null; then
                missing="${missing}${user}:${home} "
            else
                unreadable="${unreadable}${user}:${home} "
            fi
            continue
        fi
        mode=$(safe_stat "%a" "$home")
        owner=$(safe_stat "%U" "$home")
        if [ -z "$mode" ] || [ -z "$owner" ]; then
            unreadable="${unreadable}${user}:${home} "
            continue
        fi
        if [ "$owner" != "$user" ]; then
            wrong_owner="${wrong_owner}${user}->${owner}@${home} "
        fi
        # CIS: no group-write, no other-read/write/exec (perms ≤ 0750, but
        # strictly no 'o' bits is the recommendation).
        case "$mode" in ''|*[!0-7]*) ;; *)
            if [ "$((8#${mode} & 8#027))" -ne 0 ]; then
                bad_perms="${bad_perms}${home}(${mode}) "
            fi ;;
        esac
    done < /etc/passwd
    if [ -z "$missing" ]; then
        report "6.2.home.exist" "PASS" "All user home directories exist"
    else
        report "6.2.home.exist" "FAIL" "All user home directories exist" "Missing: $missing"
    fi
    if [ -z "$unreadable" ]; then
        report "6.2.home.reachable" "PASS" "All home directories reachable"
    else
        report "6.2.home.reachable" "WARN" "Home directories unreachable (stale mount?)" "$unreadable"
    fi
    if [ -z "$wrong_owner" ]; then
        report "6.2.home.owner" "PASS" "Home directories owned by the user"
    else
        report "6.2.home.owner" "FAIL" "Home directories owned by the user" "$wrong_owner"
    fi
    if [ -z "$bad_perms" ]; then
        report "6.2.home.perms" "PASS" "Home directory permissions OK"
    else
        report "6.2.home.perms" "FAIL" "Home dirs too permissive (≤750 & no 'o')" "$bad_perms"
    fi
}

check_user_dot_files() {
    section "6.2 User dotfile / .netrc / .rhosts / .forward"
    local bad_dot="" netrc_files="" forward_files="" rhosts_files=""
    local user uid home shell f mode
    while IFS=: read -r user _ uid _ _ home shell; do
        [ "$uid" -lt 1000 ] 2>/dev/null && continue
        [ "$user" = "nfsnobody" ] && continue
        if [ "$shell" = "/sbin/nologin" ] || [ "$shell" = "/bin/false" ] || \
           [ "$shell" = "/usr/sbin/nologin" ]; then
            continue
        fi
        [ -z "$home" ] && continue
        # Bounded directory check — hanging NFS home directories get skipped.
        safe_run "$SAFE_TIMEOUT" test -d "$home" || continue

        # Dotfiles should not be group or world writable.
        # Use a bounded find instead of shell globbing to avoid hangs.
        local dotlist
        dotlist=$(safe_run "$SAFE_TIMEOUT" find "$home" -maxdepth 1 -type f -name '.*' -not -name '.' -not -name '..')
        if [ -n "$dotlist" ]; then
            while IFS= read -r f; do
                [ -n "$f" ] || continue
                mode=$(safe_stat "%a" "$f")
                if [ -n "$mode" ]; then
                    case "$mode" in ''|*[!0-7]*) ;; *)
                        if [ "$((8#${mode} & 8#022))" -ne 0 ]; then
                            bad_dot="${bad_dot}${f}(${mode}) "
                        fi ;;
                    esac
                fi
            done <<< "$dotlist"
        fi
        safe_run "$SAFE_TIMEOUT" test -f "$home/.netrc"   && netrc_files="${netrc_files}${home}/.netrc "
        safe_run "$SAFE_TIMEOUT" test -f "$home/.forward" && forward_files="${forward_files}${home}/.forward "
        safe_run "$SAFE_TIMEOUT" test -f "$home/.rhosts"  && rhosts_files="${rhosts_files}${home}/.rhosts "
    done < /etc/passwd

    if [ -z "$bad_dot" ]; then
        report "6.2.dotfiles" "PASS" "User dotfiles not group/world writable"
    else
        report "6.2.dotfiles" "FAIL" "User dotfiles not group/world writable" "$bad_dot"
    fi
    if [ -z "$netrc_files" ]; then
        report "6.2.netrc" "PASS" "No user .netrc files"
    else
        report "6.2.netrc" "FAIL" "No user .netrc files" "$netrc_files"
    fi
    if [ -z "$forward_files" ]; then
        report "6.2.forward" "PASS" "No user .forward files"
    else
        report "6.2.forward" "FAIL" "No user .forward files" "$forward_files"
    fi
    if [ -z "$rhosts_files" ]; then
        report "6.2.rhosts" "PASS" "No user .rhosts files"
    else
        report "6.2.rhosts" "FAIL" "No user .rhosts files" "$rhosts_files"
    fi
}

check_banners() {
    section "Warning banners"
    local f
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if [ -f "$f" ] && [ -s "$f" ]; then
            if grep -Eq '\\m|\\s|\\r|\\v' "$f"; then
                report "banner.${f##*/}" "FAIL" "$f banner clean" \
                    "Contains OS escape sequences (\\m \\s \\r \\v)"
            else
                report "banner.${f##*/}" "PASS" "$f banner present & clean"
            fi
        else
            report "banner.${f##*/}" "FAIL" "$f banner present" "Empty or missing"
        fi
        if [ -f "$f" ]; then
            local mode owner
            mode=$(stat -L -c "%a" "$f" 2>/dev/null)
            owner=$(stat -L -c "%U:%G" "$f" 2>/dev/null)
            if [ "$owner" = "root:root" ] && perms_at_most "$mode" 644; then
                report "banner.perms.${f##*/}" "PASS" "$f = $mode $owner"
            else
                report "banner.perms.${f##*/}" "FAIL" "$f perms 644 root:root" \
                    "Current: $mode $owner"
            fi
        fi
    done
}

check_selinux() {
    section "SELinux"
    if ! command -v getenforce >/dev/null 2>&1; then
        report "se.mode" "FAIL" "SELinux available" "getenforce not present"
        return
    fi
    local mode
    mode=$(getenforce 2>/dev/null)
    if [ "$mode" = "Enforcing" ]; then
        report "se.mode" "PASS" "SELinux = Enforcing"
    else
        report "se.mode" "FAIL" "SELinux Enforcing" "Current: ${mode:-unknown}"
    fi
    if grep -Eq '^[[:space:]]*SELINUX=enforcing' /etc/selinux/config 2>/dev/null; then
        report "se.config" "PASS" "SELinux config = enforcing"
    else
        report "se.config" "FAIL" "SELinux config = enforcing"
    fi
    if grep -Eq '^[[:space:]]*SELINUXTYPE=(targeted|mls)' /etc/selinux/config 2>/dev/null; then
        report "se.type" "PASS" "SELINUXTYPE = targeted/mls"
    else
        report "se.type" "FAIL" "SELINUXTYPE = targeted or mls"
    fi
    if [ -f /proc/cmdline ] && grep -Eq '(^|[[:space:]])(selinux|enforcing)=0([[:space:]]|$)' /proc/cmdline; then
        report "se.cmdline" "FAIL" "SELinux not disabled on cmdline" \
            "selinux=0 or enforcing=0 found in /proc/cmdline"
    else
        report "se.cmdline" "PASS" "SELinux not disabled on cmdline"
    fi
    # setroubleshoot / mcstrans should not be installed
    if pkg_installed setroubleshoot; then
        report "se.setroubleshoot" "FAIL" "setroubleshoot not installed" "Package present"
    else
        report "se.setroubleshoot" "PASS" "setroubleshoot not installed"
    fi
    if pkg_installed mcstrans; then
        report "se.mcstrans" "FAIL" "mcstrans not installed" "Package present"
    else
        report "se.mcstrans" "PASS" "mcstrans not installed"
    fi
    # Unconfined daemons
    if command -v ps >/dev/null 2>&1; then
        local uncf
        # shellcheck disable=SC2009  # pgrep can't filter on SELinux context
        uncf=$(ps -eZ 2>/dev/null | grep -E 'initrc|unconfined_service_t' \
            | grep -Ev 'bash|ps|grep|sshd' | head -n 5)
        if [ -z "$uncf" ]; then
            report "se.unconfined" "PASS" "No unconfined daemons"
        else
            report "se.unconfined" "WARN" "Unconfined daemons present" \
                "Examples: $(echo "$uncf" | head -n1)"
        fi
    fi
}

check_auditd_common() {
    section "Auditd"
    if ! pkg_installed audit; then
        report "aud.pkg" "FAIL" "audit installed" "Package 'audit' missing"
        return
    fi
    if svc_enabled auditd && svc_active auditd; then
        report "aud.svc" "PASS" "auditd enabled & active"
    else
        report "aud.svc" "FAIL" "auditd enabled & active"
    fi
    local cnf=/etc/audit/auditd.conf
    if [ -f "$cnf" ]; then
        local mlf
        mlf=$(conf_get max_log_file "$cnf")
        if [ -n "$mlf" ] && [ "$mlf" -ge 1 ] 2>/dev/null; then
            report "aud.maxlog" "PASS" "max_log_file = $mlf MB"
        else
            report "aud.maxlog" "FAIL" "max_log_file configured" "Current: ${mlf:-unset}"
        fi
        local mlfa
        mlfa=$(conf_get max_log_file_action "$cnf")
        mlfa=$(echo "$mlfa" | tr '[:upper:]' '[:lower:]')
        if [ "$mlfa" = "keep_logs" ]; then
            report "aud.maxlog.action" "PASS" "max_log_file_action = keep_logs"
        else
            report "aud.maxlog.action" "FAIL" "max_log_file_action = keep_logs" \
                "Current: ${mlfa:-unset}"
        fi
        local spla
        spla=$(conf_get space_left_action "$cnf")
        spla=$(echo "$spla" | tr '[:upper:]' '[:lower:]')
        case "$spla" in
            email|exec|single|halt)
                report "aud.space" "PASS" "space_left_action = $spla" ;;
            *)
                report "aud.space" "FAIL" "space_left_action = email/exec/single/halt" \
                    "Current: ${spla:-unset}" ;;
        esac
        local adm
        adm=$(conf_get admin_space_left_action "$cnf")
        adm=$(echo "$adm" | tr '[:upper:]' '[:lower:]')
        case "$adm" in
            halt|single)
                report "aud.adm.space" "PASS" "admin_space_left_action = $adm" ;;
            *)
                report "aud.adm.space" "FAIL" "admin_space_left_action = halt/single" \
                    "Current: ${adm:-unset}" ;;
        esac
    else
        # /etc/audit/ is typically 750 root:root so a non-root run can't even
        # see the files. Differentiate "really missing" from "cannot read".
        if ! is_root && [ -d /etc/audit ] 2>/dev/null || ls /etc/audit/ >/dev/null 2>&1; then
            report "aud.conf" "SKIP" "auditd.conf present" \
                "/etc/audit is restricted; requires root"
        else
            report "aud.conf" "FAIL" "auditd.conf present" "$cnf missing"
        fi
    fi
    # Audit rules immutable: last rule should be -e 2
    local rules=/etc/audit/audit.rules
    if [ -f "$rules" ]; then
        if tac "$rules" | grep -m1 -Eq '^[[:space:]]*-e[[:space:]]+2' ; then
            report "aud.immutable" "PASS" "audit rules end with -e 2"
        else
            report "aud.immutable" "WARN" "audit rules end with -e 2" \
                "No '-e 2' final line (or rules not immutable)"
        fi
    elif ! is_root; then
        report "aud.immutable" "SKIP" "audit rules end with -e 2" "Requires root"
    fi
}

check_auditd_rules() {
    section "Auditd rules coverage (sampled)"
    local rules=/etc/audit/audit.rules
    local dropin=/etc/audit/rules.d
    local content=""
    [ -f "$rules" ] && content="$(cat "$rules")"
    if [ -d "$dropin" ]; then
        # shellcheck disable=SC2012
        content="${content}$(cat "$dropin"/*.rules 2>/dev/null || true)"
    fi
    if [ -z "$content" ]; then
        if ! is_root; then
            report "aud.rules" "SKIP" "Audit rules" "Requires root (/etc/audit is restricted)"
        else
            report "aud.rules" "SKIP" "Audit rules" "No audit rules files found"
        fi
        return
    fi
    # Helper: grep content without comments
    _rules_grep() { echo "$content" | grep -v '^[[:space:]]*#' | grep -E "$1" >/dev/null; }

    # time-change
    if _rules_grep '\-k[[:space:]]+time-change' && \
       _rules_grep 'settimeofday|adjtimex|clock_settime|/etc/localtime'; then
        report "aud.rules.time" "PASS" "time-change rules present"
    else
        report "aud.rules.time" "FAIL" "time-change rules (settimeofday/adjtimex/clock_settime/localtime)"
    fi
    # identity
    if _rules_grep '\-k[[:space:]]+identity' && \
       _rules_grep '/etc/group|/etc/passwd|/etc/shadow|/etc/gshadow|/etc/security/opasswd'; then
        report "aud.rules.identity" "PASS" "identity rules present"
    else
        report "aud.rules.identity" "FAIL" "identity rules (group/passwd/shadow/gshadow/opasswd)"
    fi
    # system-locale
    if _rules_grep '\-k[[:space:]]+system-locale' && \
       _rules_grep 'sethostname|setdomainname|/etc/issue|/etc/hosts|/etc/sysconfig/network'; then
        report "aud.rules.locale" "PASS" "system-locale rules present"
    else
        report "aud.rules.locale" "FAIL" "system-locale rules"
    fi
    # MAC
    if _rules_grep '\-k[[:space:]]+MAC-policy' && _rules_grep '/etc/selinux'; then
        report "aud.rules.mac" "PASS" "MAC-policy rules present"
    else
        report "aud.rules.mac" "FAIL" "MAC-policy rules (/etc/selinux)"
    fi
    # logins
    if _rules_grep '\-k[[:space:]]+logins' && \
       _rules_grep '/var/log/lastlog|/var/log/faillog|/var/log/tallylog'; then
        report "aud.rules.logins" "PASS" "logins rules present"
    else
        report "aud.rules.logins" "FAIL" "logins rules (lastlog/faillog/tallylog)"
    fi
    # session
    if _rules_grep '\-k[[:space:]]+(session|logins)' && \
       _rules_grep '/var/run/utmp|/var/log/wtmp|/var/log/btmp'; then
        report "aud.rules.session" "PASS" "session rules present"
    else
        report "aud.rules.session" "FAIL" "session rules (utmp/wtmp/btmp)"
    fi
    # perm_mod
    if _rules_grep '\-k[[:space:]]+perm_mod' && \
       _rules_grep 'chmod|chown|setxattr'; then
        report "aud.rules.perm_mod" "PASS" "perm_mod rules present"
    else
        report "aud.rules.perm_mod" "FAIL" "perm_mod rules (chmod/chown/xattr)"
    fi
    # access (EACCES / EPERM)
    if _rules_grep '\-k[[:space:]]+access' && \
       _rules_grep 'EACCES|EPERM'; then
        report "aud.rules.access" "PASS" "access-failure rules present"
    else
        report "aud.rules.access" "FAIL" "access-failure rules"
    fi
    # mounts
    if _rules_grep '\-k[[:space:]]+mounts' && _rules_grep '-S[[:space:]]+mount'; then
        report "aud.rules.mounts" "PASS" "mounts rules present"
    else
        report "aud.rules.mounts" "FAIL" "mounts rules"
    fi
    # delete
    if _rules_grep '\-k[[:space:]]+delete' && \
       _rules_grep 'unlink|rename'; then
        report "aud.rules.delete" "PASS" "delete rules present"
    else
        report "aud.rules.delete" "FAIL" "delete rules (unlink/rename)"
    fi
    # scope (sudoers) + actions (sudo.log)
    if _rules_grep '/etc/sudoers'; then
        report "aud.rules.scope" "PASS" "sudoers-watch rule present"
    else
        report "aud.rules.scope" "FAIL" "watch on /etc/sudoers"
    fi
    # modules
    if _rules_grep '\-k[[:space:]]+modules' && \
       _rules_grep 'insmod|rmmod|modprobe|init_module|delete_module'; then
        report "aud.rules.modules" "PASS" "module-load rules present"
    else
        report "aud.rules.modules" "FAIL" "module-load rules"
    fi
}

check_rsyslog() {
    section "Rsyslog / journald"
    if pkg_installed rsyslog; then
        if svc_enabled rsyslog 2>/dev/null || svc_active rsyslog 2>/dev/null; then
            report "log.rsyslog" "PASS" "rsyslog enabled/active"
        else
            report "log.rsyslog" "FAIL" "rsyslog enabled/active"
        fi
        # Check for remote forwarding (warning only — not every env uses central log)
        if grep -Eqs '^[^#]*@@?[A-Za-z0-9.:_-]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
            report "log.remote" "PASS" "rsyslog forwards to remote host"
        else
            report "log.remote" "WARN" "rsyslog forwards to remote host" \
                "No @ or @@ remote target found"
        fi
    else
        report "log.rsyslog" "FAIL" "rsyslog installed" "Package missing"
    fi
}

check_cron_perms_and_acl() {
    section "5.1 Cron & at permissions/ACL"
    if svc_enabled crond && svc_active crond; then
        report "cron.svc" "PASS" "crond enabled & active"
    else
        report "cron.svc" "FAIL" "crond enabled & active"
    fi
    local f mode owner
    for f in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
             /etc/cron.monthly /etc/cron.d /etc/anacrontab; do
        [ -e "$f" ] || continue
        mode=$(stat -L -c "%a" "$f" 2>/dev/null)
        owner=$(stat -L -c "%U:%G" "$f" 2>/dev/null)
        if [ "$owner" = "root:root" ] && perms_no_world_group "$mode"; then
            report "cron.${f##*/}" "PASS" "$f = $mode $owner"
        else
            report "cron.${f##*/}" "FAIL" "$f root:root 700 or stricter" \
                "Current: $mode $owner"
        fi
    done
    # cron.allow exists, cron.deny absent
    if [ -f /etc/cron.allow ]; then
        report "cron.allow" "PASS" "/etc/cron.allow exists"
        mode=$(stat -L -c "%a" /etc/cron.allow 2>/dev/null)
        owner=$(stat -L -c "%U:%G" /etc/cron.allow 2>/dev/null)
        if [ "$owner" = "root:root" ] && perms_at_most "$mode" 600; then
            report "cron.allow.perms" "PASS" "/etc/cron.allow = $mode $owner"
        else
            report "cron.allow.perms" "FAIL" "/etc/cron.allow perms 600 root:root" \
                "Current: $mode $owner"
        fi
    else
        report "cron.allow" "FAIL" "/etc/cron.allow exists" "File missing"
    fi
    if [ -f /etc/cron.deny ]; then
        report "cron.deny" "FAIL" "/etc/cron.deny absent" "File present; use cron.allow instead"
    else
        report "cron.deny" "PASS" "/etc/cron.deny absent"
    fi
    if [ -f /etc/at.allow ]; then
        report "at.allow" "PASS" "/etc/at.allow exists"
    else
        report "at.allow" "WARN" "/etc/at.allow exists" "File missing (only required if 'at' is used)"
    fi
    if [ -f /etc/at.deny ]; then
        report "at.deny" "WARN" "/etc/at.deny absent" "File present"
    else
        report "at.deny" "PASS" "/etc/at.deny absent"
    fi
}

check_securetty_su() {
    section "5.6/5.7 securetty & su restriction"
    if [ -f /etc/securetty ] && [ -s /etc/securetty ]; then
        # Only console + (optional) vc/* is typical; anything else is unusual.
        local odd
        odd=$(grep -Ev '^(console|vc/[0-9]+|tty[0-9]+)$|^[[:space:]]*(#|$)' /etc/securetty 2>/dev/null | head -n1)
        if [ -z "$odd" ]; then
            report "5.6.securetty" "PASS" "securetty restricted to console/tty"
        else
            report "5.6.securetty" "WARN" "securetty restricted to console/tty" \
                "Unexpected entry: $odd"
        fi
    fi
    # su restricted to wheel group members
    if [ -f /etc/pam.d/su ] && \
       grep -Eq '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*use_uid' /etc/pam.d/su; then
        report "5.7.su.pam" "PASS" "pam_wheel.so required in /etc/pam.d/su"
    else
        report "5.7.su.pam" "FAIL" "pam_wheel.so required in /etc/pam.d/su"
    fi
}

check_default_umask() {
    section "5.5 Default umask"
    # CIS recommends umask 027.
    local found=0
    for f in /etc/bashrc /etc/profile /etc/profile.d/*.sh /etc/login.defs; do
        [ -f "$f" ] || continue
        if grep -Eq 'umask[[:space:]]+02[7]|UMASK[[:space:]]+027' "$f" 2>/dev/null; then
            found=1; break
        fi
    done
    if [ "$found" -eq 1 ]; then
        report "5.5.umask" "PASS" "umask 027 configured"
    else
        report "5.5.umask" "WARN" "umask 027 configured" "Not found in profile/bashrc/login.defs"
    fi
}

check_gpg_and_repos() {
    section "1.2 GPG keys & repos"
    if rpm -q gpg-pubkey >/dev/null 2>&1; then
        report "1.2.gpg" "PASS" "GPG keys installed in RPM DB"
    else
        report "1.2.gpg" "FAIL" "GPG keys installed in RPM DB"
    fi
    if [ -f /etc/yum.conf ] && \
       grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*1' /etc/yum.conf; then
        report "1.2.gpgcheck" "PASS" "gpgcheck=1 in /etc/yum.conf"
    else
        report "1.2.gpgcheck" "FAIL" "gpgcheck=1 in /etc/yum.conf"
    fi
    # Every .repo should have gpgcheck=1
    local bad=""
    local rf
    for rf in /etc/yum.repos.d/*.repo; do
        [ -f "$rf" ] || continue
        if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$rf"; then
            bad="${bad}${rf##*/} "
        fi
    done
    if [ -z "$bad" ]; then
        report "1.2.repos" "PASS" "No repo has gpgcheck=0"
    else
        report "1.2.repos" "FAIL" "No repo has gpgcheck=0" "Offending: $bad"
    fi
}

check_sudo_installed() {
    section "1.3 sudo"
    if pkg_installed sudo; then
        report "1.3.sudo" "PASS" "sudo installed"
    else
        report "1.3.sudo" "FAIL" "sudo installed"
    fi
    # Sudo log file warning
    if grep -rhqs '^[[:space:]]*Defaults.*logfile=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        report "1.3.sudo.log" "PASS" "sudo logfile configured"
    else
        report "1.3.sudo.log" "WARN" "sudo logfile configured" \
            "No 'Defaults logfile=' found in sudoers"
    fi
    if grep -rhqs '^[[:space:]]*Defaults[[:space:]]\+.*use_pty' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        report "1.3.sudo.pty" "PASS" "sudo use_pty configured"
    else
        report "1.3.sudo.pty" "WARN" "sudo use_pty configured" \
            "No 'Defaults use_pty' found in sudoers"
    fi
}

check_password_quality() {
    section "5.3 Password quality (pam_pwquality)"
    local pwq=/etc/security/pwquality.conf
    if [ ! -f "$pwq" ]; then
        report "5.3" "FAIL" "pwquality.conf present" "$pwq not found"
        return
    fi
    # Expected: minlen >= 14, dcredit/ucredit/ocredit/lcredit <= -1, retry <= 3.
    local want val
    # minlen >= 14
    val=$(conf_get minlen "$pwq")
    if [ -n "$val" ] && [ "$val" -ge 14 ] 2>/dev/null; then
        report "5.3.minlen" "PASS" "pwquality minlen = $val (>=14)"
    else
        report "5.3.minlen" "FAIL" "pwquality minlen >= 14" "Current: ${val:-unset}"
    fi
    for key in dcredit ucredit ocredit lcredit; do
        val=$(conf_get "$key" "$pwq")
        if [ -n "$val" ] && [ "$val" -le -1 ] 2>/dev/null; then
            report "5.3.${key}" "PASS" "pwquality $key = $val (<=-1)"
        else
            report "5.3.${key}" "FAIL" "pwquality $key <= -1" "Current: ${val:-unset}"
        fi
    done
    val=$(conf_get retry "$pwq")
    if [ -n "$val" ] && [ "$val" -ge 1 ] 2>/dev/null && [ "$val" -le 3 ] 2>/dev/null; then
        report "5.3.retry" "PASS" "pwquality retry = $val"
    else
        # retry can also be set in PAM config; check system-auth for retry
        if grep -Eqs 'pam_pwquality\.so.*retry=[1-3]' /etc/pam.d/system-auth /etc/pam.d/password-auth; then
            report "5.3.retry" "PASS" "pwquality retry set in PAM"
        else
            report "5.3.retry" "WARN" "pwquality retry in [1,3]" "Current: ${val:-unset}"
        fi
    fi
    # Password hash algorithm: sha512
    if grep -Eqs '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+SHA512' /etc/login.defs; then
        report "5.3.hash" "PASS" "ENCRYPT_METHOD = SHA512"
    else
        report "5.3.hash" "FAIL" "ENCRYPT_METHOD = SHA512 in /etc/login.defs"
    fi
    # Password reuse remember >= 5
    if grep -Eqs 'pam_(pwhistory|unix)\.so.*remember=[5-9]|remember=[1-9][0-9]+' \
            /etc/pam.d/system-auth /etc/pam.d/password-auth; then
        report "5.3.remember" "PASS" "password reuse remember >= 5"
    else
        report "5.3.remember" "WARN" "password reuse remember >= 5" \
            "No remember=N (N>=5) found in PAM"
    fi
}

check_suid_sgid_rpm_integrity() {
    section "6.1 SUID/SGID RPM integrity (sampled, slow)"
    if ! is_root; then
        report "6.1.suidsgid" "SKIP" "SUID/SGID RPM integrity" "Requires root"
        return
    fi
    # Limit to a sample: first 50 binaries across local mounts.
    local exes sampled bad="" exe pkg out
    exes=$(find_all_local -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 50)
    sampled=$(echo "$exes" | wc -l)
    if [ -z "$exes" ]; then
        report "6.1.suidsgid" "PASS" "No SUID/SGID binaries found (or none in sample)"
        return
    fi
    for exe in $exes; do
        pkg=$(rpm -qf "$exe" 2>/dev/null)
        # If not owned by an RPM, that IS worth flagging.
        case "$pkg" in
            *'not owned'*|'')
                bad="${bad}unowned:${exe} "
                continue ;;
        esac
        # rpm -V on the file only
        out=$(rpm -V "$pkg" 2>/dev/null | awk -v f="$exe" '$NF==f{print}')
        # "M" in positions 1-8 indicates mode change from package default.
        if echo "$out" | grep -Eq '^.{0,8}M'; then
            bad="${bad}modified:${exe} "
        fi
    done
    if [ -z "$bad" ]; then
        report "6.1.suidsgid" "PASS" "Sampled $sampled SUID/SGID files match RPM DB"
    else
        report "6.1.suidsgid" "WARN" "SUID/SGID files differ from RPM DB" \
            "Examples: $bad"
    fi
}

# =============================================================================
#   RHEL 6-SPECIFIC
# =============================================================================

run_rhel6_specific() {
    section "RHEL6: iptables"
    if pkg_installed iptables; then
        if svc_enabled iptables; then
            report "RH6.fw1" "PASS" "iptables service enabled"
        else
            report "RH6.fw1" "FAIL" "iptables service enabled" "chkconfig shows iptables off"
        fi
        if iptables -L INPUT -n 2>/dev/null | head -n1 | grep -q "policy DROP"; then
            report "RH6.fw2" "PASS" "iptables INPUT default policy is DROP"
        else
            report "RH6.fw2" "WARN" "iptables INPUT default policy = DROP" \
                "Policy line: $(iptables -L INPUT -n 2>/dev/null | head -n1)"
        fi
    else
        report "RH6.fw1" "FAIL" "iptables installed" "Package missing"
    fi
    # ip6tables service comes with iptables package on RHEL 6
    if svc_enabled ip6tables 2>/dev/null; then
        report "RH6.fw3" "PASS" "ip6tables service enabled"
    else
        report "RH6.fw3" "WARN" "ip6tables service enabled"
    fi

    section "RHEL6: pam_cracklib"
    local PAM_FILE=/etc/pam.d/system-auth
    if [ -f "$PAM_FILE" ]; then
        local line
        line=$(grep -E '^[[:space:]]*password[[:space:]]+[^[:space:]]+[[:space:]]+pam_cracklib\.so' \
            "$PAM_FILE" | head -n1)
        if [ -z "$line" ]; then
            report "RH6.pam" "FAIL" "pam_cracklib configured" \
                "No pam_cracklib.so line in $PAM_FILE"
        else
            # Proper value comparison per CIS
            declare -A want=(
                [minlen]=14
                [dcredit]=-1
                [ucredit]=-1
                [ocredit]=-1
                [lcredit]=-1
            )
            local k exp_val actual_val
            for k in "${!want[@]}"; do
                exp_val="${want[$k]}"
                actual_val=$(echo "$line" | grep -oE "${k}=-?[0-9]+" | head -n1 | cut -d= -f2)
                if [ -z "$actual_val" ]; then
                    report "RH6.pam.${k}" "FAIL" "pam_cracklib ${k}=${exp_val}" \
                        "Not set in $PAM_FILE"
                    continue
                fi
                case "$k" in
                    minlen)
                        if [ "$actual_val" -ge "$exp_val" ] 2>/dev/null; then
                            report "RH6.pam.${k}" "PASS" "pam_cracklib ${k}=${actual_val} (>=${exp_val})"
                        else
                            report "RH6.pam.${k}" "FAIL" "pam_cracklib ${k}>=${exp_val}" \
                                "Current: $actual_val"
                        fi ;;
                    dcredit|ucredit|ocredit|lcredit)
                        if [ "$actual_val" -le "$exp_val" ] 2>/dev/null; then
                            report "RH6.pam.${k}" "PASS" "pam_cracklib ${k}=${actual_val} (<=${exp_val})"
                        else
                            report "RH6.pam.${k}" "FAIL" "pam_cracklib ${k}<=${exp_val}" \
                                "Current: $actual_val"
                        fi ;;
                esac
            done
        fi
    else
        report "RH6.pam" "SKIP" "pam_cracklib" "$PAM_FILE not found"
    fi

    section "RHEL6: tcp_wrappers"
    if pkg_installed tcp_wrappers; then
        report "RH6.tcpw" "PASS" "tcp_wrappers installed"
        if [ -f /etc/hosts.deny ] && \
           grep -Eq '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL' /etc/hosts.deny; then
            report "RH6.tcpw.deny" "PASS" "/etc/hosts.deny has ALL:ALL"
        else
            report "RH6.tcpw.deny" "WARN" "/etc/hosts.deny has ALL:ALL" "Not configured"
        fi
        # Perms on hosts.allow / hosts.deny: 644 root:root
        local f mode owner
        for f in /etc/hosts.allow /etc/hosts.deny; do
            [ -f "$f" ] || continue
            mode=$(stat -L -c "%a" "$f" 2>/dev/null)
            owner=$(stat -L -c "%U:%G" "$f" 2>/dev/null)
            if [ "$owner" = "root:root" ] && perms_at_most "$mode" 644; then
                report "RH6.tcpw.${f##*/}" "PASS" "$f = $mode $owner"
            else
                report "RH6.tcpw.${f##*/}" "FAIL" "$f 644 root:root" "Current: $mode $owner"
            fi
        done
    else
        report "RH6.tcpw" "WARN" "tcp_wrappers installed" "Package missing"
    fi

    section "RHEL6: protocol kernel modules"
    for mod in dccp sctp rds tipc; do
        if module_loaded "$mod"; then
            report "RH6.proto.${mod}" "FAIL" "Disable protocol: $mod" "Module loaded"
        elif module_disabled "$mod" || module_blacklisted "$mod"; then
            report "RH6.proto.${mod}" "PASS" "Disable protocol: $mod"
        else
            report "RH6.proto.${mod}" "WARN" "Disable protocol: $mod" \
                "Not loaded but no install/blacklist rule"
        fi
    done
}

# =============================================================================
#   RHEL 7-SPECIFIC
# =============================================================================

run_rhel7_specific() {
    section "RHEL7: firewalld"
    if pkg_installed firewalld; then
        if svc_enabled firewalld && svc_active firewalld; then
            report "RH7.fw1" "PASS" "firewalld enabled & active"
            if command -v firewall-cmd >/dev/null 2>&1; then
                local default_zone
                default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
                if [ -n "$default_zone" ] && [ "$default_zone" != "trusted" ]; then
                    report "RH7.fw2" "PASS" "Default zone = $default_zone"
                else
                    report "RH7.fw2" "FAIL" "Default zone != trusted" \
                        "Current: ${default_zone:-unknown}"
                fi
            fi
        else
            report "RH7.fw1" "FAIL" "firewalld enabled & active"
        fi
    elif pkg_installed iptables-services; then
        report "RH7.fw1" "WARN" "firewalld missing, iptables-services present" \
            "Consider firewalld on RHEL7"
    else
        report "RH7.fw1" "FAIL" "Host firewall installed" \
            "Neither firewalld nor iptables-services found"
    fi
    if svc_active nftables 2>/dev/null; then
        report "RH7.fw3" "WARN" "nftables active" \
            "On RHEL7, firewalld is expected instead of raw nftables"
    fi

    section "RHEL7: audit kernel cmdline"
    if [ -f /proc/cmdline ] && grep -Eqs '(^|[[:space:]])audit=1([[:space:]]|$)' /proc/cmdline; then
        report "RH7.aud.cmdline" "PASS" "audit=1 kernel cmdline"
    else
        report "RH7.aud.cmdline" "FAIL" "audit=1 in kernel cmdline"
    fi
    if [ -f /proc/cmdline ] && grep -Eqs 'audit_backlog_limit=[0-9]+' /proc/cmdline; then
        report "RH7.aud.backlog" "PASS" "audit_backlog_limit in kernel cmdline"
    else
        report "RH7.aud.backlog" "FAIL" "audit_backlog_limit in kernel cmdline" \
            "Add audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX"
    fi

    section "RHEL7: pam_faillock (in pam.d)"
    local f found=0
    for f in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
        [ -f "$f" ] || continue
        # Expect pam_faillock.so preauth with deny=N unlock_time=M
        if grep -Eq 'pam_faillock\.so[[:space:]]+preauth.*deny=[1-5][^0-9]' "$f" && \
           grep -Eq 'pam_faillock\.so.*unlock_time=([9][0-9]{2,}|[1-9][0-9]{3,})' "$f"; then
            report "RH7.faillock.${f##*/}" "PASS" "pam_faillock configured in $f"
            found=1
        else
            report "RH7.faillock.${f##*/}" "FAIL" "pam_faillock deny<=5 unlock_time>=900 in $f"
        fi
    done

    section "RHEL7: protocol kernel modules"
    for mod in dccp sctp rds tipc; do
        if module_loaded "$mod"; then
            report "RH7.proto.${mod}" "FAIL" "Disable protocol: $mod" "Module loaded"
        elif module_disabled "$mod" || module_blacklisted "$mod"; then
            report "RH7.proto.${mod}" "PASS" "Disable protocol: $mod"
        else
            report "RH7.proto.${mod}" "WARN" "Disable protocol: $mod"
        fi
    done
}

# =============================================================================
#   RHEL 8-SPECIFIC
# =============================================================================

run_rhel8_specific() {
    section "RHEL8: crypto-policies"
    if command -v update-crypto-policies >/dev/null 2>&1; then
        local current
        current=$(update-crypto-policies --show 2>/dev/null)
        case "$current" in
            FUTURE|FIPS|DEFAULT)
                report "RH8.crypto" "PASS" "system-wide crypto policy = $current" ;;
            LEGACY)
                report "RH8.crypto" "FAIL" "crypto policy != LEGACY" "Current: LEGACY" ;;
            *)
                report "RH8.crypto" "WARN" "crypto policy set" "Current: ${current:-unknown}" ;;
        esac
    else
        report "RH8.crypto" "SKIP" "crypto-policies" "update-crypto-policies not installed"
    fi

    section "RHEL8: firewall (firewalld or nftables)"
    if pkg_installed firewalld && svc_enabled firewalld && svc_active firewalld; then
        report "RH8.fw1" "PASS" "firewalld enabled & active"
        if command -v firewall-cmd >/dev/null 2>&1; then
            local default_zone
            default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
            if [ -n "$default_zone" ] && [ "$default_zone" != "trusted" ]; then
                report "RH8.fw2" "PASS" "firewalld default zone = $default_zone"
            else
                report "RH8.fw2" "FAIL" "firewalld default zone != trusted" \
                    "Current: ${default_zone:-unknown}"
            fi
        fi
    elif pkg_installed nftables && svc_enabled nftables && svc_active nftables; then
        report "RH8.fw1" "PASS" "nftables enabled & active (standalone)"
        if command -v nft >/dev/null 2>&1 && \
           nft list ruleset 2>/dev/null | grep -Eq 'hook input .*policy (drop|reject)'; then
            report "RH8.fw2" "PASS" "nftables input default policy drop/reject"
        else
            report "RH8.fw2" "FAIL" "nftables input default policy drop/reject"
        fi
    else
        report "RH8.fw1" "FAIL" "Host firewall active" \
            "Neither firewalld nor nftables is active"
    fi
    if pkg_installed iptables-services && svc_enabled iptables 2>/dev/null; then
        report "RH8.fw3" "FAIL" "iptables-services disabled" "Use firewalld/nftables on RHEL8"
    else
        report "RH8.fw3" "PASS" "iptables-services not active"
    fi

    section "RHEL8: audit kernel cmdline"
    if [ -f /proc/cmdline ] && grep -Eqs '(^|[[:space:]])audit=1([[:space:]]|$)' /proc/cmdline; then
        report "RH8.aud.cmdline" "PASS" "audit=1 in kernel cmdline"
    else
        report "RH8.aud.cmdline" "FAIL" "audit=1 in kernel cmdline"
    fi
    if [ -f /proc/cmdline ] && grep -Eqs 'audit_backlog_limit=[0-9]+' /proc/cmdline; then
        report "RH8.aud.backlog" "PASS" "audit_backlog_limit in kernel cmdline"
    else
        report "RH8.aud.backlog" "FAIL" "audit_backlog_limit in kernel cmdline"
    fi

    section "RHEL8: journald"
    if [ -f /etc/systemd/journald.conf ]; then
        local got jd_key jd_want
        for kv in "Storage=persistent" "Compress=yes" "ForwardToSyslog=yes"; do
            jd_key="${kv%=*}"
            jd_want="${kv#*=}"
            got=$(conf_get "$jd_key" /etc/systemd/journald.conf)
            if [ "$got" = "$jd_want" ]; then
                report "RH8.journald.${jd_key}" "PASS" "journald $kv"
            else
                report "RH8.journald.${jd_key}" "FAIL" "journald $kv" "Current: ${got:-unset}"
            fi
        done
    else
        report "RH8.journald" "SKIP" "journald.conf" "File missing"
    fi

    section "RHEL8: pam_faillock.conf"
    local fc=/etc/security/faillock.conf
    if [ -f "$fc" ]; then
        local deny unlock
        deny=$(conf_get deny "$fc")
        unlock=$(conf_get unlock_time "$fc")
        if [ -n "$deny" ] && [ "$deny" -ge 1 ] 2>/dev/null && [ "$deny" -le 5 ] 2>/dev/null; then
            report "RH8.faillock.deny" "PASS" "faillock deny = $deny (1..5)"
        else
            report "RH8.faillock.deny" "FAIL" "faillock deny in [1..5]" \
                "Current: ${deny:-unset}"
        fi
        if [ -n "$unlock" ] && [ "$unlock" -ge 900 ] 2>/dev/null; then
            report "RH8.faillock.unlock" "PASS" "faillock unlock_time = $unlock (>=900)"
        else
            report "RH8.faillock.unlock" "FAIL" "faillock unlock_time >= 900" \
                "Current: ${unlock:-unset}"
        fi
    else
        report "RH8.faillock" "WARN" "/etc/security/faillock.conf present" "File missing"
    fi
    # authselect should include faillock
    if [ -f /etc/authselect/authselect.conf ] && \
       grep -q 'with-faillock' /etc/authselect/authselect.conf; then
        report "RH8.authselect.faillock" "PASS" "authselect includes faillock"
    else
        report "RH8.authselect.faillock" "WARN" "authselect includes faillock"
    fi

    section "RHEL8: USB storage"
    if module_loaded usb_storage; then
        report "RH8.usb" "FAIL" "usb-storage disabled" "Module is loaded"
    elif module_disabled usb-storage || module_disabled usb_storage || \
         module_blacklisted usb-storage || module_blacklisted usb_storage; then
        report "RH8.usb" "PASS" "usb-storage blocked in modprobe"
    else
        report "RH8.usb" "WARN" "usb-storage disabled" "Not loaded but no block rule"
    fi

    section "RHEL8: protocol kernel modules"
    for mod in dccp sctp rds tipc; do
        if module_loaded "$mod"; then
            report "RH8.proto.${mod}" "FAIL" "Disable protocol: $mod" "Module loaded"
        elif module_disabled "$mod" || module_blacklisted "$mod"; then
            report "RH8.proto.${mod}" "PASS" "Disable protocol: $mod"
        else
            report "RH8.proto.${mod}" "WARN" "Disable protocol: $mod"
        fi
    done
}

# =============================================================================
#   SUMMARY / REPORT
# =============================================================================

print_summary() {
    section "SUMMARY"
    local total=$((PASS+FAIL+WARN+SKIP))
    printf "  Target       : RHEL %s\n" "$RHEL_VERSION"
    printf "  Host         : %s\n" "$(hostname 2>/dev/null)"
    printf "  Total checks : %d\n" "$total"
    printf "  %sPASS%s         : %d\n" "$C_GRN" "$C_RST" "$PASS"
    printf "  %sFAIL%s         : %d\n" "$C_RED" "$C_RST" "$FAIL"
    printf "  %sWARN%s         : %d\n" "$C_YEL" "$C_RST" "$WARN"
    printf "  %sSKIP%s         : %d\n" "$C_BLU" "$C_RST" "$SKIP"
    if [ "$total" -gt 0 ]; then
        local denom=$(( total - SKIP ))
        [ "$denom" -lt 1 ] && denom=1
        printf "  Score        : %d%% passed (of non-skipped)\n" \
            $(( PASS * 100 / denom ))
    fi
}

write_report() {
    local out="$1"
    {
        echo "id,status,description,detail"
        # Guard against empty array under set -u (bash < 4.4)
        if [ "${#RESULTS[@]}" -gt 0 ]; then
            local r
            for r in "${RESULTS[@]}"; do
                echo "$r"
            done
        fi
    } > "$out"
    echo
    echo "Report written to: $out"
}

# =============================================================================
#   MAIN
# =============================================================================

preflight

printf "%sCIS RHEL %s Benchmark Audit — %s%s\n" \
    "$C_BLU" "$RHEL_VERSION" "$(hostname 2>/dev/null)" "$C_RST"
printf "Run at: %s\n" "$(date -Is 2>/dev/null || date)"

check_filesystem_modules
check_separate_partitions
check_mount_options
check_sticky_bit_world_writable_dirs
check_aide
check_bootloader_perms
check_core_dumps
check_aslr
check_gpg_and_repos
check_sudo_installed
check_unused_services
check_unused_clients
check_time_sync
check_xwindows
check_network_sysctl
check_ssh_config
check_password_aging
check_inactive_lockout
check_default_umask
check_root_uid
check_world_writable_files
check_unowned_files
check_passwd_shadow_perms
check_passwd_shadow_consistency
check_home_dirs
check_user_dot_files
check_banners
check_selinux
check_auditd_common
check_auditd_rules
check_rsyslog
check_cron_perms_and_acl
check_securetty_su
check_suid_sgid_rpm_integrity

case "$RHEL_VERSION" in
    6) run_rhel6_specific ;;
    7) check_password_quality; run_rhel7_specific ;;
    8) check_password_quality; run_rhel8_specific ;;
esac

print_summary
[ -n "$OUTFILE" ] && write_report "$OUTFILE"

[ "$FAIL" -eq 0 ]
