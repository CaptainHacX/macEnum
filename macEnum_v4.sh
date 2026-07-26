#!/bin/bash
#
# macEnum.sh - Comprehensive macOS Local Enumeration & Privilege Escalation Auditor
# ---------------------------------------------------------------------------------
# Inspired by LinEnum.sh (@rebootuser) and linpeas.sh (carlospolop / PEASS-ng),
# but written from scratch for macOS internals. No Linux-only assumptions
# (/proc, /etc/shadow, systemctl, getcap, dpkg/yum) are used.
#
# Purpose : Security assessment, red teaming, pentesting and auditing of macOS.
# Targets : macOS Intel + Apple Silicon (M1/M2/M3/M4)
#           Ventura (13) / Sonoma (14) / Sequoia (15) and older releases.
# Deps    : Pure system tools. Optional tools (brew/mas/python/etc.) are probed
#           defensively and skipped when absent. bash 3.2 compatible.
#
# SAFETY  : 100% READ-ONLY. This script never modifies, deletes, installs, or
#           disables anything. It only uses read/get/list/show subcommands.
#           It is an auditing/enumeration tool, NOT an exploitation or attack
#           tool. Use only on systems you own or are explicitly authorized to
#           assess.
#
# Author    : CaptainHacX
# Copyright : (c) 2026 CaptainHacX. All rights reserved.
# License   : For authorized security testing only. Unauthorized copying,
#             modification, distribution, or removal of this attribution is
#             prohibited. Use only on systems you own or are explicitly
#             permitted to assess.
# ---------------------------------------------------------------------------------
#  This script and its original logic are the intellectual property of
#  CaptainHacX. If you redistribute it, keep this notice intact.
#
# Usage   : ./macEnum.sh [-t] [-q] [-F] [-T] [-o report.txt]
#                        [-j out.json] [-H out.html] [-s sections] [-x sections] [-h]
# ---------------------------------------------------------------------------------

VERSION="4.0"
AUTHOR="CaptainHacX"
COPYRIGHT="2026 ${AUTHOR}. All rights reserved."

###############################################################################
# Globals / options
###############################################################################
THOROUGH=0
QUIET=0
REPORT=""
FINDINGS_ONLY=0
SHOW_TIMING=0
JSON_OUT=""
HTML_OUT=""
ONLY_SECTIONS=""
SKIP_SECTIONS=""

CURRENT_USER="$(id -un 2>/dev/null)"
CURRENT_UID="$(id -u 2>/dev/null)"
HOME_DIR="${HOME:-$(eval echo ~"$CURRENT_USER")}"
SELF_PATH="$0"

# ---- Secure temp-file creation & cleanup -----------------------------------
# Every temp file this script creates is recorded in a registry FILE (not a
# shell variable): mk_secure_tmp() is normally invoked via command
# substitution ("$(mk_secure_tmp ...)"), which runs in a subshell, so a
# variable update there would never be visible back in the parent shell -
# a file write is. Some of these temp files can briefly hold decoded secrets
# (Wi-Fi/kcpassword/VNC) or the full findings list, so cleanup must also run
# on interrupt/termination, not just normal exit.
TMP_REGISTRY="$(mktemp /tmp/.macenum_tmpreg.XXXXXX 2>/dev/null)"
if [ -z "$TMP_REGISTRY" ]; then
    TMP_REGISTRY="/tmp/.macenum_tmpreg.$$.${RANDOM}${RANDOM}"
    : > "$TMP_REGISTRY" 2>/dev/null
fi
chmod 600 "$TMP_REGISTRY" 2>/dev/null

mk_secure_tmp() {
    # $1 = filename prefix. Always returns a path that is mode 0600, even on
    # the (rare) mktemp-failure fallback path, and never relies on umask.
    local prefix="$1" f
    f="$(mktemp "/tmp/${prefix}.XXXXXX" 2>/dev/null)"
    if [ -z "$f" ]; then
        f="/tmp/${prefix}.$$.${RANDOM}${RANDOM}"
        : > "$f" 2>/dev/null
    fi
    chmod 600 "$f" 2>/dev/null
    printf '%s\n' "$f" >> "$TMP_REGISTRY" 2>/dev/null
    echo "$f"
}
_macenum_cleanup() {
    if [ -f "$TMP_REGISTRY" ]; then
        while IFS= read -r _t; do [ -n "$_t" ] && rm -f "$_t" 2>/dev/null; done < "$TMP_REGISTRY"
        rm -f "$TMP_REGISTRY" 2>/dev/null
    fi
}
trap _macenum_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Temp files for finding aggregation (TSV: severity \t technique \t message)
FINDINGS_FILE="$(mk_secure_tmp macenum_find)"

usage() {
    cat <<EOF
================================================================================
 macEnum.sh v${VERSION} - macOS Enumeration & Privilege Escalation Auditor
 (c) ${COPYRIGHT}  |  Author: ${AUTHOR}
================================================================================
 A 100% READ-ONLY security auditing tool for macOS. It NEVER modifies, deletes,
 installs, disables, or attacks anything - it only inspects and reports.
 Use only on systems you own or are explicitly authorized to assess.

--------------------------------------------------------------------------------
 USAGE
--------------------------------------------------------------------------------
   ./macEnum.sh [options]

 Run with no options for a fast baseline scan. Add -t for a deep scan.

--------------------------------------------------------------------------------
 OPTIONS
--------------------------------------------------------------------------------
   -t        Thorough mode. Enables slower, filesystem-wide searches and the
             deeper checks (secret sweeps, dylib otool scans, Wi-Fi passwords,
             clipboard, keychain item inventory).
   -q        Quiet mode. Disables ANSI colors. Use this when saving to a file
             or piping output elsewhere.
   -F        Findings-only mode. Suppresses informational output and prints
             ONLY the security findings (CRIT / VULN / warnings) + the summary.
   -T        Show how long each section takes (useful with -t).
   -o FILE   Save a full copy of the output to FILE (in addition to screen).
   -j FILE   Export the findings as machine-readable JSON to FILE.
   -H FILE   Export the findings as a styled HTML report to FILE.
   -s LIST   Run ONLY the comma-separated sections in LIST.
   -x LIST   Run everything EXCEPT the comma-separated sections in LIST.
   -h        Show this help and exit.

--------------------------------------------------------------------------------
 SECTION KEYS (for -s and -x)
--------------------------------------------------------------------------------
   system        Host, OS, build, kernel, hardware, security posture
   users         Users, groups, admins, password policy, hashes (root)
   privileges    sudo, SUID/SGID, writable PATH, weak permissions
   privesc       Helper tools, dylib injection, sudo CVEs, PAM, authz DB
   privesc2      Writable root paths (synthetic.conf, sudoers.d, periodic,
                 newsyslog, launchd dirs), ACLs, groups, live-sudo, TCC chains
   cve           macOS LPE/SIP CVE exposure by build, helper & Sparkle review
   launch        LaunchAgents/Daemons, login items, cron/periodic, profiles
   persistence   Login hooks, security plugins, shell-init, plugin bundles
   processes     Running/root/third-party processes, creds in args
   network       Interfaces, ports, connections, DNS, proxy, Wi-Fi
   apps          Installed apps, brew, mas, pip, gem, npm packages
   sensitive     SSH/cloud/app creds, kcpassword, VNC pw, keychain, history
   discovery     Spotlight secret search, GPG, password mgrs, git, DB configs
   secrets       Content scan of files for hardcoded tokens/keys/.env secrets
   browsers      Safari/Chrome/Edge/Brave/Firefox profiles & artifacts
   security      SIP, Gatekeeper, firewall, FileVault, XProtect, TCC, NVRAM
   trust         Custom CA trust, code-signing identities, TCC privacy grants
   defensive     EDR / AV / DLP / MDM detection & coverage analysis
   hardening     Login/screen-lock/update policy, sharing, sshd, exposure, hosts
   permissions   Weak perms on key files, authorized_keys, other-user exposure
   exploit       Lateral movement (Kerberos/SSH), injection surface, env leaks,
                 defense-evasion/tamper indicators, IR triage timeline
   sysrecon      Updates, MDM, mounts, Time Machine, firmware, pf, clipboard
   containers    Docker, Podman, Colima, Kubernetes, VM detection
   devtools      Xcode, language runtimes, compilers, writable dev dirs

--------------------------------------------------------------------------------
 SEVERITY LEVELS (shown inline and in the end SUMMARY)
--------------------------------------------------------------------------------
   [CRIT]   Critical - direct/again-likely privilege escalation or root exec
   [VULN]   High     - serious weakness or exposed credential
   [!]      Medium   - misconfiguration / notable exposure to review
   [low]    Low      - informational risk / verify-in-context
   [+]      Benign informational data (not a finding)
   The SUMMARY prints a risk score and lists every finding grouped by severity.

--------------------------------------------------------------------------------
 EXAMPLES
--------------------------------------------------------------------------------
   ./macEnum.sh                          Quick baseline scan to the screen
   ./macEnum.sh -t                       Full, deep scan (recommended)
   ./macEnum.sh -F                       Show only findings (fast triage)
   ./macEnum.sh -t -o report.txt         Deep scan, also saved to report.txt
   ./macEnum.sh -t -q -o report.txt      Deep scan, no colors, clean text file
   ./macEnum.sh -t -j out.json -H out.html   Deep scan + JSON + HTML reports
   ./macEnum.sh -s secrets,defensive     Only the secret-scan + EDR sections
   ./macEnum.sh -x sensitive,browsers    Everything except those two sections
   ./macEnum.sh -t -F -s hardening,permissions,privesc   Targeted weakness hunt
   sudo ./macEnum.sh -t -o full.txt      Run as root for maximum visibility

--------------------------------------------------------------------------------
 RECOMMENDED WORKFLOW
--------------------------------------------------------------------------------
   1) First pass : ./macEnum.sh -F            (quick - just the findings)
   2) Full audit : sudo ./macEnum.sh -t -o report.txt -H report.html
   3) Review the SUMMARY at the bottom, then read CRIT/VULN findings in report.
   4) Re-run a single area while fixing, e.g.: ./macEnum.sh -s hardening

--------------------------------------------------------------------------------
 NOTES
--------------------------------------------------------------------------------
 * 100% READ-ONLY: the script never changes, disables, or installs anything.
 * Run as a normal user for realistic results; running with sudo/root reveals
   more (password hashes, /etc/kcpassword, firmware password, full sudoers/TCC).
 * Some checks need Full Disk Access (TCC.db, browser DBs, Messages/Notes).
   Grant Terminal/iTerm Full Disk Access in System Settings > Privacy for these.
 * -t (thorough) enables filesystem-wide secret scans and is much slower but
   finds far more. Use it for a real audit; omit it for a quick look.
 * Findings are tagged with MITRE ATT&CK technique IDs for reporting.
================================================================================
EOF
}

while getopts "tqFTo:j:H:s:x:h" opt 2>/dev/null; do
    case "$opt" in
        t) THOROUGH=1 ;;
        q) QUIET=1 ;;
        F) FINDINGS_ONLY=1 ;;
        T) SHOW_TIMING=1 ;;
        o) REPORT="$OPTARG" ;;
        j) JSON_OUT="$OPTARG" ;;
        H) HTML_OUT="$OPTARG" ;;
        s) ONLY_SECTIONS="$OPTARG" ;;
        x) SKIP_SECTIONS="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

###############################################################################
# Colors. Disabled with -q.
###############################################################################
if [ "$QUIET" -eq 1 ]; then
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; BOLD=""; DIM=""; NC=""
else
    RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; BLUE="\033[1;34m"
    CYAN="\033[1;36m"; MAGENTA="\033[1;35m"; BOLD="\033[1m"; DIM="\033[2m"; NC="\033[0m"
fi

###############################################################################
# Output helpers
###############################################################################
# In findings-only mode, suppress all descriptive output (keep only findings).
_suppress() { [ "$FINDINGS_ONLY" -eq 1 ]; }

title() {
    _suppress && return 0
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}${CYAN}$1${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
}

# subtitle "Name" ["T1234"]  -> optional MITRE ATT&CK technique tag
subtitle() {
    _suppress && return 0
    if [ -n "$2" ]; then
        echo -e "\n${YELLOW}══[ $1 ]══${NC} ${DIM}[ATT&CK $2]${NC}"
    else
        echo -e "\n${YELLOW}══[ $1 ]══${NC}"
    fi
}

info() { _suppress && return 0; echo -e "  ${GREEN}[+]${NC} $1"; }
data() { _suppress && return 0; echo -e "      $1"; }
none() { _suppress && return 0; echo -e "      ${DIM}$1${NC}"; }

# Record a finding into the aggregation file (severity, technique, message).
# Uses \037 (unit separator) as the delimiter: it is NOT IFS-whitespace, so an
# empty technique field is preserved on read (a tab would collapse and shift
# the message into the technique column).
FSEP=$(printf '\037')
record_finding() {
    # De-duplicate: some conditions are legitimately checked from more than
    # one section (e.g. SIP state from SECURITY and PRIVESC2); only count
    # and print each exact (severity, technique, message) combination once.
    local line
    line="$(printf '%s\037%s\037%s' "$1" "$2" "$3")"
    grep -qxF "$line" "$FINDINGS_FILE" 2>/dev/null && return 0
    printf '%s\n' "$line" >> "$FINDINGS_FILE" 2>/dev/null
}

# Finding emitters. Each: msg [technique]
crit() {
    local tag=""; [ -n "$2" ] && tag="  ${DIM}[ATT&CK $2]${NC}"
    echo -e "  ${RED}${BOLD}[CRIT]${NC} ${RED}$1${NC}${tag}"
    record_finding "CRITICAL" "${2:-}" "$1"
}
vuln() {
    local tag=""; [ -n "$2" ] && tag="  ${DIM}[ATT&CK $2]${NC}"
    echo -e "  ${RED}[VULN]${NC} ${RED}$1${NC}${tag}"
    record_finding "HIGH" "${2:-}" "$1"
}
warn() {
    local tag=""; [ -n "$2" ] && tag="  ${DIM}[ATT&CK $2]${NC}"
    echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$1${NC}${tag}"
    record_finding "MEDIUM" "${2:-}" "$1"
}
lowf() {
    local tag=""; [ -n "$2" ] && tag="  ${DIM}[ATT&CK $2]${NC}"
    _suppress || echo -e "  ${CYAN}[low]${NC} $1${tag}"
    record_finding "LOW" "${2:-}" "$1"
}

# Run a command, indent its output (suppressed in findings-only mode).
run() { _suppress && return 0; eval "$1" 2>/dev/null | sed 's/^/      /'; }

have() { command -v "$1" >/dev/null 2>&1; }

# Join stdin lines with ", " (portable - avoids BSD paste's per-character
# cycling behavior when given a multi-character -d delimiter).
join_lines() {
    awk '{ if (NR>1) printf ", "; printf "%s", $0 } END { if (NR>0) print "" }'
}

# Mask a secret-ish string: keep first 4 + last 4 chars.
mask() {
    local s="$1" n=${#1}
    if [ "$n" -le 10 ]; then echo "********"; else echo "${s:0:4}...${s: -4}"; fi
}

# Version key for comparisons: "1.9.13p2" -> 1009013002 (numeric, bash 3.2 safe)
ver_key() {
    local v="$1" maj min mic pat rest
    pat=0
    case "$v" in *p*) pat="${v##*p}"; v="${v%%p*}";; esac
    maj="${v%%.*}"; rest="${v#*.}"
    if [ "$rest" = "$v" ]; then min=0; mic=0
    else
        min="${rest%%.*}"; mic="${rest#*.}"
        [ "$mic" = "$rest" ] && mic=0
    fi
    # strip non-digits
    maj=$(echo "$maj" | tr -cd '0-9'); min=$(echo "$min" | tr -cd '0-9')
    mic=$(echo "$mic" | tr -cd '0-9'); pat=$(echo "$pat" | tr -cd '0-9')
    printf '%d%03d%03d%03d' "${maj:-0}" "${min:-0}" "${mic:-0}" "${pat:-0}" 2>/dev/null
}

###############################################################################
# Banner
###############################################################################
banner() {
    echo -e "${CYAN}"
    cat <<'EOF'
   ███╗   ███╗ █████╗  ██████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
   ████╗ ████║██╔══██╗██╔════╝██╔════╝████╗  ██║██║   ██║████╗ ████║
   ██╔████╔██║███████║██║     █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
   ██║╚██╔╝██║██╔══██║██║     ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
   ██║ ╚═╝ ██║██║  ██║╚██████╗███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
EOF
    echo -e "${NC}"
    echo -e "   ${BOLD}macOS Enumeration & Privilege Escalation Auditor v${VERSION}${NC}"
    echo -e "   ${DIM}Native macOS read-only audit toolkit${NC}"
    echo -e "   ${MAGENTA}© ${COPYRIGHT}${NC}"
    echo -e "   ${DIM}Author: ${AUTHOR}  |  For authorized security testing only${NC}"
    echo -e "   ${DIM}Mode: $( [ "$THOROUGH" -eq 1 ] && echo 'THOROUGH' || echo 'quick' )$( [ "$FINDINGS_ONLY" -eq 1 ] && echo ' / findings-only')  |  User: ${CURRENT_USER} (uid=${CURRENT_UID})  |  $(date)${NC}"
    [ "$THOROUGH" -eq 0 ] && echo -e "   ${DIM}Tip: run with -t for deeper (slower) filesystem-wide checks${NC}"
    self_integrity
}

# ---- Feature #39: self-integrity / tamper awareness -------------------------
self_integrity() {
    local h=""
    if have shasum; then h="$(shasum -a 256 "$SELF_PATH" 2>/dev/null | awk '{print $1}')"; fi
    [ -n "$h" ] && echo -e "   ${DIM}SHA-256(self): ${h}${NC}"
    if ! grep -q "CaptainHacX" "$SELF_PATH" 2>/dev/null; then
        echo -e "   ${RED}[!] WARNING: author/copyright attribution appears to have been removed from this script.${NC}"
    fi
}

###############################################################################
# 1. SYSTEM INFORMATION
###############################################################################
enum_system() {
    title "SYSTEM INFORMATION"

    subtitle "Host identity" "T1082"
    info "ComputerName : $(scutil --get ComputerName 2>/dev/null || hostname)"
    info "LocalHostName: $(scutil --get LocalHostName 2>/dev/null)"
    info "Hostname     : $(hostname 2>/dev/null)"

    subtitle "OS / build / kernel" "T1082"
    info "Product      : $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
    info "Build        : $(sw_vers -buildVersion 2>/dev/null)"
    info "Kernel       : $(uname -srm 2>/dev/null)"
    info "Architecture : $(uname -m 2>/dev/null)  ($(sysctl -n hw.optional.arm64 2>/dev/null | grep -q 1 && echo 'Apple Silicon' || echo 'Intel'))"
    info "Uptime       :$(uptime 2>/dev/null | sed 's/^ *//' | cut -d, -f1)"

    subtitle "Hardware" "T1082"
    run "system_profiler SPHardwareDataType 2>/dev/null | grep -E 'Model Name|Model Identifier|Chip|Processor|Total Number of Cores|Memory|Serial Number|Hardware UUID|Activation Lock'"

    subtitle "Core security posture (details in SECURITY section)"
    info "SIP          : $(csrutil status 2>/dev/null | sed 's/.*status: //')"
    info "Gatekeeper   : $(spctl --status 2>/dev/null)"
    info "FileVault    : $(fdesetup status 2>/dev/null | head -1)"
}

###############################################################################
# 2. USERS AND GROUPS
###############################################################################
enum_users() {
    title "USERS AND GROUPS"

    subtitle "Current identity" "T1033"
    run "id"
    info "Logged-in sessions:"
    run "who"
    info "Recent logins:"
    run "last 2>/dev/null | head -15"

    subtitle "All local users (UID >= 500 are interactive)" "T1087.001"
    run "dscl . -list /Users UniqueID 2>/dev/null | awk '\$2 >= 500 {print}' | sort -k2 -n"
    none "(system/service accounts have UID < 500 and are hidden from the login window)"

    subtitle "Admin group members (privilege escalation targets)" "T1069.001"
    admins="$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')"
    info "admin: $admins"
    is_admin=0
    for u in $admins; do
        [ "$u" = "$CURRENT_USER" ] && is_admin=1
    done
    # dscl's GroupMembership only reflects SECONDARY group membership; a user
    # whose PRIMARY gid is 80 (admin) would be missed above. 'id -Gn' resolves
    # both, so cross-check it too to avoid a false negative.
    case " $(id -Gn 2>/dev/null) " in *" admin "*) is_admin=1 ;; esac
    [ "$is_admin" -eq 1 ] && vuln "Current user '$CURRENT_USER' is a member of the 'admin' group (can sudo / escalate)." "T1078.003"

    subtitle "Login shells per user"
    run "dscl . -list /Users UserShell 2>/dev/null | grep -vE '/usr/bin/false|/dev/null' | sort"

    subtitle "Root account status"
    rootshell="$(dscl . -read /Users/root UserShell 2>/dev/null | awk '{print $2}')"
    if dscl . -read /Users/root Password 2>/dev/null | grep -q '\*'; then
        info "root login is disabled (password '*')."
    else
        warn "root account may be enabled - inspect 'dscl . -read /Users/root'."
    fi
    info "root shell: ${rootshell:-unknown}"

    subtitle "Password policy"
    run "pwpolicy -getaccountpolicies 2>/dev/null | tail -n +2 | grep -E 'policyContent|minutes|Length|<key>' | head -40"
    none "(empty output usually means no enforced complexity policy)"

    subtitle "Local password hashes (root-only; ShadowHashData)" "T1003"
    if [ "$CURRENT_UID" -eq 0 ]; then
        for udir in /var/db/dslocal/nodes/Default/users/*.plist; do
            [ -r "$udir" ] || continue
            uname="$(basename "$udir" .plist)"
            if defaults read "$udir" ShadowHashData >/dev/null 2>&1; then
                crit "Readable ShadowHashData for user '$uname' (dump via 'defaults read $udir ShadowHashData'; crack with hashcat -m 7100)." "T1003"
            fi
        done
    else
        none "Need root to read /var/db/dslocal/nodes/Default/users/*.plist (ShadowHashData)."
    fi
}

###############################################################################
# 3. PRIVILEGES (sudo, SUID/SGID, weak perms)
###############################################################################
enum_privileges() {
    title "PRIVILEGES & PRIVILEGE ESCALATION (basics)"

    subtitle "Sudo rights (no-password check)" "T1548.003"
    sudo_np="$(sudo -n -l 2>/dev/null)"
    if [ -n "$sudo_np" ]; then
        vuln "Current user can run sudo WITHOUT a password:" "T1548.003"
        echo "$sudo_np" | sed 's/^/        /'
        echo "$sudo_np" | grep -q "NOPASSWD" && crit "NOPASSWD entry present - direct privilege escalation." "T1548.003"
        echo "$sudo_np" | grep -qE "\(ALL.*\)\s*ALL|ALL : ALL" && crit "Effective 'ALL' sudo permission -> root via 'sudo -s'." "T1548.003"
    else
        info "No passwordless sudo (or sudo requires a password / not in sudoers)."
    fi

    subtitle "Sudoers configuration"
    if [ -r /etc/sudoers ]; then
        info "/etc/sudoers (readable):"
        run "grep -vE '^\s*#|^\s*$' /etc/sudoers"
    else
        none "/etc/sudoers not readable as current user."
    fi
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            [ -r "$f" ] || continue
            info "$f:"
            run "grep -vE '^\s*#|^\s*$' '$f'"
        done
    fi

    subtitle "SUID binaries (setuid - run as file owner, often root)" "T1548.001"
    suid="$(find /usr/local /opt /Applications /private/etc -perm -4000 -type f 2>/dev/null; \
            find /usr/bin /bin /sbin /usr/sbin -perm -4000 -type f 2>/dev/null)"
    if [ -n "$suid" ]; then
        echo "$suid" | sort -u | while read -r f; do
            _suppress || ls -l "$f" 2>/dev/null | sed 's/^/        /'
        done
        echo "$suid" | sort -u | grep -vE '^/usr/|^/bin/|^/sbin/|^/System/' | while read -r f; do
            [ -n "$f" ] && vuln "Non-system SUID binary: $f (review for abuse / GTFOBins)." "T1548.001"
        done
        # F7: cross-reference SUID set against GTFOBins shell-escapable binaries
        gtfo='/(bash|sh|zsh|csh|tcsh|ksh|dash|vi|vim|view|less|more|man|awk|sed|perl|python|python3|ruby|lua|tclsh|ed|find|nmap|tar|zip|cpan|gdb|lldb|php|node|expect|env|make|rsync|ssh|scp|openssl|tee|dd|nano|emacs|ftp|lftp)$'
        echo "$suid" | sort -u | grep -E "$gtfo" | while read -r f; do
            [ -n "$f" ] && crit "SUID/SGID binary is shell-escapable via GTFOBins -> privilege escalation: $f" "T1548.001"
        done
    fi

    subtitle "SGID binaries (setgid)" "T1548.001"
    run "find /usr/local /opt /Applications /private/etc -perm -2000 -type f 2>/dev/null | head -40"

    subtitle "Writable files in PATH (binary hijacking)" "T1574.007"
    echo "$PATH" | tr ':' '\n' | while read -r d; do
        [ -d "$d" ] || continue
        if [ -w "$d" ]; then
            vuln "PATH directory is writable: $d (plant/replace a binary executed by other users)." "T1574.007"
        fi
        find "$d" -maxdepth 1 -type f -perm -0002 2>/dev/null | while read -r wf; do
            [ -n "$wf" ] && vuln "World-writable binary in PATH: $wf" "T1574.007"
        done
    done

    subtitle "World-writable files in sensitive dirs"
    run "find /Library/LaunchDaemons /Library/LaunchAgents /Library/StartupItems /usr/local/bin /usr/local/sbin -perm -0002 -type f 2>/dev/null | head -40"

    subtitle "Sticky-bit & writable directories of interest"
    run "ls -ld /tmp /var/tmp /private/tmp /Users/Shared 2>/dev/null"

    subtitle "Files writable by current user under /Library & /usr/local (privesc surface)"
    if [ "$THOROUGH" -eq 1 ]; then
        # NOTE: '-writable' is a GNU find extension; stock/BSD find on macOS
        # does not support it and errors out silently under 2>/dev/null,
        # so writability is tested explicitly per candidate with '[ -w ]'.
        local wf wcount=0
        while IFS= read -r wf; do
            [ -w "$wf" ] || continue
            warn "Writable: $wf"
            wcount=$((wcount+1))
            [ "$wcount" -ge 60 ] && break
        done < <(find /Library /usr/local -type f 2>/dev/null | grep -vE "$HOME_DIR")
    else
        none "(enable -t for a full writable-file sweep of /Library and /usr/local)"
    fi
}

###############################################################################
# 4. ADVANCED PRIVILEGE ESCALATION DETECTORS  (Features #1,2,3,4,6,7,32)
###############################################################################
enum_privesc() {
    title "ADVANCED PRIVILEGE ESCALATION DETECTORS"

    # ---- #1 Privileged Helper Tools (SMJobBless) ----------------------------
    subtitle "Privileged Helper Tools (SMJobBless / XPC root helpers)" "T1543.004"
    if [ -d /Library/PrivilegedHelperTools ]; then
        found=0
        for h in /Library/PrivilegedHelperTools/*; do
            [ -e "$h" ] || continue
            found=1
            info "Helper: $h"
            run "ls -l '$h'"
            run "codesign -dv '$h' 2>&1 | grep -E 'Authority|TeamIdentifier|Identifier=' | head -3"
            if [ -w "$h" ]; then
                crit "Writable privileged helper tool: $h (root code execution via XPC)." "T1543.004"
            fi
            if ! codesign --verify "$h" >/dev/null 2>&1; then
                warn "Helper fails code-signature verification: $h"
            fi
        done
        [ "$found" -eq 0 ] && none "No privileged helper tools installed."
    else
        none "/Library/PrivilegedHelperTools does not exist."
    fi

    # ---- #2 Dylib hijacking / injection surface -----------------------------
    subtitle "Dylib injection surface (disabled library validation)" "T1574.006"
    none "Apps with library validation disabled allow DYLD_INSERT_LIBRARIES code injection."
    appcount=0
    for app in /Applications/*.app; do
        [ -d "$app" ] || continue
        appcount=$((appcount+1))
        [ "$THOROUGH" -eq 0 ] && [ "$appcount" -gt 40 ] && break
        execname="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
        [ -z "$execname" ] && continue
        bin="$app/Contents/MacOS/$execname"
        [ -f "$bin" ] || continue
        ents="$(codesign -d --entitlements - "$bin" 2>/dev/null)"
        if echo "$ents" | grep -q 'disable-library-validation'; then
            vuln "Library Validation disabled: $bin (DYLD_INSERT_LIBRARIES injection possible)." "T1574.006"
        fi
        if echo "$ents" | grep -q 'allow-dyld-environment-variables'; then
            warn "App allows DYLD environment variables: $bin (injection vector)." "T1574.006"
        fi
    done
    if [ "$THOROUGH" -eq 1 ]; then
        subtitle "Weak/@rpath dylib dependencies in writable locations (thorough)" "T1574.006"
        for app in /Applications/*.app; do
            [ -d "$app" ] || continue
            execname="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
            bin="$app/Contents/MacOS/$execname"
            [ -f "$bin" ] || continue
            otool -L "$bin" 2>/dev/null | awk '{print $1}' | grep -E '^/usr/local/|^/opt/' | while read -r lib; do
                d="$(dirname "$lib")"
                [ -d "$d" ] && [ -w "$d" ] && vuln "App $bin loads $lib from a writable directory ($d)." "T1574.006"
            done
        done
    else
        none "(enable -t to otool-scan app dylib dependencies for writable load paths)"
    fi

    # ---- #3 Sudo version CVE + GTFOBins -------------------------------------
    subtitle "Sudo version & known CVEs" "T1548.003"
    sudover="$(sudo -V 2>/dev/null | awk '/Sudo version/{print $3; exit}')"
    if [ -n "$sudover" ]; then
        info "sudo version: $sudover"
        vk="$(ver_key "$sudover")"
        # Baron Samedit CVE-2021-3156: vulnerable < 1.9.5p2 (and >= 1.8.2). Fixed 1.9.5p2.
        if [ "$vk" -ge "$(ver_key 1.8.2)" ] 2>/dev/null && [ "$vk" -lt "$(ver_key 1.9.5p2)" ] 2>/dev/null; then
            crit "sudo $sudover is in the CVE-2021-3156 (Baron Samedit) heap-overflow range -> local root. VERIFY before exploiting." "T1548.003"
        fi
        # CVE-2023-22809 sudoedit: vulnerable 1.8.0 .. 1.9.12p1
        if [ "$vk" -ge "$(ver_key 1.8.0)" ] 2>/dev/null && [ "$vk" -le "$(ver_key 1.9.12p1)" ] 2>/dev/null; then
            warn "sudo $sudover is in the CVE-2023-22809 (sudoedit -e EDITOR) range; relevant only if you have a sudoedit/-e rule. VERIFY." "T1548.003"
        fi
    else
        none "Could not determine sudo version."
    fi
    # GTFOBins-style abuse mapping for allowed sudo commands
    sudo_np="$(sudo -n -l 2>/dev/null)"
    if [ -n "$sudo_np" ]; then
        gtfo='vi|vim|nano|view|less|more|man|awk|sed|perl|python|python3|ruby|lua|tclsh|ed|ex|find|nmap|tar|zip|gdb|lldb|ssh|scp|rsync|bash|sh|zsh|env|nohup|make|cpan|gem|node|php|openssl|xargs|ftp|expect'
        hits="$(echo "$sudo_np" | grep -oiE "/[^ ]*($gtfo)\$|($gtfo)\$" 2>/dev/null | sort -u)"
        [ -n "$hits" ] && crit "Sudo-allowed binary is shell-escapable (GTFOBins -> root): $(echo "$hits" | tr '\n' ' ')" "T1548.003"
    fi

    # ---- #4 Authorization database rights -----------------------------------
    subtitle "Authorization database rights (admin without password)" "T1548"
    for right in system.privilege.admin system.preferences system.install.software.local; do
        rule="$(security authorizationdb read "$right" 2>/dev/null)"
        [ -z "$rule" ] && continue
        if echo "$rule" | grep -A1 '<key>class</key>' | grep -q '<string>allow</string>'; then
            crit "Authorization right '$right' is set to ALLOW (no auth) - admin actions without a password." "T1548"
        fi
        if echo "$rule" | grep -A1 'authenticate-user' | grep -qi '<false/>'; then
            warn "Authorization right '$right' has authenticate-user=false - weakened." "T1548"
        fi
    done
    none "(rights left at default 'authenticate-admin' are normal)"

    # ---- #6 PAM / sudo_local ------------------------------------------------
    subtitle "PAM configuration (sudo / Touch ID)" "T1556"
    if [ -f /etc/pam.d/sudo ]; then
        run "grep -vE '^\s*#|^\s*$' /etc/pam.d/sudo"
        grep -q 'pam_tid.so' /etc/pam.d/sudo 2>/dev/null && info "Touch ID for sudo (pam_tid.so) is enabled."
        [ -f /etc/pam.d/sudo_local ] && { info "/etc/pam.d/sudo_local present:"; run "grep -vE '^\s*#|^\s*$' /etc/pam.d/sudo_local"; }
    fi
    # writable PAM config or modules = root
    # ('-writable' is GNU-only; stock macOS find lacks it, so test with '[ -w ]'.)
    find /etc/pam.d -type f 2>/dev/null | while read -r pf; do
        [ -n "$pf" ] && [ -w "$pf" ] && crit "Writable PAM config (auth bypass / root): $pf" "T1556"
    done
    for pamdir in /usr/lib/pam /usr/local/lib/pam; do
        [ -d "$pamdir" ] || continue
        find "$pamdir" -type f 2>/dev/null | while read -r pm; do
            [ -n "$pm" ] && [ -w "$pm" ] && crit "Writable PAM module (loaded by sudo/login as root): $pm" "T1556"
        done
    done

    # ---- #7 Writable application bundles ------------------------------------
    subtitle "Writable app bundles owned by root (trojan/privesc)" "T1574"
    for app in /Applications/*.app; do
        [ -d "$app" ] || continue
        owner="$(stat -f '%Su' "$app" 2>/dev/null)"
        execname="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
        bin="$app/Contents/MacOS/$execname"
        [ -f "$bin" ] || continue
        if [ -w "$bin" ] && [ "$owner" = "root" ]; then
            crit "Root-owned app has a writable main binary: $bin (replace to run code as root when launched by root/admin)." "T1574"
        fi
    done
    none "(self-owned writable apps are reported under PROCESSES as tamper/persistence)"

    # ---- #32 Writable-parent / symlink-attack surface -----------------------
    if [ "$THOROUGH" -eq 1 ]; then
        subtitle "Writable parent directories of system binaries (symlink/rename attacks)" "T1574"
        for d in /usr/local/bin /usr/local/sbin /opt/homebrew/bin /opt/homebrew/sbin /Library/Application\ Support; do
            [ -d "$d" ] || continue
            parent="$(dirname "$d")"
            [ -w "$parent" ] && warn "Writable parent dir '$parent' of '$d' (rename/symlink attack surface)." "T1574"
        done
    else
        none "(enable -t for writable-parent/symlink attack-surface analysis)"
    fi

    # ---- F6: risky sudoers Defaults -----------------------------------------
    subtitle "Risky sudoers Defaults" "T1548.003"
    local sf sudread=0 tt
    for sf in /etc/sudoers $(ls /etc/sudoers.d/* 2>/dev/null); do
        [ -r "$sf" ] || continue
        sudread=1
        grep -E '^[[:space:]]*Defaults' "$sf" 2>/dev/null | grep -qE '!requiretty' && warn "sudoers: !requiretty set in $sf." "T1548.003"
        grep -E '^[[:space:]]*Defaults' "$sf" 2>/dev/null | grep -qiE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|BASH_ENV|PYTHONPATH|PERL5LIB)' && crit "sudoers: dangerous env_keep (LD_PRELOAD/DYLD_/BASH_ENV...) in $sf - injection to root." "T1548.003"
        grep -E '^[[:space:]]*Defaults' "$sf" 2>/dev/null | grep -qE 'targetpw|rootpw|runaspw' && lowf "sudoers: alternate password mode (targetpw/rootpw) in $sf." "T1548.003"
        grep -qE '^[[:space:]]*Defaults.*!tty_tickets' "$sf" 2>/dev/null && warn "sudoers: !tty_tickets (sudo session shared across ttys) in $sf." "T1548.003"
        tt="$(grep -oE 'timestamp_timeout=[0-9-]+' "$sf" 2>/dev/null | head -1)"
        [ -n "$tt" ] && warn "sudoers: custom $tt in $sf (credential-cache window)." "T1548.003"
    done
    [ "$sudread" -eq 0 ] && none "Cannot read sudoers (needs root)."

    # ---- F9: writable directories hosting root LaunchDaemon programs --------
    subtitle "Writable dirs hosting root LaunchDaemon programs" "T1543.004"
    local p un prog d fnd9=0
    for p in /Library/LaunchDaemons/*.plist; do
        [ -f "$p" ] || continue
        un="$(/usr/libexec/PlistBuddy -c 'Print :UserName' "$p" 2>/dev/null)"
        [ -n "$un" ] && [ "$un" != "root" ] && continue
        prog="$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null)"
        [ -z "$prog" ] && prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)"
        case "$prog" in /*) ;; *) continue;; esac
        d="$(dirname "$prog")"
        if [ -d "$d" ] && [ -w "$d" ]; then
            crit "Writable directory '$d' hosts a root LaunchDaemon program ($p) - rename/replace for root execution." "T1543.004"
            fnd9=1
        fi
    done
    [ "$fnd9" -eq 0 ] && none "No writable directories host root LaunchDaemon programs."

    # ---- F21: applications failing code-signature verification --------------
    # Thorough-only: codesigning every app is slow; keep the quick scan fast.
    subtitle "Applications failing code-signature verification" "T1565.001"
    if [ "$THOROUGH" -eq 1 ]; then
        local app badn=0
        for app in /Applications/*.app "$HOME_DIR"/Applications/*.app; do
            [ -d "$app" ] || continue
            codesign --verify --no-strict "$app" >/dev/null 2>&1 || {
                badn=$((badn+1))
                warn "App fails code-signature verification (unsigned/modified/tampered): $app" "T1565.001"
            }
        done
        [ "$badn" -eq 0 ] && none "All applications passed code-signature verification."
    else
        none "(enable -t to verify code signatures of all installed applications)"
    fi
}

###############################################################################
# 5. LAUNCH SERVICES (persistence basics - existing)
###############################################################################
enum_launch() {
    title "LAUNCH SERVICES, DAEMONS & SCHEDULED TASKS"

    local third_party_dirs=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "$HOME_DIR/Library/LaunchAgents"
    )
    local system_dirs=(
        "/System/Library/LaunchDaemons"
        "/System/Library/LaunchAgents"
    )

    scan_launch_targets() {
        find "$1" -maxdepth 1 -name '*.plist' 2>/dev/null | while read -r p; do
            if [ -w "$p" ]; then
                owner="$(stat -f '%Su' "$p" 2>/dev/null)"
                crit "Writable launchd plist: $p (owner=$owner). Hijack to run code as that principal." "T1543.001"
            fi
            prog="$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null)"
            [ -z "$prog" ] && prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)"
            if [ -n "$prog" ] && [ -e "$prog" ] && [ -w "$prog" ]; then
                crit "Launchd target is writable: $prog (referenced by $p)." "T1543.001"
            fi
        done
    }

    for d in "${third_party_dirs[@]}"; do
        [ -d "$d" ] || continue
        subtitle "$d" "T1543.001"
        run "ls -la '$d' 2>/dev/null | grep -vE '^total|^d'"
        scan_launch_targets "$d"
    done

    for d in "${system_dirs[@]}"; do
        [ -d "$d" ] || continue
        subtitle "$d  (Apple/SIP - $(ls "$d" 2>/dev/null | wc -l | tr -d ' ') items, scanning for writable targets only)"
        scan_launch_targets "$d"
    done

    subtitle "Loaded launchd jobs (root domain)"
    run "launchctl list 2>/dev/null | awk 'NR==1 || \$1 != \"-\"' | head -40"

    subtitle "StartupItems (legacy persistence)" "T1037"
    if [ -d /Library/StartupItems ] || [ -d /System/Library/StartupItems ]; then
        run "ls -la /Library/StartupItems /System/Library/StartupItems 2>/dev/null"
    else
        none "No StartupItems directories present (deprecated mechanism)."
    fi

    subtitle "Login Items (per-user autostart)" "T1547.015"
    run "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null | tr ',' '\n'"
    run "ls -la '$HOME_DIR/Library/Application Support/com.apple.backgroundtaskmanagementagent' 2>/dev/null"

    subtitle "Configuration profiles (MDM / config persistence)" "T1484"
    run "profiles list -all 2>/dev/null | head -30"

    subtitle "Periodic & cron scheduled tasks" "T1053.003"
    run "ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null"
    run "ls -la /usr/lib/cron/tabs 2>/dev/null"
    run "crontab -l 2>/dev/null"
    [ -f /etc/crontab ] && run "cat /etc/crontab"
    find /etc/periodic -type f 2>/dev/null | while read -r pf; do
        [ -n "$pf" ] && [ -w "$pf" ] && crit "Writable periodic script (runs as root): $pf" "T1053.003"
    done

    subtitle "emond rules (legacy event monitor persistence)" "T1546"
    run "ls -la /etc/emond.d/rules 2>/dev/null /private/var/db/emondClients 2>/dev/null"
}

###############################################################################
# 6. EXTENDED PERSISTENCE DETECTORS (Features #8,9,10,11,12,13)
###############################################################################
enum_persistence() {
    title "EXTENDED PERSISTENCE VECTORS"

    # ---- #8 Login / Logout hooks --------------------------------------------
    subtitle "Login/Logout hooks (run as root at login/logout)" "T1037"
    for plist in /Library/Preferences/com.apple.loginwindow /var/root/Library/Preferences/com.apple.loginwindow; do
        for hook in LoginHook LogoutHook; do
            val="$(defaults read "$plist" "$hook" 2>/dev/null)"
            if [ -n "$val" ]; then
                vuln "$hook configured ($plist): $val" "T1037"
                [ -e "$val" ] && [ -w "$val" ] && crit "$hook script is writable: $val (root code execution)." "T1037"
            fi
        done
    done
    none "(empty = no legacy login/logout hooks set)"

    # ---- #9 Authorization / Security Agent plugins --------------------------
    subtitle "Security Agent & Authorization plugins (loginwindow cred capture)" "T1556"
    # /System/... plugins are Apple-signed & SIP-protected -> list only, never flag.
    # Only the user-writable-domain /Library path is treated as third-party surface.
    sysplug="/System/Library/CoreServices/SecurityAgentPlugins"
    [ -d "$sysplug" ] && { info "$sysplug (Apple/SIP, reference):"; run "ls '$sysplug' 2>/dev/null | head -20"; }
    d="/Library/Security/SecurityAgentPlugins"
    if [ -d "$d" ]; then
        run "ls -la '$d' 2>/dev/null"
        find "$d" -maxdepth 1 -mindepth 1 2>/dev/null | while read -r p; do
            [ -n "$p" ] || continue
            # Confirm it is genuinely non-Apple before flagging
            if codesign -dv "$p" 2>&1 | grep -qi 'Authority=Apple'; then
                data "Apple-signed plugin: $p"
            else
                warn "Third-party security/authorization plugin: $p (can capture login credentials)." "T1556"
            fi
            [ -w "$p" ] && crit "Writable security/authorization plugin: $p" "T1556"
        done
    else
        none "No /Library/Security/SecurityAgentPlugins (no third-party login plugins)."
    fi

    # ---- #10 Shell init & PATH injection ------------------------------------
    subtitle "Shell init files (persistence / env injection)" "T1546.004"
    for f in "$HOME_DIR/.zshrc" "$HOME_DIR/.zprofile" "$HOME_DIR/.zshenv" "$HOME_DIR/.zlogin" \
             "$HOME_DIR/.bash_profile" "$HOME_DIR/.bashrc" "$HOME_DIR/.profile" \
             /etc/zshrc /etc/zprofile /etc/zshenv /etc/profile /etc/bashrc; do
        [ -f "$f" ] || continue
        data "present: $f"
        # System-wide files writable by a non-root user = persistence/privesc
        case "$f" in
            /etc/*) [ -w "$f" ] && [ "$CURRENT_UID" -ne 0 ] && crit "System shell init writable by current user: $f" "T1546.004" ;;
        esac
    done
    subtitle "PATH definition files" "T1574.007"
    run "cat /etc/paths 2>/dev/null"
    run "ls /etc/paths.d 2>/dev/null"
    for f in /etc/paths /etc/paths.d/* /etc/manpaths; do
        [ -f "$f" ] && [ -w "$f" ] && [ "$CURRENT_UID" -ne 0 ] && crit "Writable PATH file: $f (inject a directory to hijack binaries)." "T1574.007"
    done

    # ---- #11 Loadable system plugin bundles ---------------------------------
    subtitle "Loadable plugin bundles (Spotlight / QuickLook / ScreenSaver / Audio)" "T1546"
    for d in /Library/Spotlight "$HOME_DIR/Library/Spotlight" \
             /Library/QuickLook "$HOME_DIR/Library/QuickLook" \
             "/Library/Screen Savers" "$HOME_DIR/Library/Screen Savers" \
             "/Library/Audio/Plug-Ins/HAL" /Library/Contextual\ Menu\ Items; do
        [ -d "$d" ] || continue
        ents="$(ls "$d" 2>/dev/null | grep -viE '^$')"
        [ -z "$ents" ] && continue
        info "$d:"
        echo "$ents" | while read -r e; do data "- $e"; done
        find "$d" -maxdepth 1 -mindepth 1 2>/dev/null | while read -r p; do
            [ -n "$p" ] && [ -w "$p" ] && crit "Writable plugin bundle (auto-loaded code execution): $p" "T1546"
        done
    done

    # ---- #12 at / atrun jobs -------------------------------------------------
    subtitle "at / atrun scheduled jobs" "T1053.001"
    run "ls -la /usr/lib/cron/jobs /var/at/jobs 2>/dev/null"
    run "atq 2>/dev/null"
    none "(the SUID 'at' family also appears under PRIVILEGES)"

    # ---- #13 Configuration profile payload parser ---------------------------
    subtitle "Configuration profile payloads of interest" "T1484"
    prof="$(profiles show 2>/dev/null || profiles -P 2>/dev/null)"
    if [ -n "$prof" ]; then
        echo "$prof" | grep -iE 'PayloadType|PayloadIdentifier' | grep -iE 'mcx|syspolicy|certificate|proxy|webcontent|vpn|com.apple.security' | head -20 | while read -r line; do
            data "$line"
        done
        echo "$prof" | grep -qi 'com.apple.syspolicy.kernel-extension-policy' && warn "A profile manages kernel-extension policy (could allow third-party kexts)." "T1484"
        echo "$prof" | grep -qi 'certificate' && warn "A profile installs certificate payload(s) - check for rogue/root CAs." "T1484"
    else
        none "No readable configuration profiles (full payloads usually require root)."
    fi

    # ---- F8: unsigned / invalid-signature launchd targets -------------------
    # Thorough-only: codesign-verifying every launchd target is slow.
    subtitle "Unsigned or invalid-signature launchd targets" "T1543.001"
    if [ "$THOROUGH" -eq 1 ]; then
        local lf prog ft bad8=0
        for lf in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist "$HOME_DIR"/Library/LaunchAgents/*.plist; do
            [ -f "$lf" ] || continue
            prog="$(/usr/libexec/PlistBuddy -c 'Print :Program' "$lf" 2>/dev/null)"
            [ -z "$prog" ] && prog="$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$lf" 2>/dev/null)"
            [ -n "$prog" ] && [ -f "$prog" ] || continue
            ft="$(file "$prog" 2>/dev/null)"
            echo "$ft" | grep -q 'Mach-O' || continue   # scripts can't be codesigned; only verify Mach-O
            if ! codesign --verify "$prog" >/dev/null 2>&1; then
                warn "Launchd target binary is unsigned/invalid: $prog (referenced by $lf)." "T1543.001"
                bad8=1
            fi
        done
        [ "$bad8" -eq 0 ] && none "All Mach-O launchd target binaries pass signature verification."
    else
        none "(enable -t to verify signatures of launchd target binaries)"
    fi

    # ---- F20: recently-modified persistence items ---------------------------
    subtitle "Recently modified persistence items (last 7 days)" "T1543"
    local recent
    recent="$(find /Library/LaunchDaemons /Library/LaunchAgents "$HOME_DIR/Library/LaunchAgents" /etc/periodic /usr/lib/cron/tabs -type f -mtime -7 2>/dev/null | head -30)"
    if [ -n "$recent" ]; then
        printf '%s\n' "$recent" | while IFS= read -r rf; do
            [ -n "$rf" ] && lowf "Recently modified persistence item (verify it is expected): $rf" "T1543"
        done
    else
        none "No launchd/cron/periodic items modified in the last 7 days."
    fi
}

###############################################################################
# 7. PROCESSES
###############################################################################
enum_processes() {
    title "PROCESSES"

    subtitle "Top processes by CPU"
    run "ps -arcwwwxo 'pid,ppid,user,%cpu,%mem,start,command' 2>/dev/null | head -20"

    subtitle "Root-owned processes (interesting attack surface)"
    run "ps -axo user,pid,ppid,command 2>/dev/null | awk '\$1==\"root\"' | head -40"

    subtitle "Interesting / third-party processes (non-Apple binaries)" "T1574"
    ps -axo user=,comm= 2>/dev/null | sort -u | \
        grep -vE ' /System/| /usr/(lib|libexec|sbin)/| /sbin/| \(| -' | head -60 | while read -r puser p; do
        case "$p" in /System/*|/usr/lib*|/usr/libexec*|/usr/sbin*|/sbin*|""|-*) continue;; esac
        [ -e "$p" ] || { data "$p"; continue; }
        if [ -w "$p" ]; then
            if [ "$puser" != "$CURRENT_USER" ]; then
                vuln "Writable binary running as '$puser' (privesc): $p" "T1574"
            else
                warn "Writable self-owned running binary (tamper/persistence): $p" "T1574"
            fi
        else
            data "[$puser] $p"
        fi
    done

    subtitle "Processes referencing credentials/keys in arguments" "T1552.001"
    run "ps -axww 2>/dev/null \
         | grep -iE 'password=|passwd=|token=|secret=|api[_-]?key|-p ' \
         | grep -ivE 'grep|macEnum|shell-snapshot|/bin/zsh -c|sed -n' \
         | head -15"
    creds_in_args="$(ps -axww 2>/dev/null | grep -iE 'password=|api[_-]?key=|secret=|token=' | grep -ivE 'grep|macEnum|shell-snapshot' | head -1)"
    [ -n "$creds_in_args" ] && vuln "Credential material exposed in a process command line (visible to any local user via 'ps')." "T1552.001"
}

###############################################################################
# 8. NETWORK
###############################################################################
enum_network() {
    title "NETWORK"

    subtitle "Interfaces & IP addresses" "T1016"
    run "ifconfig 2>/dev/null | grep -E '^[a-z]|inet ' | grep -vE '127.0.0.1|::1'"

    subtitle "Network services (ordered)"
    run "networksetup -listallnetworkservices 2>/dev/null"

    subtitle "Routing table (IPv4 default + gateways)"
    run "netstat -rn 2>/dev/null | grep -E 'Destination|default|^[0-9]' | head -20"

    subtitle "ARP cache (neighbouring hosts)" "T1016"
    run "arp -an 2>/dev/null | head -20"

    subtitle "Listening ports & owning processes" "T1049"
    if have lsof; then
        run "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==1 || !seen[\$1\$9]++'"
        run "lsof -nP -iUDP 2>/dev/null | head -20"
    else
        run "netstat -anv -p tcp 2>/dev/null | grep LISTEN | head -25"
    fi

    subtitle "Established connections" "T1049"
    if have lsof; then
        run "lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | head -25"
    else
        run "netstat -anv -p tcp 2>/dev/null | grep ESTABLISHED | head -25"
    fi

    subtitle "DNS configuration"
    run "scutil --dns 2>/dev/null | grep -E 'nameserver|search domain' | sort -u | head -15"
    [ -f /etc/resolv.conf ] && run "grep -v '^#' /etc/resolv.conf"

    subtitle "Proxy configuration"
    run "scutil --proxy 2>/dev/null"
    run "env | grep -iE 'http_proxy|https_proxy|all_proxy|no_proxy'"

    subtitle "/etc/hosts (custom entries)"
    run "grep -vE '^\s*#|^\s*$' /etc/hosts 2>/dev/null"

    subtitle "Wi-Fi / known networks"
    run "networksetup -listpreferredwirelessnetworks en0 2>/dev/null | head -15"

    # ---- R17: Directory services / auth backends ----------------------------
    subtitle "Directory services / authentication backends" "T1087.002"
    run "dscl localhost -list / 2>/dev/null | grep -vE '^Contact$|^Search$|^$'"
    run "dscl /Search -read / CSPSearchPath 2>/dev/null"
    ad="$(dsconfigad -show 2>/dev/null)"
    if [ -n "$ad" ]; then
        info "Bound to Active Directory:"
        echo "$ad" | sed 's/^/        /'
    else
        none "Not bound to Active Directory (local directory only)."
    fi

    # ---- R18: File shares exported by this host -----------------------------
    subtitle "File shares exported by this host" "T1135"
    shares="$(sharing -l 2>/dev/null)"
    if [ -n "$shares" ]; then
        echo "$shares" | sed 's/^/      /' | head -40
    else
        none "No AFP/SMB share points configured (sharing -l empty)."
    fi
    if [ -f /etc/exports ]; then
        exp="$(grep -vE '^\s*#|^\s*$' /etc/exports 2>/dev/null)"
        if [ -n "$exp" ]; then
            warn "NFS exports are configured (/etc/exports):" "T1135"
            echo "$exp" | sed 's/^/        /'
        fi
    fi

    # ---- R22: VPN connections & network locations ---------------------------
    subtitle "VPN connections & network locations" "T1016"
    run "scutil --nc list 2>/dev/null"
    run "networksetup -listlocations 2>/dev/null"
    # Third-party VPN client configs / profiles (read-only listing)
    for vd in "$HOME_DIR/Library/Application Support/Tunnelblick/Configurations" \
              "/Library/Application Support/Tunnelblick" \
              "/opt/homebrew/etc/wireguard" "/usr/local/etc/wireguard" "/etc/wireguard"; do
        [ -e "$vd" ] && info "VPN config location present: $vd"
    done
    # OpenVPN/WireGuard profiles in home (config files may embed keys)
    find "$HOME_DIR" -maxdepth 4 \( -name '*.ovpn' -o -name '*.wgconf' -o -name 'wg0.conf' \) 2>/dev/null | head -15 | while read -r vc; do
        [ -z "$vc" ] && continue
        if grep -qE 'BEGIN .*PRIVATE KEY|^\[Interface\]|PrivateKey' "$vc" 2>/dev/null; then
            warn "VPN profile with embedded key material: $vc" "T1552.001"
        else
            data "VPN profile: $vc"
        fi
    done
}

###############################################################################
# 9. APPLICATIONS & PACKAGES
###############################################################################
enum_applications() {
    title "INSTALLED APPLICATIONS & PACKAGES"

    subtitle "/Applications (top level)"
    run "ls /Applications 2>/dev/null | head -60"

    subtitle "Installed packages (pkgutil receipts)"
    run "pkgutil --pkgs 2>/dev/null | grep -vi '^com.apple' | head -40"

    if have brew; then
        subtitle "Homebrew formulae"
        run "brew list --formula 2>/dev/null | head -60"
        subtitle "Homebrew casks"
        run "brew list --cask 2>/dev/null | head -40"
        bp="$(brew --prefix 2>/dev/null)"
        [ -n "$bp" ] && [ -w "$bp" ] && warn "Homebrew prefix $bp is user-writable (formula binaries can be tampered with)." "T1574"
    else
        none "Homebrew not installed."
    fi

    if have mas; then
        subtitle "Mac App Store apps (mas)"
        run "mas list 2>/dev/null | head -40"
    fi
    if have pip3 || have pip; then
        subtitle "Python packages (pip)"
        run "{ pip3 list 2>/dev/null || pip list 2>/dev/null; } | head -40"
    fi
    if have gem; then
        subtitle "Ruby gems"
        run "gem list 2>/dev/null | head -40"
    fi
    if have npm; then
        subtitle "Global Node packages"
        run "npm list -g --depth=0 2>/dev/null | head -40"
    fi
}

###############################################################################
# 10. SENSITIVE INFORMATION / CREDENTIALS  (+ Features #5,14,15,16,17,18,19,20)
###############################################################################
enum_sensitive() {
    title "SENSITIVE INFORMATION & CREDENTIALS"

    subtitle "SSH keys & config" "T1552.004"
    if [ -d "$HOME_DIR/.ssh" ]; then
        run "ls -la '$HOME_DIR/.ssh' 2>/dev/null"
        for k in "$HOME_DIR"/.ssh/id_* "$HOME_DIR"/.ssh/*.pem; do
            [ -f "$k" ] || continue
            case "$k" in *.pub) continue;; esac
            if grep -lq "PRIVATE KEY" "$k" 2>/dev/null; then
                if grep -q "ENCRYPTED" "$k" 2>/dev/null; then
                    info "Private key (passphrase-protected): $k"
                else
                    vuln "UNENCRYPTED private SSH key: $k" "T1552.004"
                fi
            fi
        done
        [ -f "$HOME_DIR/.ssh/config" ] && run "grep -iE 'Host|IdentityFile|User|ProxyJump' '$HOME_DIR/.ssh/config'"
        [ -f "$HOME_DIR/.ssh/known_hosts" ] && info "known_hosts present ($(wc -l < "$HOME_DIR/.ssh/known_hosts" 2>/dev/null | tr -d ' ') entries) - lateral movement targets."
    else
        none "No ~/.ssh directory."
    fi

    # ---- #5 kcpassword (auto-login plaintext password) ----------------------
    subtitle "Auto-login password (/etc/kcpassword)" "T1555"
    if [ -r /etc/kcpassword ]; then
        decoded="$(perl -e '
            my @key=(0x7D,0x89,0x52,0x23,0xD2,0xBC,0xDD,0xEA,0xA3,0xB9,0x1F);
            open(F,"<","/etc/kcpassword") or exit;
            binmode F; local $/; my $d=<F>; close F;
            my @b=unpack("C*",$d); my $o="";
            for my $i (0..$#b){ my $k=$key[$i % 11]; last if $b[$i]==$k; $o.=chr($b[$i]^$k); }
            print $o;
        ' 2>/dev/null)"
        if [ -n "$decoded" ]; then
            crit "Auto-login is enabled; recovered plaintext password from /etc/kcpassword: '$decoded'" "T1555"
        else
            warn "/etc/kcpassword is readable (auto-login enabled) but could not be decoded automatically." "T1555"
        fi
    else
        none "/etc/kcpassword not present/readable (auto-login likely disabled, or needs root)."
    fi

    # ---- #14 VNC / ARD password ---------------------------------------------
    subtitle "Screen Sharing / ARD (VNC) password" "T1555"
    vncf="/Library/Preferences/com.apple.VNCSettings.txt"
    if [ -r "$vncf" ]; then
        raw="$(cat "$vncf" 2>/dev/null | tr -d '[:space:]')"
        info "VNC password file present: $vncf"
        data "raw (hex): $raw"
        cand="$(perl -e '
            my $h=$ARGV[0]; my @key=(0x17,0x34,0x51,0x6E,0x8B,0xA8,0xC5,0xE3);
            my @b = map { hex } ($h =~ /(..)/g); my $o="";
            for my $i (0..$#b){ $o.=chr($b[$i]^$key[$i % 8]); }
            $o=~s/[^[:print:]].*$//; print $o;
        ' "$raw" 2>/dev/null)"
        [ -n "$cand" ] && vuln "Candidate VNC/ARD password (XOR-decoded, VERIFY): '$cand'" "T1555"
    else
        none "No VNC password file (or needs root): $vncf"
    fi

    subtitle "Cloud provider credentials" "T1552.001"
    [ -f "$HOME_DIR/.aws/credentials" ]   && vuln "AWS credentials file: $HOME_DIR/.aws/credentials" "T1552.001"
    [ -f "$HOME_DIR/.aws/config" ]        && info "AWS config: $HOME_DIR/.aws/config"
    [ -d "$HOME_DIR/.config/gcloud" ]     && vuln "GCP gcloud config dir: $HOME_DIR/.config/gcloud" "T1552.001"
    [ -d "$HOME_DIR/.azure" ]             && vuln "Azure CLI dir: $HOME_DIR/.azure" "T1552.001"
    [ -f "$HOME_DIR/.kube/config" ]       && vuln "Kubernetes config: $HOME_DIR/.kube/config" "T1552.001"
    [ -f "$HOME_DIR/.docker/config.json" ] && warn "Docker config: $HOME_DIR/.docker/config.json (may hold registry auth)." "T1552.001"

    # ---- #16 Cloud token deep parse -----------------------------------------
    subtitle "Cloud token deep parse (masked)" "T1552.001"
    if [ -r "$HOME_DIR/.aws/credentials" ]; then
        grep -E '^\[|aws_access_key_id' "$HOME_DIR/.aws/credentials" 2>/dev/null | while read -r line; do
            case "$line" in
                \[*\]) data "AWS profile: $line" ;;
                *aws_access_key_id*) key="$(echo "$line" | sed 's/.*=//; s/ //g')"; data "  access_key_id: $(mask "$key")" ;;
            esac
        done
    fi
    [ -f "$HOME_DIR/.config/gcloud/credentials.db" ] && data "GCP credentials.db: $HOME_DIR/.config/gcloud/credentials.db"
    ls "$HOME_DIR"/.config/gcloud/legacy_credentials/*/adc.json 2>/dev/null | while read -r f; do data "GCP ADC: $f"; done
    [ -f "$HOME_DIR/.azure/accessTokens.json" ] && data "Azure tokens: $HOME_DIR/.azure/accessTokens.json"
    if [ -r "$HOME_DIR/.kube/config" ]; then
        grep -E 'server:|name:' "$HOME_DIR/.kube/config" 2>/dev/null | head -10 | while read -r line; do data "kube: $line"; done
    fi

    # ---- #17 App / dev token sweep ------------------------------------------
    subtitle "App & developer token files" "T1552.001"
    [ -f "$HOME_DIR/.netrc" ]            && vuln "~/.netrc present (plaintext FTP/HTTP creds)." "T1552.001"
    [ -f "$HOME_DIR/.git-credentials" ]  && vuln "~/.git-credentials present (plaintext git tokens)." "T1552.001"
    [ -f "$HOME_DIR/.config/gh/hosts.yml" ] && vuln "GitHub CLI token store: ~/.config/gh/hosts.yml" "T1552.001"
    [ -f "$HOME_DIR/.npmrc" ]            && grep -q '_authToken' "$HOME_DIR/.npmrc" 2>/dev/null && vuln "npm auth token in ~/.npmrc" "T1552.001"
    [ -f "$HOME_DIR/.pypirc" ]           && warn "~/.pypirc present (PyPI upload creds)." "T1552.001"
    [ -f "$HOME_DIR/.gem/credentials" ]  && warn "~/.gem/credentials present (RubyGems API key)." "T1552.001"
    [ -f "$HOME_DIR/.terraform.d/credentials.tfrc.json" ] && warn "Terraform Cloud token present." "T1552.001"
    for envf in "$HOME_DIR"/.env "$HOME_DIR"/.envrc; do
        [ -f "$envf" ] && warn "Environment file present: $envf (often holds secrets)." "T1552.001"
    done

    subtitle "Shell history & rc files (secrets often leak here)" "T1552.003"
    for h in .bash_history .zsh_history .sh_history .python_history .node_repl_history .mysql_history .psql_history; do
        [ -f "$HOME_DIR/$h" ] && info "$HOME_DIR/$h ($(wc -l < "$HOME_DIR/$h" 2>/dev/null | tr -d ' ') lines)"
    done

    # ---- #19 Shell-history secret grep --------------------------------------
    subtitle "Secrets mined from shell history" "T1552.003"
    histhits="$(grep -hiE 'password=|passwd |[-_]token[=: ]|secret[=: ]|api[_-]?key|AKIA[0-9A-Z]{16}|curl .*-u |mysql .*-p|psql .*password' \
        "$HOME_DIR"/.bash_history "$HOME_DIR"/.zsh_history "$HOME_DIR"/.sh_history 2>/dev/null | head -15)"
    if [ -n "$histhits" ]; then
        echo "$histhits" | while IFS= read -r l; do data "$l"; done
        vuln "Potential credentials found in shell history (see above)." "T1552.003"
    else
        none "No obvious credential patterns in shell history."
    fi

    subtitle "Environment variables (filtered for secrets)" "T1552"
    run "env | grep -iE 'key|token|secret|pass|cred|aws|azure|gcp' | grep -viE 'SSH_AUTH_SOCK'"

    # ---- #18 Keychain inventory (names only - no secret dump, no prompt) -----
    subtitle "Keychains & item inventory (metadata only)" "T1555.001"
    run "security list-keychains 2>/dev/null"
    none "Secret dumping ('security dump-keychain -d') requires the user password & is NOT performed."
    if [ "$THOROUGH" -eq 1 ]; then
        info "Keychain item labels/services (no secrets):"
        security dump-keychain 2>/dev/null | grep -E '"(svce|labl|acct)"' | sed 's/^/        /' | head -40
    else
        none "(enable -t to inventory keychain item names without dumping secrets)"
    fi

    # ---- #15 Wi-Fi passwords (root + may prompt; thorough only) --------------
    subtitle "Saved Wi-Fi passwords" "T1555"
    # NOTE: 'security find-generic-password -wa <ssid>' triggers a BLOCKING GUI
    # authorization prompt for non-root callers. We therefore only attempt it as
    # root, and even then bound each lookup with a 3s watchdog so it can never
    # hang the scan. Non-root: we just print the manual command (no prompt).
    if [ "$THOROUGH" -eq 1 ] && [ "$CURRENT_UID" -eq 0 ]; then
        none "Attempting retrieval as root (each lookup is time-bounded to 3s)."
        wtmp="$(mk_secure_tmp macenum_wifi)"
        networksetup -listpreferredwirelessnetworks en0 2>/dev/null | sed 's/^[[:space:]]*//' | grep -v 'Preferred networks' | head -10 | while read -r ssid; do
            [ -z "$ssid" ] && continue
            : > "$wtmp"
            security find-generic-password -wa "$ssid" >"$wtmp" 2>/dev/null &
            sp=$!
            ( sleep 3; kill -9 "$sp" 2>/dev/null ) >/dev/null 2>&1 &
            wp=$!
            wait "$sp" 2>/dev/null
            kill "$wp" 2>/dev/null
            pw="$(cat "$wtmp" 2>/dev/null)"
            [ -n "$pw" ] && vuln "Wi-Fi password recovered for '$ssid': $pw" "T1555"
        done
        rm -f "$wtmp" 2>/dev/null
    elif [ "$THOROUGH" -eq 1 ]; then
        none "Skipped auto-retrieval (not root - it would trigger a blocking keychain prompt)."
        none "Retrieve manually: sudo security find-generic-password -wa '<SSID>'"
    else
        none "(enable -t and run as root to attempt Wi-Fi password retrieval)"
    fi

    # ---- #20 Notes / Messages / Mail artifact locator -----------------------
    subtitle "Personal data stores (TCC-gated; paths for manual review)" "T1005"
    for f in "$HOME_DIR/Library/Messages/chat.db" \
             "$HOME_DIR/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite" \
             "$HOME_DIR/Library/Mail"; do
        [ -e "$f" ] && data "present (needs Full Disk Access to read): $f"
    done

    if [ "$THOROUGH" -eq 1 ]; then
        subtitle "Thorough credential file sweep (home dir)" "T1552.001"
        # Pruned + depth-bounded so it stays fast even on large home dirs.
        find "$HOME_DIR" -maxdepth 5 \( -name "*.pem" -o -name "*.key" -o -name "*.p12" \
            -o -name "*.keystore" -o -name "*.env" -o -name ".env*" -o -name "credentials*" \) \
            -type f \
            ! -path '*/node_modules/*' ! -path '*/.git/*' ! -path '*/Library/Caches/*' \
            ! -path '*/site-packages/*' ! -path '*/venv/*' ! -path '*/.venv/*' \
            ! -path '*/Pods/*' ! -path '*/.Trash/*' ! -path '*/.cache/*' \
            2>/dev/null | head -60 | while read -r f; do
            warn "Possible credential file: $f" "T1552.001"
        done
        none "Hardcoded secret-content scanning is performed by the 'secrets' section (faster, pruned)."
    else
        none "(enable -t for deep credential-file sweep; see also the 'secrets' section)"
    fi
}

###############################################################################
# 10b. DATA & CREDENTIAL DISCOVERY  (Features R1, R11, R12, R13, R14)
###############################################################################
enum_discovery() {
    title "DATA & CREDENTIAL DISCOVERY"

    # ---- R1: Spotlight-indexed sensitive files ------------------------------
    subtitle "Spotlight-indexed sensitive files (mdfind)" "T1083"
    if have mdfind; then
        local total=0 pat res c
        for pat in '*.pem' '*.key' '*.ppk' '*.pfx' '*.p12' '*.keystore' '*.kdbx' '*.kdb' \
                   '*.ovpn' 'id_rsa' 'id_ed25519' 'id_dsa' '.env' '*credential*' '*secret*'; do
            res="$(mdfind -onlyin "$HOME_DIR" "kMDItemFSName == '$pat'" 2>/dev/null | head -8)"
            if [ -n "$res" ]; then
                data "pattern '$pat':"
                printf '%s\n' "$res" | while IFS= read -r f; do data "    $f"; done
                c="$(printf '%s\n' "$res" | grep -c .)"
                total=$((total + c))
            fi
        done
        if [ "$total" -gt 0 ]; then
            lowf "$total Spotlight-indexed key/secret-named files found under $HOME_DIR (listed above)." "T1552.001"
        else
            none "No sensitive-named files surfaced via Spotlight (index may be limited/disabled)."
        fi
    else
        none "mdfind/Spotlight not available."
    fi

    # ---- R11: GPG / PGP keyring ---------------------------------------------
    subtitle "GPG / PGP keyring" "T1552.004"
    if [ -d "$HOME_DIR/.gnupg" ]; then
        info "GnuPG home present: $HOME_DIR/.gnupg"
        run "ls -la '$HOME_DIR/.gnupg' 2>/dev/null | grep -viE '^total'"
        if ls "$HOME_DIR/.gnupg/private-keys-v1.d/"*.key >/dev/null 2>&1; then
            warn "GPG private key material present in ~/.gnupg/private-keys-v1.d/." "T1552.004"
        fi
        if have gpg; then
            local sk
            sk="$(gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep -E '^sec')"
            if [ -n "$sk" ]; then
                warn "GPG secret keys exist (usable for signing/decryption):" "T1552.004"
                run "gpg --list-secret-keys --keyid-format=long 2>/dev/null | head -20"
            fi
        fi
    else
        none "No ~/.gnupg directory."
    fi

    # ---- R12: Password managers ---------------------------------------------
    subtitle "Password managers" "T1555.005"
    pm_found=0
    check_pm() { # $1 = name, remaining args = candidate paths
        local name="$1"; shift
        local p
        for p in "$@"; do
            if [ -e "$p" ]; then info "$name detected: $p"; pm_found=1; return 0; fi
        done
    }
    check_pm "1Password"   "/Applications/1Password.app" "/Applications/1Password 7.app" "$HOME_DIR/Library/Group Containers/2BUA8C4S2C.com.1password"
    check_pm "Bitwarden"   "/Applications/Bitwarden.app" "$HOME_DIR/Library/Application Support/Bitwarden"
    check_pm "KeePassXC"   "/Applications/KeePassXC.app"
    check_pm "KeePass"     "/Applications/KeePass.app"
    check_pm "Enpass"      "/Applications/Enpass.app"
    check_pm "Dashlane"    "/Applications/Dashlane.app"
    check_pm "NordPass"    "/Applications/NordPass.app"
    check_pm "Keeper"      "/Applications/Keeper Password Manager.app"
    check_pm "LastPass"    "/Applications/LastPass.app"
    check_pm "Proton Pass" "/Applications/Proton Pass.app"
    [ "$pm_found" -eq 0 ] && none "No common password-manager apps detected."
    if have mdfind; then
        local vaults
        vaults="$(mdfind -onlyin "$HOME_DIR" "kMDItemFSName == '*.kdbx' || kMDItemFSName == '*.opvault' || kMDItemFSName == '*.agilekeychain' || kMDItemFSName == '*.kdb'" 2>/dev/null | head -15)"
        if [ -n "$vaults" ]; then
            warn "Password-manager vault files found (high-value targets):" "T1555.005"
            printf '%s\n' "$vaults" | while IFS= read -r v; do data "    $v"; done
        fi
    fi

    # ---- R13: Git repositories & embedded credentials -----------------------
    subtitle "Git repositories & embedded credentials" "T1552.001"
    [ -f "$HOME_DIR/.gitconfig" ] && run "git config --global --get-regexp 'user\\.' 2>/dev/null"
    local gdepth=4; [ "$THOROUGH" -eq 1 ] && gdepth=10
    local found_repo=0 gd repo cfg urls
    while IFS= read -r gd; do
        [ -z "$gd" ] && continue
        found_repo=1
        repo="$(dirname "$gd")"
        data "repo: $repo"
        cfg="$gd/config"
        urls=""
        if have git; then
            urls="$(git -C "$repo" config --get-regexp 'remote\..*\.url' 2>/dev/null | awk '{print $2}')"
        fi
        if [ -z "$urls" ] && [ -f "$cfg" ]; then
            urls="$(grep -E '^[[:space:]]*url[[:space:]]*=' "$cfg" 2>/dev/null | sed 's/.*=[[:space:]]*//')"
        fi
        printf '%s\n' "$urls" | while IFS= read -r u; do
            [ -z "$u" ] && continue
            data "  remote: $u"
            printf '%s' "$u" | grep -qE '://[^/[:space:]]+:[^/[:space:]]+@' && vuln "Git remote embeds credentials: $u (in $repo)" "T1552.001"
        done
        [ -f "$repo/.git-credentials" ] && vuln "Repo contains .git-credentials: $repo/.git-credentials" "T1552.001"
    done < <(find "$HOME_DIR" -maxdepth "$gdepth" -type d -name .git 2>/dev/null | head -60)
    [ "$found_repo" -eq 0 ] && none "No git repositories found under $HOME_DIR (depth $gdepth)."

    # ---- R14: Database client credentials & configs -------------------------
    subtitle "Database client credentials & configs" "T1552.001"
    local dbany=0
    [ -f "$HOME_DIR/.pgpass" ]       && { vuln "PostgreSQL ~/.pgpass present (plaintext host:port:db:user:password)." "T1552.001"; dbany=1; }
    if [ -f "$HOME_DIR/.my.cnf" ]; then
        dbany=1
        if grep -qiE '^[[:space:]]*password' "$HOME_DIR/.my.cnf" 2>/dev/null; then
            vuln "MySQL ~/.my.cnf contains a stored password." "T1552.001"
        else
            info "MySQL ~/.my.cnf present (no obvious password line)."
        fi
    fi
    [ -f "$HOME_DIR/.mylogin.cnf" ]   && { warn "MySQL ~/.mylogin.cnf present (obfuscated login path)." "T1552.001"; dbany=1; }
    [ -f "$HOME_DIR/.pg_service.conf" ] && { info "PostgreSQL service file ~/.pg_service.conf present."; dbany=1; }
    [ -f "$HOME_DIR/.mongorc.js" ]    && { info "Mongo ~/.mongorc.js present."; dbany=1; }
    for d in \
        "$HOME_DIR/Library/DBeaverData" \
        "$HOME_DIR/Library/Application Support/com.tinyapp.TablePlus" \
        "$HOME_DIR/Library/Application Support/Sequel Ace" \
        "$HOME_DIR/Library/Application Support/Postico 2" ; do
        [ -e "$d" ] && { warn "DB client data store present (may hold saved connections/creds): $d" "T1552.001"; dbany=1; }
    done
    [ -f "$HOME_DIR/Library/DBeaverData/workspace6/General/.dbeaver/credentials-config.json" ] && \
        vuln "DBeaver credentials-config.json present (encrypted saved DB credentials)." "T1552.001"
    [ "$dbany" -eq 0 ] && none "No common database client configs found."
}

###############################################################################
# 11. BROWSERS
###############################################################################
enum_browsers() {
    title "BROWSER ARTIFACTS"

    chromium_browser() {
        local name="$1" base="$2"
        subtitle "$name"
        if [ ! -d "$base" ]; then none "No $name profile (looked in: $base)."; return; fi
        info "User Data dir: $base"
        [ -f "$base/Local State" ] && info "Local State (encrypted master key for cookies/passwords): $base/Local State"
        find "$base" -maxdepth 1 -type d \( -name 'Default' -o -name 'Profile *' -o -name 'System Profile' -o -name 'Guest Profile' \) 2>/dev/null \
            | sort | while IFS= read -r prof; do
            info "Profile: $prof"
            [ -f "$prof/Login Data" ]   && warn "  Saved passwords DB : $prof/Login Data" "T1555.003"
            [ -f "$prof/Cookies" ]      && data "  Cookies DB         : $prof/Cookies"
            [ -f "$prof/Web Data" ]     && data "  Autofill/Web Data  : $prof/Web Data"
            [ -f "$prof/History" ]      && data "  History DB         : $prof/History"
            [ -f "$prof/Bookmarks" ]    && data "  Bookmarks          : $prof/Bookmarks"
            [ -f "$prof/Preferences" ]  && data "  Preferences        : $prof/Preferences"
            if [ -d "$prof/Extensions" ]; then
                data "  Extensions dir     : $prof/Extensions"
                ls "$prof/Extensions" 2>/dev/null | head -20 | while read -r ext; do
                    data "      - $ext"
                done
            fi
        done
    }

    subtitle "Safari"
    sdir="$HOME_DIR/Library/Safari"
    if [ -d "$sdir" ]; then
        info "Safari data dir: $sdir"
        for f in "History.db" "Bookmarks.plist" "Downloads.plist" "TopSites.plist" "LastSession.plist" "CloudTabs.db"; do
            [ -f "$sdir/$f" ] && data "  $f : $sdir/$f"
        done
        [ -f "$sdir/History.db" ] && info "Safari History.db present (TCC-protected; needs Full Disk Access): $sdir/History.db"
        for ext_dir in "$sdir/Extensions" "$HOME_DIR/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions"; do
            [ -d "$ext_dir" ] && { info "Safari extensions dir: $ext_dir"; run "ls '$ext_dir' 2>/dev/null"; }
        done
    else
        none "No Safari profile (or TCC-protected): $sdir"
    fi

    chromium_browser "Google Chrome" "$HOME_DIR/Library/Application Support/Google/Chrome"
    chromium_browser "Google Chrome Beta" "$HOME_DIR/Library/Application Support/Google/Chrome Beta"
    chromium_browser "Microsoft Edge" "$HOME_DIR/Library/Application Support/Microsoft Edge"
    chromium_browser "Brave" "$HOME_DIR/Library/Application Support/BraveSoftware/Brave-Browser"

    subtitle "Firefox"
    fdir="$HOME_DIR/Library/Application Support/Firefox/Profiles"
    if [ -d "$fdir" ]; then
        info "Firefox profiles dir: $fdir"
        find "$fdir" -maxdepth 1 -type d -name '*.*' 2>/dev/null | sort | while IFS= read -r prof; do
            info "Profile: $prof"
            [ -f "$prof/logins.json" ] && warn "  Saved logins (encrypted): $prof/logins.json" "T1555.003"
            [ -f "$prof/key4.db" ]     && info "  Key DB (decrypts logins with logins.json): $prof/key4.db"
            [ -f "$prof/cookies.sqlite" ]      && data "  Cookies DB  : $prof/cookies.sqlite"
            [ -f "$prof/places.sqlite" ]       && data "  History DB  : $prof/places.sqlite"
            [ -f "$prof/cert9.db" ]            && data "  Cert DB     : $prof/cert9.db"
            [ -d "$prof/extensions" ]          && data "  Extensions  : $prof/extensions"
        done
    else
        none "No Firefox profile: $fdir"
    fi
}

###############################################################################
# 12. SECURITY CONFIGURATION
###############################################################################
enum_security() {
    title "SECURITY CONFIGURATION"

    subtitle "System Integrity Protection (SIP)" "T1518.001"
    sip="$(csrutil status 2>/dev/null)"
    info "$sip"
    echo "$sip" | grep -qi disabled && vuln "SIP is DISABLED - system files & protections can be tampered with." "T1518.001"

    subtitle "Gatekeeper / assessment" "T1553"
    gk="$(spctl --status 2>/dev/null)"
    info "$gk"
    echo "$gk" | grep -qi disabled && vuln "Gatekeeper is DISABLED - unsigned/unnotarized code can run freely." "T1553"

    subtitle "Application Firewall"
    fw="/usr/libexec/ApplicationFirewall/socketfilterfw"
    if [ -x "$fw" ]; then
        info "$("$fw" --getglobalstate 2>/dev/null)"
        info "$("$fw" --getstealthmode 2>/dev/null)"
        "$fw" --getglobalstate 2>/dev/null | grep -qi "disabled" && warn "Application Firewall is disabled."
    fi

    subtitle "FileVault (full-disk encryption)"
    fv="$(fdesetup status 2>/dev/null)"
    info "$fv"
    echo "$fv" | grep -qi "Off" && vuln "FileVault is OFF - disk contents are unencrypted at rest." "T1003"

    subtitle "Authenticated-root / sealed system volume"
    run "csrutil authenticated-root status 2>/dev/null"

    subtitle "XProtect (built-in AV signatures)"
    run "system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 -iE 'XProtect' | grep -iE 'XProtect|20' | head -6"
    xp="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"
    [ -f "$xp" ] && info "XProtect definitions: $(stat -f '%Sm' "$xp" 2>/dev/null)"

    subtitle "MRT (Malware Removal Tool)"
    mrt="/Library/Apple/System/Library/CoreServices/MRT.app"
    [ -d "$mrt" ] && info "MRT present: $(defaults read "$mrt/Contents/Info" CFBundleShortVersionString 2>/dev/null)" || none "MRT not found (folded into XProtect Remediator on newer macOS)."

    subtitle "TCC (Transparency, Consent & Control) database" "T1548"
    tcc_user="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"
    tcc_sys="/Library/Application Support/com.apple.TCC/TCC.db"
    if [ -r "$tcc_user" ] && have sqlite3; then
        info "User TCC.db readable - granted permissions:"
        run "sqlite3 '$tcc_user' 'SELECT service,client,auth_value FROM access' 2>/dev/null | head -25"
    else
        none "User TCC.db not readable (expected unless this process has Full Disk Access)."
    fi
    [ -r "$tcc_sys" ] && warn "System TCC.db is readable: $tcc_sys (Full Disk Access already granted to this context)." "T1548"

    subtitle "EFI / boot security (NVRAM)"
    run "nvram -p 2>/dev/null | grep -iE 'csr-active-config|boot-args|SystemAudioVolume'"
    [ -n "$(nvram boot-args 2>/dev/null)" ] && warn "Custom NVRAM boot-args set: $(nvram boot-args 2>/dev/null)"

    subtitle "Remote access services" "T1021"
    run "launchctl list 2>/dev/null | grep -iE 'ssh|screensharing|ard|vnc|remote'"
    systemsetup -getremotelogin 2>/dev/null | grep -qi "On" && warn "Remote Login (SSH) is enabled." "T1021.004"
}

###############################################################################
# 12a. CERTIFICATES, TRUST & PRIVACY GRANTS  (Features R8, R9, R10)
###############################################################################
enum_trust() {
    title "CERTIFICATES, TRUST & PRIVACY GRANTS"

    # ---- R8: custom certificate trust overrides (rogue-CA check) ------------
    subtitle "Custom certificate trust overrides (rogue-CA check)" "T1553.004"
    local ts_admin ts_user
    ts_admin="$(security dump-trust-settings -d 2>/dev/null)"
    ts_user="$(security dump-trust-settings 2>/dev/null)"
    if printf '%s' "$ts_admin" | grep -q 'Cert '; then
        warn "Admin-domain trust overrides present (manually trusted certs - verify none are rogue):" "T1553.004"
        printf '%s\n' "$ts_admin" | grep -E 'Cert |SHA-1' | sed 's/^/        /' | head -30
    fi
    if printf '%s' "$ts_user" | grep -q 'Cert '; then
        warn "User-domain trust overrides present (manually trusted certs):" "T1553.004"
        printf '%s\n' "$ts_user" | grep -E 'Cert |SHA-1' | sed 's/^/        /' | head -30
    fi
    printf '%s%s' "$ts_admin" "$ts_user" | grep -q 'Cert ' || none "No custom trust overrides (only default Apple-trusted roots)."

    local logc="$HOME_DIR/Library/Keychains/login.keychain-db"
    if [ -f "$logc" ]; then
        local cas
        cas="$(security find-certificate -a "$logc" 2>/dev/null | sed -n 's/.*"labl"<blob>="\(.*\)"/\1/p' | sort -u | head -25)"
        if [ -n "$cas" ]; then
            info "Certificates stored in login keychain:"
            printf '%s\n' "$cas" | sed 's/^/        /'
        fi
    fi

    # ---- R9: code-signing identities ----------------------------------------
    subtitle "Code-signing identities (private keys + certs in keychain)" "T1552.004"
    local ids
    ids="$(security find-identity -v -p codesigning 2>/dev/null | grep -E '[0-9A-F]{40}')"
    if [ -n "$ids" ]; then
        info "Usable code-signing identities (this host can sign code as these):"
        printf '%s\n' "$ids" | sed 's/^/        /'
    else
        none "No code-signing identities available in the default keychain."
    fi

    # ---- R10: TCC privacy-permission inventory ------------------------------
    subtitle "TCC privacy-permission inventory" "T1518.001"
    local tu="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"
    local tsys="/Library/Application Support/com.apple.TCC/TCC.db"
    if have sqlite3 && { [ -r "$tu" ] || [ -r "$tsys" ]; }; then
        local entry svc tmp fr risk c1 c2 clients
        for entry in \
            "kTCCServiceSystemPolicyAllFiles:Full Disk Access:HIGH" \
            "kTCCServiceAccessibility:Accessibility (UI control / keylog):HIGH" \
            "kTCCServiceListenEvent:Input Monitoring (keylog):HIGH" \
            "kTCCServiceScreenCapture:Screen Recording:HIGH" \
            "kTCCServicePostEvent:Send Keystrokes:HIGH" \
            "kTCCServiceCamera:Camera:LOW" \
            "kTCCServiceMicrophone:Microphone:LOW" \
            "kTCCServiceAppleEvents:Automation (control other apps):LOW" ; do
            svc="${entry%%:*}"; tmp="${entry#*:}"; fr="${tmp%%:*}"; risk="${tmp##*:}"
            c1=""; c2=""
            [ -r "$tu" ]   && c1="$(sqlite3 "$tu"   "SELECT client FROM access WHERE service='$svc' AND auth_value IN (2,3)" 2>/dev/null)"
            [ -r "$tsys" ] && c2="$(sqlite3 "$tsys" "SELECT client FROM access WHERE service='$svc' AND auth_value IN (2,3)" 2>/dev/null)"
            clients="$(printf '%s\n%s\n' "$c1" "$c2" | grep -v '^$' | sort -u)"
            if [ -n "$clients" ]; then
                if [ "$risk" = "HIGH" ]; then
                    info "${fr} ${RED}[high-risk]${NC} granted to:"
                else
                    info "${fr} granted to:"
                fi
                printf '%s\n' "$clients" | sed 's/^/        /'
                # F22: elevate non-Apple holders of high-risk capabilities to findings
                if [ "$risk" = "HIGH" ]; then
                    printf '%s\n' "$clients" | grep -viE '^com\.apple\.|^/System/|^/usr/(lib|libexec|sbin)/|^/bin/|^/sbin/' | while IFS= read -r cl; do
                        [ -n "$cl" ] && warn "Non-Apple app holds high-risk '${fr}': $cl" "T1548"
                    done
                fi
            fi
        done
    else
        none "TCC.db not readable (needs Full Disk Access / root). No grants enumerated - no assumptions made."
    fi
}

###############################################################################
# 12b. DEFENSIVE STACK - EDR / AV / DLP / MDM  (Features E1..E14)
#
# Detection philosophy (false-positive resistant):
#   * A product is only asserted PRESENT when a CONCRETE, CURRENT artifact
#     matches: an install path that exists, an active system extension, or an
#     installed launchd plist. A stale pkgutil receipt or a loose process name
#     alone is NEVER enough to claim presence.
#   * "RUNNING" is asserted only via a loaded launchd label, a matching process,
#     or an "activated enabled" system extension.
#   * Matchers are exact: reverse-DNS labels, exact bundle IDs, exact paths.
#   * Every detection prints the exact signal(s) that triggered it.
#   * EDR vendors that also ship VPN/other products are disambiguated
#     (e.g. Palo Alto Cortex/Traps != GlobalProtect VPN;
#      Cisco Umbrella DLP != plain AnyConnect VPN).
###############################################################################

# Signature database. One record per line:
#   name|category|paths|launchd_labels|sysext_ids|pkg_ids|proc_basenames
# Multi-values are comma-separated. Empty fields are allowed.
# category in: EDR | AV | DLP | MDM | Telemetry
edr_db() {
cat <<'DBEOF'
CrowdStrike Falcon|EDR|/Applications/Falcon.app,/Library/CS|com.crowdstrike.falcond,com.crowdstrike.falcon|com.crowdstrike.falcon|com.crowdstrike.falcon|falcond,com.crowdstrike.falcon.Agent
SentinelOne|EDR|/Applications/SentinelOne,/Library/Sentinel|com.sentinelone.sentineld,com.sentinelone|com.sentinelone|com.sentinelone|sentineld,SentinelAgent
Microsoft Defender for Endpoint|EDR|/Applications/Microsoft Defender.app,/Library/Application Support/Microsoft/Defender|com.microsoft.fresno,com.microsoft.wdav,com.microsoft.dlp|com.microsoft.wdav.epsext,com.microsoft.wdav.netext|com.microsoft.wdav|wdavdaemon
Jamf Protect|EDR|/Applications/JamfProtect.app,/Library/Application Support/JamfProtect|com.jamf.protect|com.jamf.protect|com.jamf.protect|JamfProtect
VMware Carbon Black|EDR|/Applications/VMware Carbon Black Cloud,/Applications/Confer.app,/Applications/CarbonBlack|com.carbonblack,com.vmware.carbonblack|com.vmware.carbonblack|com.carbonblack,com.vmware.carbonblack|repmgr,CbDefense
Palo Alto Cortex XDR|EDR|/Library/Application Support/PaloAltoNetworks/Traps,/Applications/Cortex XDR.app|com.paloaltonetworks.cortex,com.paloaltonetworks.traps|com.paloaltonetworks.cortex|com.paloaltonetworks.cortex,com.paloaltonetworks.traps|CortexXDRAgent
Sophos|AV|/Library/Sophos Anti-Virus,/Applications/Sophos|com.sophos|com.sophos.endpoint|com.sophos|SophosScanD
Trend Micro|AV|/Library/Application Support/TrendMicro,/Applications/TrendMicro Security.app|com.trendmicro|com.trendmicro|com.trendmicro|iCoreService
ESET|AV|/Applications/ESET Endpoint Security.app,/Library/Application Support/ESET|com.eset|com.eset|com.eset|esets_daemon
Malwarebytes|AV|/Applications/Malwarebytes.app,/Library/Application Support/Malwarebytes|com.malwarebytes|com.malwarebytes|com.malwarebytes|RTProtectionDaemon
Bitdefender|AV|/Library/Bitdefender,/Applications/Bitdefender|com.bitdefender|com.bitdefender|com.bitdefender|BDLDaemon
Kaspersky|AV|/Library/Application Support/Kaspersky Lab|com.kaspersky|com.kaspersky|com.kaspersky|kav
Cylance|EDR|/Applications/Cylance,/Library/Application Support/Cylance|com.cylance|com.cylance|com.cylance|CylanceSvc
Trellix/FireEye HX|EDR|/Library/FireEye,/Applications/FireEye Endpoint Agent.app|com.fireeye.xagt,com.trellix|com.fireeye,com.trellix|com.fireeye,com.trellix|xagt
Elastic Defend|EDR|/Library/Elastic/Endpoint,/Library/Elastic/Agent|co.elastic.endpoint,co.elastic|co.elastic|co.elastic,com.elastic|elastic-endpoint
Tanium|EDR|/Library/Tanium,/opt/Tanium|com.tanium|com.tanium|com.tanium|TaniumClient
Rapid7 Insight|EDR|/opt/rapid7,/Library/Rapid7|com.rapid7|com.rapid7|com.rapid7|ir_agent
Qualys Cloud Agent|EDR|/Applications/QualysCloudAgent.app,/Library/QualysCloudAgent|com.qualys.cloud-agent,com.qualys.edr|com.qualys|com.qualys|qualys-cloud-agent,qualys-cep
Huntress|EDR|/opt/huntress,/Applications/Huntress.app|com.huntress|com.huntress|com.huntress|HuntressAgent
osquery|Telemetry|/var/osquery,/opt/osquery,/usr/local/bin/osqueryd|com.facebook.osqueryd,io.osquery|io.osquery|com.facebook.osquery,io.osquery|osqueryd
Kolide Launcher|Telemetry|/usr/local/kolide-k2,/etc/kolide-k2|com.kolide.launcher,launcherk2|launcherk2|com.kolide,launcherk2|launcher
Code42 Incydr|DLP|/Applications/Code42.app,/Library/Application Support/CrashPlan|com.code42|com.code42|com.code42|Code42Service
Netskope|DLP|/Library/Application Support/Netskope|com.netskope|com.netskope|com.netskope|stagentd
Zscaler|DLP|/Applications/Zscaler,/Library/Application Support/Zscaler|com.zscaler|com.zscaler|com.zscaler|Zscaler
Cisco Umbrella|DLP|/opt/cisco/secureclient/umbrella,/opt/cisco/anyconnect/umbrella,/Library/Application Support/OpenDNS|com.cisco.anyconnect.umbrella,com.opendns.osx|com.cisco.anyconnect.macos.acumbrella|com.opendns|acumbrellaagent
Forcepoint DLP|DLP|/Library/Application Support/Websense,/Applications/Forcepoint DLP Endpoint.app|com.websense,com.forcepoint|com.forcepoint,com.websense|com.forcepoint,com.websense|EndpointClassifier
Digital Guardian|DLP|/Library/Application Support/Digital Guardian|com.digitalguardian|com.digitalguardian|com.digitalguardian|dgagent
Jamf Pro (MDM)|MDM|/usr/local/jamf,/Library/Application Support/JAMF|com.jamfsoftware,com.jamf.management|com.jamf.management|com.jamfsoftware|jamf
Kandji|MDM|/Library/Kandji,/Applications/Kandji Self Service.app|io.kandji|io.kandji|io.kandji|kandji
Mosyle|MDM|/Library/Application Support/Mosyle,/Library/mosyle|com.mosyle|com.mosyle|com.mosyle|MosyleHelper
Microsoft Intune|MDM|/Applications/Company Portal.app,/Library/Application Support/Microsoft/Intune|com.microsoft.intune|com.microsoft.intune|com.microsoft.intune|IntuneMdmAgent
VMware Workspace ONE|MDM|/Applications/Workspace ONE Intelligent Hub.app,/Library/Application Support/AirWatch|com.airwatch,com.vmware.hub|com.vmware.hub|com.airwatch,com.vmware.hub|hubd
Addigy|MDM|/Library/Addigy|com.addigy|com.addigy|com.addigy|
JumpCloud|MDM|/Applications/JumpCloud.app,/opt/jc|com.jumpcloud|com.jumpcloud|com.jumpcloud|jumpcloud-agent
DBEOF
}

enum_defensive() {
    title "DEFENSIVE STACK (EDR / AV / DLP / MDM)"

    # ---- Capture authoritative state once (read-only) -----------------------
    local SYSEXT LAUNCHED PSALL PKGS LAUNCH_PLISTS KEXTS
    SYSEXT="$(systemextensionsctl list 2>/dev/null)"
    LAUNCHED="$(launchctl list 2>/dev/null)"
    PSALL="$(ps -axo user=,comm= 2>/dev/null)"
    PKGS="$(pkgutil --pkgs 2>/dev/null)"
    LAUNCH_PLISTS="$(ls /Library/LaunchDaemons /Library/LaunchAgents \
                        "$HOME_DIR/Library/LaunchAgents" 2>/dev/null)"
    KEXTS="$(kextstat 2>/dev/null || kmutil showloaded 2>/dev/null)"

    # ---- Matchers (exact, low false-positive) -------------------------------
    # echo first existing path from a comma list
    _first_path() { local IFS=','; local p; for p in $1; do [ -n "$p" ] && [ -e "$p" ] && { echo "$p"; return 0; }; done; return 1; }
    # grep -F each comma token against a captured blob ($2); return 0 if any hit
    _csv_in() { local IFS=','; local t; for t in $1; do [ -n "$t" ] && printf '%s\n' "$2" | grep -Fq "$t" && return 0; done; return 1; }
    # process match: token must appear as a path component "/token"
    _proc_in() { local IFS=','; local t; for t in $1; do [ -n "$t" ] && printf '%s\n' "$PSALL" | grep -Fq "/$t" && return 0; done; return 1; }
    # sysext present (any state)
    _sysext_present() { _csv_in "$1" "$SYSEXT"; }
    # sysext active (activated enabled) for any id in the list
    _sysext_active() {
        local IFS=','; local t
        for t in $1; do
            [ -n "$t" ] || continue
            printf '%s\n' "$SYSEXT" | grep -F "$t" | grep -qi 'activated enabled' && return 0
        done
        return 1
    }
    # app version from first .app path
    _app_ver() { local IFS=','; local p; for p in $1; do case "$p" in *.app) [ -d "$p" ] && defaults read "$p/Contents/Info" CFBundleShortVersionString 2>/dev/null && return;; esac; done; }

    # File to remember detected products for the coverage verdict / TCC step.
    local DEF_TMP; DEF_TMP="$(mk_secure_tmp macenum_def)"
    : > "$DEF_TMP"

    subtitle "Detected security products" "T1518.001"
    local any=0
    while IFS='|' read -r name cat paths labels sysexts pkgs procs; do
        [ -z "$name" ] && continue
        # ---- presence (concrete artifact) ----
        local hitpath="" present=0 sig=""
        hitpath="$(_first_path "$paths")"
        if [ -n "$hitpath" ]; then present=1; sig="path:$hitpath"; fi
        if _sysext_present "$sysexts"; then present=1; sig="$sig${sig:+, }sysext"; fi
        if _csv_in "$labels" "$LAUNCH_PLISTS"; then present=1; sig="$sig${sig:+, }launchd-plist"; fi
        # ---- running ----
        local running=0 rsig=""
        if _csv_in "$labels" "$LAUNCHED"; then running=1; rsig="launchd-loaded"; fi
        if _proc_in "$procs"; then running=1; rsig="$rsig${rsig:+, }process"; fi
        if _sysext_active "$sysexts"; then running=1; rsig="$rsig${rsig:+, }sysext-active"; fi
        # supplementary (not sufficient alone): pkg receipt
        local pkghit=0
        _csv_in "$pkgs" "$PKGS" && pkghit=1

        # A product is reported if PRESENT (concrete) or RUNNING (process/ext/label).
        if [ "$present" -eq 1 ] || [ "$running" -eq 1 ]; then
            any=1
            local ver; ver="$(_app_ver "$paths")"
            local state
            if [ "$running" -eq 1 ]; then state="${GREEN}RUNNING${NC}"; else state="${YELLOW}installed (not running)${NC}"; fi
            echo -e "  ${GREEN}[+]${NC} ${BOLD}$name${NC} ${DIM}($cat)${NC} - $state"
            [ -n "$ver" ] && data "version : $ver"
            [ -n "$sig" ]  && data "evidence: $sig"
            [ -n "$rsig" ] && data "activity: $rsig"
            [ "$pkghit" -eq 1 ] && data "receipt : pkgutil receipt present"
            # remember: name<US>category<US>labels,sysexts (ids for TCC cross-ref)
            printf '%s\037%s\037%s\n' "$name" "$cat" "${labels},${sysexts}" >> "$DEF_TMP"
            # coverage gap: a real protection agent that is installed but not running
            if [ "$running" -eq 0 ]; then
                case "$cat" in
                    EDR|AV) vuln "$name is INSTALLED but NOT RUNNING - endpoint protection gap." "T1518.001" ;;
                    DLP)    warn "$name (DLP) is installed but not running." "T1518.001" ;;
                esac
            fi
        elif [ "$pkghit" -eq 1 ]; then
            # Receipt only, no current artifact -> likely uninstalled. Informational, no finding.
            none "$name: only a pkgutil receipt found (likely uninstalled / no active artifact)."
        fi
    done < <(edr_db)
    [ "$any" -eq 0 ] && none "No products from the signature database produced a concrete match."

    # ---- E2: System & network extensions (authoritative) --------------------
    subtitle "System extensions (Endpoint Security / Network)" "T1518.001"
    if [ -n "$SYSEXT" ]; then
        run "systemextensionsctl list 2>/dev/null"
    else
        none "systemextensionsctl returned nothing (pre-Catalina, or no system extensions)."
    fi

    # ---- E3/E11: third-party active ES / network-filter coverage ------------
    subtitle "Endpoint Security & content-filter coverage" "T1518.001"
    local tp_active
    tp_active="$(printf '%s\n' "$SYSEXT" | grep -i 'activated enabled' | grep -viE 'com\.apple\.' )"
    if [ -n "$tp_active" ]; then
        info "Active third-party system extensions (real-time monitoring / filtering):"
        echo "$tp_active" | sed 's/^/        /'
    else
        none "No active third-party Endpoint Security / network-filter extensions found."
    fi

    # ---- E4: legacy kernel extensions (older agents) ------------------------
    subtitle "Third-party kernel extensions (legacy agents)" "T1547.006"
    local tpkext
    tpkext="$(printf '%s\n' "$KEXTS" | grep -viE 'com\.apple\.|Index|Refs' | awk '{print $6}' | grep -v '^$' | sort -u)"
    if [ -n "$tpkext" ]; then
        echo "$tpkext" | while read -r k; do data "$k"; done
    else
        none "No third-party kernel extensions loaded (expected on modern macOS)."
    fi

    # ---- E9: TCC permissions for detected security tools --------------------
    subtitle "Security-tool permissions (Full Disk Access via TCC)" "T1518.001"
    local tcc_user="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"
    local tcc_sys="/Library/Application Support/com.apple.TCC/TCC.db"
    local fda=""
    if have sqlite3; then
        [ -r "$tcc_sys" ]  && fda="$fda$(sqlite3 "$tcc_sys"  "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value IN (2,3)" 2>/dev/null)"
        [ -r "$tcc_user" ] && fda="$fda $(sqlite3 "$tcc_user" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value IN (2,3)" 2>/dev/null)"
    fi
    if [ -n "$fda" ]; then
        info "Clients granted Full Disk Access:"
        echo "$fda" | tr ' ' '\n' | grep -v '^$' | sort -u | sed 's/^/        /'
        # Cross-reference detected EDR/AV against FDA grants
        while IFS=$'\037' read -r dn dc dids; do
            case "$dc" in EDR|AV) ;; *) continue;; esac
            if _csv_in "$dids" "$fda"; then
                info "$dn has Full Disk Access (good - it can monitor effectively)."
            else
                warn "$dn appears to LACK Full Disk Access - it may be partially blind." "T1518.001"
            fi
        done < "$DEF_TMP"
    else
        none "Cannot verify Full Disk Access grants (TCC.db not readable - needs Full Disk Access / root). No assumption made."
    fi

    # ---- E10: PPPC / management profiles ------------------------------------
    subtitle "Management profiles (PPPC / system-extension policy)" "T1484"
    local profout
    profout="$(profiles show 2>/dev/null; profiles list -all 2>/dev/null)"
    if [ -n "$profout" ]; then
        echo "$profout" | grep -qi 'TCC.configuration-profile-policy' && info "A PPPC (privacy) profile is managing app permissions (MDM-controlled)."
        echo "$profout" | grep -qi 'system-extension-policy\|com.apple.system-extension' && info "A profile manages allowed system extensions (MDM-approved EDR)."
        echo "$profout" | grep -iE 'PayloadDisplayName|PayloadType' | grep -iE 'extension|tcc|privacy|defender|crowdstrike|sentinel|jamf' | head -10 | while read -r l; do data "$l"; done
    else
        none "No readable management profiles (full payloads usually require root)."
    fi

    # ---- E12: audit & logging posture ---------------------------------------
    # Note: Apple deprecated OpenBSM auditd in recent macOS in favor of the
    # Endpoint Security framework. So auditd being absent is only a real gap
    # when there is ALSO no active third-party Endpoint Security extension.
    subtitle "Audit & logging posture" "T1562.008"
    if printf '%s\n' "$LAUNCHED" | grep -q 'com.apple.auditd'; then
        info "OpenBSM auditd is loaded (kernel audit trail active)."
    elif [ -n "$tp_active" ]; then
        info "OpenBSM auditd not loaded (deprecated on modern macOS); telemetry is provided by the active Endpoint Security extension(s) above."
    else
        lowf "Neither OpenBSM auditd nor an active Endpoint Security extension is present - limited host audit telemetry." "T1562.008"
    fi
    [ -r /etc/security/audit_control ] && run "grep -vE '^#|^$' /etc/security/audit_control"
    have praudit && data "praudit available: $(command -v praudit)"

    # ---- E14: VPN/compliance-agent tamper-resistance (e.g. GlobalProtect) ---
    # A common real-world gap: if a VPN/compliance agent's user-facing
    # component is a LaunchAgent without KeepAlive, a standard non-admin user
    # can force-quit it (e.g. via Activity Monitor) and launchd will never
    # restart it, permanently disabling enforcement until next login/reboot -
    # no admin rights or exploit needed. Read-only: this only inspects plist
    # config and process state; it never stops, kills, or deletes anything.
    subtitle "VPN/compliance agent tamper-resistance (GlobalProtect)" "T1562.001"
    local gp_found=0 gp_plist is_agent gp_keepalive gp_running gp_state
    for gp_plist in /Library/LaunchAgents/*.plist "$HOME_DIR"/Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
        [ -f "$gp_plist" ] || continue
        case "$gp_plist" in
            *[Pp]alo[Aa]lto*|*[Gg]lobal[Pp]rotect*|*[Pp]an[Gg][Pp]*) ;;
            *) continue ;;
        esac
        gp_found=1
        case "$gp_plist" in
            /Library/LaunchDaemons/*) is_agent=0; info "Found: $gp_plist  [LaunchDaemon - root-enforced]" ;;
            *)                        is_agent=1; info "Found: $gp_plist  [LaunchAgent - user session, user-killable]" ;;
        esac
        gp_keepalive="$(/usr/libexec/PlistBuddy -c 'Print :KeepAlive' "$gp_plist" 2>/dev/null)"
        data "  KeepAlive: ${gp_keepalive:-not set}"
        if [ "$is_agent" -eq 1 ] && { [ -z "$gp_keepalive" ] || echo "$gp_keepalive" | grep -qi 'false'; }; then
            vuln "VPN/compliance component is a user-level LaunchAgent without KeepAlive ($gp_plist) - a standard non-admin user can force-quit it (e.g. via Activity Monitor) with no auto-restart, disabling VPN/compliance enforcement until next login/reboot." "T1562.001"
        fi
    done
    if [ "$gp_found" -eq 0 ]; then
        none "No GlobalProtect (Palo Alto Networks) launchd components found."
    else
        gp_state="$HOME_DIR/Library/Application Support/PaloAltoNetworks/GlobalProtect"
        [ -d "$gp_state" ] && info "State/policy cache directory: $gp_state (lives under the user's own home dir - no root-level integrity protection on its contents)."
        gp_running="$(ps -axo comm= 2>/dev/null | grep -ciE 'PanGPA|PanGPS|GlobalProtect')"
        [ "$gp_running" -gt 0 ] 2>/dev/null && data "GlobalProtect process(es) currently running: $gp_running"
    fi

    # ---- E13: coverage verdict ----------------------------------------------
    subtitle "Defensive coverage verdict" "T1518.001"
    local edr_run dlp_any mdm_any
    edr_run="$(awk -F'\037' '$2=="EDR"||$2=="AV"{print $1}' "$DEF_TMP" 2>/dev/null | join_lines)"
    dlp_any="$(awk -F'\037' '$2=="DLP"{print $1}' "$DEF_TMP" 2>/dev/null | join_lines)"
    mdm_any="$(awk -F'\037' '$2=="MDM"{print $1}' "$DEF_TMP" 2>/dev/null | join_lines)"
    info "EDR/AV : ${edr_run:-none detected}"
    info "DLP    : ${dlp_any:-none detected}"
    info "MDM    : ${mdm_any:-none detected}"

    if [ -z "$edr_run" ]; then
        if [ -n "$tp_active" ]; then
            warn "No agent from the signature set matched, but an active third-party system extension is present (possibly an unlisted EDR - verify manually)." "T1518.001"
        else
            warn "No EDR/AV endpoint-protection agent detected (signature set + no third-party Endpoint Security extension). Host may be unmonitored." "T1518.001"
        fi
    fi
    rm -f "$DEF_TMP" 2>/dev/null
}

###############################################################################
# 13. SYSTEM & CONFIG RECON  (Features #22..#31)
###############################################################################
enum_sysrecon() {
    title "SYSTEM & CONFIGURATION RECON"

    # ---- #22 Software update / patch level ----------------------------------
    subtitle "Software update status" "T1082"
    run "softwareupdate --history 2>/dev/null | head -10"
    if [ "$THOROUGH" -eq 1 ]; then
        info "Checking Apple for available updates (network, may be slow)..."
        avail="$(softwareupdate -l 2>&1 | grep -iE 'Label:|recommended|restart' | head -10)"
        if [ -n "$avail" ]; then
            echo "$avail" | while IFS= read -r l; do data "$l"; done
            warn "Pending OS/security updates available - host may be missing security patches." "T1082"
        else
            none "No pending updates reported (or offline)."
        fi
    else
        none "(enable -t to query Apple for pending security updates)"
    fi

    # ---- #23 MDM / supervision / enrollment ---------------------------------
    subtitle "MDM enrollment / supervision" "T1082"
    enr="$(profiles status -type enrollment 2>/dev/null)"
    [ -n "$enr" ] && echo "$enr" | while IFS= read -r l; do info "$l"; done || none "Enrollment status unavailable (often needs root)."
    echo "$enr" | grep -qi 'Yes (User Approved)\|MDM enrollment: Yes' && warn "Device is MDM-enrolled - remote management can push configs/commands." "T1082"

    # ---- #24 Mounts / disk images / network shares --------------------------
    subtitle "Mounted volumes & network shares" "T1135"
    run "mount 2>/dev/null"
    netmounts="$(mount 2>/dev/null | grep -iE 'smbfs|afpfs|nfs|webdav')"
    [ -n "$netmounts" ] && echo "$netmounts" | while IFS= read -r l; do warn "Network share mounted: $l" "T1135"; done
    run "hdiutil info 2>/dev/null | grep -E 'image-path|/dev/disk' | head -10"

    # ---- #25 Time Machine ---------------------------------------------------
    subtitle "Time Machine backups" "T1005"
    run "tmutil destinationinfo 2>/dev/null"
    snaps="$(tmutil listlocalsnapshots / 2>/dev/null | head -5)"
    [ -n "$snaps" ] && { info "Local APFS snapshots present (may contain other users' data):"; echo "$snaps" | while IFS= read -r l; do data "$l"; done; }

    # ---- #26 Quarantine / download provenance -------------------------------
    subtitle "Recently downloaded / quarantined files" "T1082"
    for d in "$HOME_DIR/Downloads" "$HOME_DIR/Desktop"; do
        [ -d "$d" ] || continue
        ls -t "$d" 2>/dev/null | head -25 | while read -r f; do
            xattr "$d/$f" 2>/dev/null | grep -q 'com.apple.quarantine' && data "quarantined: $d/$f"
        done
    done
    [ -f "$HOME_DIR/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" ] && \
        none "Download history DB: $HOME_DIR/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"

    # ---- #27 Firmware / boot / sleep security -------------------------------
    subtitle "Firmware & sleep security"
    if have firmwarepasswd; then
        fpw="$(firmwarepasswd -check 2>/dev/null)"
        [ -n "$fpw" ] && info "$fpw" || none "firmwarepasswd check needs root (Intel only)."
    else
        none "firmwarepasswd not present (Apple Silicon uses recoveryOS boot policy)."
    fi
    swap="$(sysctl -n vm.swapusage 2>/dev/null)"
    info "Swap: $swap"
    echo "$swap" | grep -qi 'encrypted' || warn "Swap/sleepimage may not be encrypted."
    run "pmset -g 2>/dev/null | grep -iE 'hibernatemode|standby'"

    # ---- #28 pf packet filter -----------------------------------------------
    subtitle "Packet filter (pf) ruleset"
    [ -f /etc/pf.conf ] && run "grep -vE '^\s*#|^\s*$' /etc/pf.conf | head -25" || none "/etc/pf.conf not present/readable."
    run "ls /etc/pf.anchors 2>/dev/null"
    run "pfctl -s info 2>/dev/null | head -5"

    # ---- #29 Sharing services -----------------------------------------------
    subtitle "Sharing / inbound services" "T1021"
    run "sharing -l 2>/dev/null | head -30"
    run "systemsetup -getremotelogin -getremoteappleevents 2>/dev/null"

    # ---- #30 Clipboard (privacy-sensitive; thorough only) -------------------
    subtitle "Clipboard contents" "T1115"
    if [ "$THOROUGH" -eq 1 ]; then
        clip="$(pbpaste 2>/dev/null | head -c 300)"
        if [ -n "$clip" ]; then
            data "clipboard (truncated): $clip"
            echo "$clip" | grep -qiE 'password|secret|token|key|AKIA' && vuln "Clipboard appears to contain a credential/secret." "T1115"
        else
            none "Clipboard empty or unreadable."
        fi
    else
        none "(enable -t to read the clipboard; it is privacy-sensitive and may contain copied passwords)"
    fi

    # ---- #31 launchd-injected environment -----------------------------------
    subtitle "launchd global environment" "T1574.007"
    lpath="$(launchctl getenv PATH 2>/dev/null)"
    [ -n "$lpath" ] && info "launchctl PATH: $lpath"
    for v in DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH; do
        val="$(launchctl getenv "$v" 2>/dev/null)"
        [ -n "$val" ] && crit "Global launchd $v is set: $val (system-wide code injection)." "T1574.006"
    done
    none "(no global DYLD_* override = good)"
}

###############################################################################
# 14. CONTAINERS & VIRTUALIZATION
###############################################################################
enum_containers() {
    title "CONTAINERS & VIRTUALIZATION"

    subtitle "Are we inside a VM?"
    vmmodel="$(sysctl -n hw.model 2>/dev/null)"
    if echo "$vmmodel" | grep -qiE 'VMware|VirtualBox|Parallels|Apple Virtual'; then
        warn "Running inside a virtual machine ($vmmodel)."
    else
        info "Hardware model: $vmmodel (no obvious VM signature)."
    fi
    run "ioreg -l 2>/dev/null | grep -iE 'VirtualBox|VMware|Parallels|Hypervisor' | head -5"

    subtitle "Docker" "T1610"
    if have docker; then
        info "docker present: $(docker --version 2>/dev/null)"
        run "docker ps -a 2>/dev/null | head -15"
        run "docker images 2>/dev/null | head -15"
        id 2>/dev/null | grep -qi docker && crit "Current user is in the 'docker' group - root-equivalent via container mounts." "T1610"
        [ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ] && crit "Writable docker.sock - mount host / to a container for root." "T1610"
    else
        none "docker not installed."
    fi

    subtitle "Podman / Colima / Lima / nerdctl"
    for t in podman colima lima nerdctl; do
        have "$t" && info "$t present: $($t --version 2>/dev/null | head -1)"
    done

    subtitle "Kubernetes tooling"
    have kubectl && { info "kubectl present"; run "kubectl config get-contexts 2>/dev/null"; }
}

###############################################################################
# 15. DEVELOPER TOOLS
###############################################################################
enum_devtools() {
    title "DEVELOPER TOOLS & RUNTIMES"

    subtitle "Xcode / Command Line Tools"
    run "xcode-select -p 2>/dev/null"
    have xcodebuild && run "xcodebuild -version 2>/dev/null | head -2"

    subtitle "Language runtimes & versions"
    have python3 && info "Python3 : $(python3 --version 2>&1)"
    have python  && info "Python  : $(python --version 2>&1)"
    have ruby    && info "Ruby    : $(ruby --version 2>&1)"
    have node    && info "Node.js : $(node --version 2>&1)"
    have go      && info "Go      : $(go version 2>&1)"
    have rustc   && info "Rust    : $(rustc --version 2>&1)"
    if have java; then
        jv="$(java -version 2>&1 | head -1)"
        echo "$jv" | grep -qi 'Unable to locate' || info "Java    : $jv"
    fi
    have perl    && info "Perl    : $(perl -v 2>&1 | grep -m1 version)"
    have php     && info "PHP     : $(php --version 2>&1 | head -1)"
    have git     && info "Git     : $(git --version 2>&1)"
    have brew    && info "Homebrew: $(brew --version 2>&1 | head -1)"

    subtitle "Compilers / interpreters present"
    for c in gcc clang cc make nc ncat socat python3 perl ruby osascript swift; do
        have "$c" && data "available: $c -> $(command -v $c)"
    done

    subtitle "Writable global package dirs (supply-chain / privesc)" "T1574"
    for d in /usr/local/lib/node_modules /Library/Frameworks/Python.framework $(brew --prefix 2>/dev/null); do
        [ -d "$d" ] && [ -w "$d" ] && warn "World/user-writable dev dir: $d" "T1574"
    done
}

###############################################################################
# 16. SECRET & CREDENTIAL CONTENT SCAN  (Features F1, F2, F3, F5)
#
# Reads file CONTENTS (read-only) for hardcoded secrets. False-positive control:
#   * F1 matches only high-confidence token shapes (AKIA…, ghp_…, JWTs, PEM…).
#   * F2 only scans env-type files (.env/.tfvars/.netrc/credentials).
#   * F3 (thorough) requires a key-like LHS AND a 40+ char value.
#   * Secret values are MASKED in output; heavy dirs (node_modules, caches,
#     venv, site-packages, .git, Pods, build) are pruned.
###############################################################################
enum_secrets() {
    title "SECRET & CREDENTIAL CONTENT SCAN"

    local maxd=2
    [ "$THOROUGH" -eq 1 ] && maxd=3
    local roots
    roots=( "$HOME_DIR" "$HOME_DIR/.config" "$HOME_DIR/.aws" "$HOME_DIR/.azure" "$HOME_DIR/.kube" )
    if [ "$THOROUGH" -eq 1 ]; then
        roots=( "${roots[@]}" "$HOME_DIR/Documents" "$HOME_DIR/Desktop" "$HOME_DIR/Projects" \
                "$HOME_DIR/Developer" "$HOME_DIR/Downloads" "$HOME_DIR/src" )
    fi

    # Build a NUL-delimited candidate list (read-only). Skip files >512k and
    # heavy dirs. A single batched grep then finds the (few) matching files -
    # far faster than grepping every candidate individually.
    local CAND
    CAND="$(mk_secure_tmp macenum_sec)"
    : > "$CAND"
    local r
    for r in "${roots[@]}"; do
        [ -d "$r" ] || continue
        find "$r" -maxdepth "$maxd" -type f -size -512k \
            \( -name '*.env' -o -name '.env*' -o -name '*.cfg' -o -name '*.conf' -o -name '*.config' \
               -o -name '*.ini' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' -o -name '*.properties' \
               -o -name '*.txt' -o -name '*.sh' -o -name '*.bash*' -o -name '*.zsh*' -o -name '*.rc' \
               -o -name '*.xml' -o -name '*.tfvars' -o -name '.netrc' \) \
            ! -path '*/node_modules/*' ! -path '*/.git/*' ! -path '*/Library/Caches/*' \
            ! -path '*/site-packages/*' ! -path '*/venv/*' ! -path '*/.venv/*' ! -path '*/.Trash/*' \
            ! -path '*/Pods/*' ! -path '*/dist/*' ! -path '*/build/*' ! -path '*/vendor/*' \
            ! -path '*/.cargo/*' ! -path '*/go/pkg/*' ! -path '*/.npm/*' ! -path '*/.cache/*' \
            -print0 2>/dev/null
    done > "$CAND"
    local nfiles; nfiles="$(tr -cd '\000' < "$CAND" 2>/dev/null | wc -c | tr -d ' ')"; nfiles="${nfiles:-0}"

    local MASK='s#([A-Za-z0-9_+/=-]{4})[A-Za-z0-9_+/=.-]{10,}([A-Za-z0-9_+/=-]{4})#\1…REDACTED…\2#g'

    # ---- F1: high-confidence named secret tokens (batched -> detail) --------
    subtitle "Hardcoded secrets - token patterns (scanned $nfiles files)" "T1552.001"
    local PAT='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{20,}|rk_live_[0-9A-Za-z]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{20,}|dop_v1_[a-f0-9]{64}|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
    local hitfiles=0 f m
    if [ -s "$CAND" ]; then
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            m="$(grep -aInE "$PAT" "$f" 2>/dev/null | head -4)"
            [ -z "$m" ] && continue
            hitfiles=$((hitfiles+1))
            _suppress || { data "${f}:"; printf '%s\n' "$m" | sed -E "$MASK" | sed 's/^/        /'; }
            vuln "Hardcoded secret/token pattern in $f" "T1552.001"
        done < <(xargs -0 grep -lIEa "$PAT" < "$CAND" 2>/dev/null | head -80)
    fi
    [ "$hitfiles" -eq 0 ] && none "No high-confidence secret tokens matched."

    # ---- F2: secret-like assignments in env-type files ----------------------
    subtitle "Secret assignments in .env / tfvars / netrc files" "T1552.001"
    local APAT='(password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|[_-]token|private[_-]?key|db[_-]?pass)[[:space:]]*[:=][[:space:]]*[^[:space:]]{6,}'
    local envf envhit=0 em
    while IFS= read -r envf; do
        [ -z "$envf" ] && continue
        em="$(grep -aIniE "$APAT" "$envf" 2>/dev/null | grep -viE 'changeme|example|your_|xxxx|<[^>]*>|placeholder|dummy|=[[:space:]]*$|:[[:space:]]*$' | head -6)"
        if [ -n "$em" ]; then
            envhit=$((envhit+1))
            _suppress || { data "${envf}:"; printf '%s\n' "$em" | sed -E "$MASK" | sed 's/^/        /'; }
            warn "Secret assignment(s) in $envf" "T1552.001"
        fi
    done < <(for r in "${roots[@]}"; do [ -d "$r" ] && find "$r" -maxdepth "$maxd" -type f -size -512k \( -name '*.env' -o -name '.env*' -o -name '*.tfvars' -o -name '.netrc' \) ! -path '*/node_modules/*' ! -path '*/.git/*' 2>/dev/null; done | head -80)
    [ "$envhit" -eq 0 ] && none "No secret-like assignments in env-type files."

    # ---- F3: high-entropy key=value (thorough; key-like LHS + 40+ char val) --
    subtitle "Long high-entropy tokens (key-like assignments)" "T1552.001"
    if [ "$THOROUGH" -eq 1 ] && [ -s "$CAND" ]; then
        local EPAT='[A-Za-z0-9_]*(key|token|secret|password|cred|auth)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*[A-Za-z0-9+/_-]{40,}'
        local ehit=0
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            m="$(grep -aIniE "$EPAT" "$f" 2>/dev/null | grep -viE 'example|sample|test|dummy|placeholder' | head -3)"
            [ -z "$m" ] && continue
            ehit=$((ehit+1))
            _suppress || { data "${f}:"; printf '%s\n' "$m" | sed -E "$MASK" | sed 's/^/        /'; }
            lowf "High-entropy token assigned in $f" "T1552.001"
        done < <(xargs -0 grep -lIEa "$EPAT" < "$CAND" 2>/dev/null | head -50)
        [ "$ehit" -eq 0 ] && none "No long high-entropy key assignments found."
    else
        none "(enable -t for high-entropy token scanning)"
    fi

    # ---- F5: app & cloud token stores (decode where trivial, masked) --------
    subtitle "App & cloud token stores" "T1552.001"
    local dcfg="$HOME_DIR/.docker/config.json"
    if [ -f "$dcfg" ] && grep -q '"auth"' "$dcfg" 2>/dev/null; then
        warn "Docker registry auth tokens present in $dcfg (base64 user:password)." "T1552.001"
        if have base64; then
            grep -oE '"auth"[[:space:]]*:[[:space:]]*"[^"]+"' "$dcfg" 2>/dev/null | sed -E 's/.*"([^"]+)"$/\1/' | head -5 | while IFS= read -r b; do
                dec="$(printf '%s' "$b" | base64 -D 2>/dev/null)"
                user="$(printf '%s' "$dec" | cut -d: -f1)"
                _suppress || data "registry login user: ${user:-?} (password masked)"
            done
        fi
    fi
    [ -f "$HOME_DIR/.npmrc" ] && grep -q '_authToken' "$HOME_DIR/.npmrc" 2>/dev/null && \
        warn "npm auth token present in ~/.npmrc." "T1552.001"
    [ -f "$HOME_DIR/.config/gh/hosts.yml" ] && \
        warn "GitHub CLI OAuth token store: ~/.config/gh/hosts.yml" "T1552.001"
    for ct in "$HOME_DIR/.config/gcloud/access_tokens.db" "$HOME_DIR/.config/gcloud/credentials.db" \
              "$HOME_DIR/.azure/accessTokens.json" "$HOME_DIR/.azure/msal_token_cache.json"; do
        [ -f "$ct" ] && warn "Cloud token cache present: $ct" "T1552.001"
    done
    if [ "$THOROUGH" -eq 1 ]; then
        # Slack/VS Code desktop token leftovers (grep storage; read-only)
        for sd in "$HOME_DIR/Library/Application Support/Slack/storage" \
                  "$HOME_DIR/Library/Application Support/Code/User"; do
            [ -d "$sd" ] || continue
            grep -rhoaE 'xox[bapsr]-[0-9A-Za-z-]{10,}' "$sd" 2>/dev/null | head -3 | while IFS= read -r tk; do
                warn "Slack-style token found in $sd ($(mask "$tk"))." "T1552.001"
            done
        done
    fi

    rm -f "$CAND" 2>/dev/null
}

###############################################################################
# 17. SECURITY HARDENING & MISCONFIGURATIONS  (Features F10-F19)
###############################################################################
enum_hardening() {
    title "SECURITY HARDENING & MISCONFIGURATIONS"

    # ---- F14: macOS support status ------------------------------------------
    subtitle "macOS version support status" "T1082"
    local prodver major
    prodver="$(sw_vers -productVersion 2>/dev/null)"
    major="${prodver%%.*}"
    if [ -n "$major" ] && [ "$major" -le 13 ] 2>/dev/null; then
        warn "macOS $prodver (major $major) is at/near end of Apple security support - plan an upgrade." "T1082"
    else
        info "macOS $prodver appears within the supported release window."
    fi

    # ---- F10: login window & account policy ---------------------------------
    subtitle "Login window & account policy" "T1078"
    local lw="/Library/Preferences/com.apple.loginwindow" v
    v="$(defaults read "$lw" GuestEnabled 2>/dev/null)";        [ "$v" = "1" ] && warn "Guest account is enabled." "T1078"
    v="$(defaults read "$lw" SHOWFULLNAME 2>/dev/null)";        [ "$v" = "0" ] && lowf "Login window shows a user list (name+password fields not enforced)." "T1078"
    v="$(defaults read "$lw" RetriesUntilHint 2>/dev/null)";    { [ -n "$v" ] && [ "$v" != "0" ] 2>/dev/null && warn "Password hints are enabled (RetriesUntilHint=$v)." "T1078"; }
    v="$(defaults read "$lw" autoLoginUser 2>/dev/null)";       [ -n "$v" ] && warn "Automatic login configured for: $v (see kcpassword in SENSITIVE)." "T1078"
    v="$(defaults read /Library/Preferences/.GlobalPreferences MultipleSessionEnabled 2>/dev/null)"; [ "$v" = "1" ] && lowf "Fast user switching is enabled."

    # ---- F11: screen lock / password after sleep ----------------------------
    subtitle "Screen lock / password after sleep" "T1078"
    local sp spd
    sp="$(defaults -currentHost read com.apple.screensaver askForPassword 2>/dev/null)"
    spd="$(defaults -currentHost read com.apple.screensaver askForPasswordDelay 2>/dev/null)"
    if [ "$sp" = "0" ]; then
        warn "No password required after screen saver / sleep (askForPassword=0)." "T1078"
    elif [ -n "$spd" ] && [ "$spd" -gt 60 ] 2>/dev/null; then
        warn "Screen-lock password grace period is long (${spd}s)." "T1078"
    else
        none "Screen lock requires a password (or is managed by policy)."
    fi

    # ---- F13: automatic security updates ------------------------------------
    subtitle "Automatic security updates" "T1082"
    local su="/Library/Preferences/com.apple.SoftwareUpdate" ac cdi cui
    ac="$(defaults read "$su" AutomaticCheckEnabled 2>/dev/null)"
    cdi="$(defaults read "$su" ConfigDataInstall 2>/dev/null)"
    cui="$(defaults read "$su" CriticalUpdateInstall 2>/dev/null)"
    [ "$ac" = "0" ]  && warn "Automatic update checking is disabled." "T1082"
    [ "$cdi" = "0" ] && warn "XProtect/security-data auto-install (ConfigDataInstall) is disabled." "T1082"
    [ "$cui" = "0" ] && warn "Critical security update auto-install is disabled." "T1082"
    [ -z "$ac$cdi$cui" ] && none "Update prefs not explicitly set (system default / MDM-managed)."

    # ---- F12: sharing / remote-access services ------------------------------
    subtitle "Sharing / remote-access services enabled" "T1021"
    local ll; ll="$(launchctl list 2>/dev/null)"
    printf '%s\n' "$ll" | grep -qE 'com\.apple\.screensharing$'      && warn "Screen Sharing service is loaded." "T1021.001"
    printf '%s\n' "$ll" | grep -qi 'com\.apple\.RemoteDesktop.agent' && warn "Apple Remote Desktop (ARD) agent is loaded." "T1021.001"
    printf '%s\n' "$ll" | grep -qE 'com\.apple\.smbd'               && warn "SMB file sharing (smbd) is loaded." "T1135"
    printf '%s\n' "$ll" | grep -qE 'com\.apple\.AppleFileServer'    && warn "AFP file sharing is loaded." "T1135"
    local nat="/Library/Preferences/SystemConfiguration/com.apple.nat"
    [ -f "$nat" ] && defaults read "$nat" 2>/dev/null | grep -q 'Enabled[[:space:]]*=[[:space:]]*1' && warn "Internet Sharing (NAT) config is enabled." "T1021"
    systemsetup -getremotelogin 2>/dev/null | grep -qi 'On' && warn "Remote Login (SSH) is enabled." "T1021.004"

    # ---- F19: SSH server hardening ------------------------------------------
    subtitle "SSH server (sshd) hardening" "T1021.004"
    local sc="/etc/ssh/sshd_config"
    if [ -f "$sc" ]; then
        local prl pwa pep
        prl="$(grep -iE '^[[:space:]]*PermitRootLogin' "$sc" 2>/dev/null | awk '{print tolower($2)}' | tail -1)"
        pwa="$(grep -iE '^[[:space:]]*PasswordAuthentication' "$sc" 2>/dev/null | awk '{print tolower($2)}' | tail -1)"
        pep="$(grep -iE '^[[:space:]]*PermitEmptyPasswords' "$sc" 2>/dev/null | awk '{print tolower($2)}' | tail -1)"
        [ "$prl" = "yes" ] && vuln "sshd PermitRootLogin=yes (root can log in over SSH)." "T1021.004"
        [ "$pwa" = "yes" ] && warn "sshd PasswordAuthentication=yes (brute-forceable; prefer keys)." "T1021.004"
        [ "$pep" = "yes" ] && crit "sshd PermitEmptyPasswords=yes (empty-password logins allowed)." "T1021.004"
        run "grep -iE '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|ChallengeResponseAuthentication)' '$sc'"
    else
        none "No /etc/ssh/sshd_config present/readable."
    fi

    # ---- F16: network-exposed listeners (non-loopback) ----------------------
    subtitle "Network-exposed listening services (non-loopback)" "T1049"
    if have lsof; then
        local exposed
        exposed="$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $1" "$9}' | grep -vE '127\.0\.0\.1:|\[::1\]:|localhost:' | sort -u)"
        if [ -n "$exposed" ]; then
            printf '%s\n' "$exposed" | while IFS= read -r line; do
                [ -n "$line" ] && warn "Listening on a non-loopback address: $line" "T1049"
            done
        else
            none "All TCP listeners are bound to loopback (not network-exposed)."
        fi
    else
        none "lsof unavailable; cannot evaluate listener exposure."
    fi

    # ---- F17: network-stack hardening ---------------------------------------
    subtitle "Network stack hardening (sysctl)" "T1016"
    local f4 f6 promisc
    f4="$(sysctl -n net.inet.ip.forwarding 2>/dev/null)"
    f6="$(sysctl -n net.inet6.ip6.forwarding 2>/dev/null)"
    [ "$f4" = "1" ] && warn "IPv4 forwarding is enabled (host is routing packets)." "T1016"
    [ "$f6" = "1" ] && warn "IPv6 forwarding is enabled." "T1016"
    promisc="$(ifconfig 2>/dev/null | grep -ci PROMISC)"
    [ -n "$promisc" ] && [ "$promisc" -gt 0 ] 2>/dev/null && lowf "$promisc interface(s) in promiscuous mode (normal for bridges/VMs; verify)." "T1040"
    [ "$f4" != "1" ] && [ "$f6" != "1" ] && none "IP forwarding disabled (good)."

    # ---- F18: /etc/hosts hijack check ---------------------------------------
    subtitle "/etc/hosts integrity (hijack check)" "T1565.001"
    local hh
    hh="$(grep -viE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null | grep -iE 'apple\.com|icloud|github|google|microsoft|amazon|paypal|okta|bank' | grep -vE '127\.0\.0\.1|::1|0\.0\.0\.0|255\.255\.255\.255|broadcasthost')"
    if [ -n "$hh" ]; then
        warn "/etc/hosts maps well-known domains to custom IPs (possible hijack/MITM):" "T1565.001"
        _suppress || printf '%s\n' "$hh" | sed 's/^/        /'
    else
        none "No suspicious well-known-domain redirects in /etc/hosts."
    fi

    # ---- F15: outdated packages (thorough) ----------------------------------
    subtitle "Outdated packages (potential CVE exposure)" "T1082"
    if [ "$THOROUGH" -eq 1 ] && have brew; then
        local ob oc
        ob="$(brew outdated --quiet 2>/dev/null | head -40)"
        if [ -n "$ob" ]; then
            _suppress || printf '%s\n' "$ob" | sed 's/^/      outdated: /'
            oc="$(printf '%s\n' "$ob" | grep -c .)"
            lowf "$oc outdated Homebrew package(s) - update to pick up security fixes." "T1082"
        else
            none "Homebrew packages are up to date."
        fi
    else
        none "(enable -t with Homebrew installed to list outdated packages)"
    fi
}

###############################################################################
# 18. WEAK PERMISSIONS & DATA EXPOSURE  (Features F23, F24, F25)
###############################################################################
enum_permissions() {
    title "WEAK PERMISSIONS & DATA EXPOSURE"

    _checkperm() { # $1=path  $2=label  $3=strict(1 => no group/other bits at all)
        local f="$1" label="$2" strict="$3" p go
        [ -e "$f" ] || return
        p="$(stat -f '%Lp' "$f" 2>/dev/null)"
        [ -z "$p" ] && return
        go="$(printf '%s' "$p" | sed 's/.*\(..\)$/\1/')"
        if [ "$strict" = "1" ]; then
            if [ "$go" != "00" ]; then
                vuln "$label has lax permissions ($p) - should be 600/700: $f" "T1552"
            else
                data "ok ($p): $f"
            fi
        else
            case "$p" in
                *[2367]) warn "$label is group/world-accessible ($p): $f" "T1552" ;;
                *)       data "ok ($p): $f" ;;
            esac
        fi
    }

    subtitle "Permissions on credential files & directories" "T1552"
    local k
    for k in "$HOME_DIR"/.ssh/id_* "$HOME_DIR"/.ssh/*.pem; do
        [ -f "$k" ] || continue
        case "$k" in *.pub) continue;; esac
        _checkperm "$k" "SSH private key" 1
    done
    [ -d "$HOME_DIR/.ssh" ] && _checkperm "$HOME_DIR/.ssh" "~/.ssh directory" 1
    _checkperm "$HOME_DIR/.aws/credentials" "AWS credentials" 0
    _checkperm "$HOME_DIR/.netrc"           "~/.netrc" 1
    _checkperm "$HOME_DIR/.git-credentials" "~/.git-credentials" 1
    _checkperm "$HOME_DIR/.gnupg"           "~/.gnupg directory" 0
    [ -f "$HOME_DIR/.env" ] && _checkperm "$HOME_DIR/.env" ".env file" 0

    subtitle "SSH authorized_keys (who can log in as you)" "T1098.004"
    local ak="$HOME_DIR/.ssh/authorized_keys" n
    if [ -f "$ak" ]; then
        n="$(grep -cvE '^[[:space:]]*#|^[[:space:]]*$' "$ak" 2>/dev/null)"
        info "$n authorized SSH key(s) can log in as $CURRENT_USER:"
        _suppress || grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$ak" 2>/dev/null | awk '{print $NF}' | sed 's/^/        /' | head -20
        _checkperm "$ak" "authorized_keys" 0
    else
        none "No ~/.ssh/authorized_keys."
    fi

    subtitle "Other users' data & shared-folder exposure" "T1530"
    local ud p
    for ud in /Users/*; do
        [ -d "$ud" ] || continue
        case "$ud" in */Shared|*/Guest|*/.localized) continue;; esac
        [ "$ud" = "$HOME_DIR" ] && continue
        # Only flag if a normally-private subdir is actually readable by us.
        if ls "$ud/Documents" >/dev/null 2>&1 || [ -r "$ud/.ssh" ]; then
            p="$(stat -f '%Lp' "$ud" 2>/dev/null)"
            warn "Another user's private data is readable by you (home perms $p): $ud" "T1530"
        fi
    done
    if [ -d /Users/Shared ]; then
        local ww
        ww="$(find /Users/Shared -maxdepth 2 -perm -0002 -type f 2>/dev/null | head -15)"
        if [ -n "$ww" ]; then
            warn "World-writable files in /Users/Shared:" "T1530"
            _suppress || printf '%s\n' "$ww" | sed 's/^/        /'
        fi
    fi
}

###############################################################################
# 19. ADVANCED PRIVILEGE ESCALATION  (Features P1-P18, P21, P22, P23)
#  All read-only. Detects exploitable conditions; never exploits them.
###############################################################################
enum_privesc2() {
    title "ADVANCED PRIVILEGE ESCALATION (WRITABLE ROOT PATHS, CHAINS & TECHNIQUES)"

    local BREWP; BREWP="$(brew --prefix 2>/dev/null)"

    # ---- P1: /etc/synthetic.conf (APFS root injection) ----------------------
    subtitle "APFS root injection via /etc/synthetic.conf" "T1574"
    if [ -e /etc/synthetic.conf ]; then
        if [ -w /etc/synthetic.conf ]; then
            crit "/etc/synthetic.conf is writable - inject entries at the read-only root '/' (firmlink) then reboot." "T1574"
        else
            none "present, not writable: /etc/synthetic.conf"
        fi
    elif [ -w /etc ]; then
        crit "/etc is writable and synthetic.conf absent - create it to inject '/' entries at next boot." "T1574"
    else
        none "/etc/synthetic.conf not writable."
    fi

    # ---- P4: writable sudoers drop-in dir -----------------------------------
    subtitle "Writable sudoers drop-in directory" "T1548.003"
    if [ -d /etc/sudoers.d ] && [ -w /etc/sudoers.d ]; then
        crit "/etc/sudoers.d is writable - drop a 'user ALL=(ALL) NOPASSWD:ALL' file for instant root." "T1548.003"
    else
        none "/etc/sudoers.d not writable."
    fi

    # ---- P5: writable local directory store (forge admin) -------------------
    subtitle "Writable OpenDirectory store (forge admin/UID-0 user)" "T1136.001"
    local p5=0
    for d in /var/db/dslocal/nodes/Default /var/db/dslocal/nodes/Default/users; do
        if [ -d "$d" ] && [ -w "$d" ]; then crit "Writable directory store $d - forge a UID-0/admin user plist." "T1136.001"; p5=1; fi
    done
    [ "$p5" -eq 0 ] && none "Local user store (dslocal) not writable."

    # ---- P2 + P10: writable periodic dirs / scripts -------------------------
    subtitle "Writable periodic dirs/scripts (root cron-like execution)" "T1053.003"
    local p2=0
    for d in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly \
             /usr/local/etc/periodic/daily /usr/local/etc/periodic/weekly /usr/local/etc/periodic/monthly \
             "$BREWP/etc/periodic/daily" "$BREWP/etc/periodic/weekly" "$BREWP/etc/periodic/monthly"; do
        if [ -d "$d" ] && [ -w "$d" ]; then crit "Writable periodic dir $d - drop a script run by root via 'periodic'." "T1053.003"; p2=1; fi
    done
    local pfcount=0
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -w "$f" ] || continue
        crit "Writable periodic script (runs as root): $f" "T1053.003"
        pfcount=$((pfcount+1))
        [ "$pfcount" -ge 20 ] && break
    done < <(find /etc/periodic /usr/local/etc/periodic "$BREWP/etc/periodic" -type f 2>/dev/null)
    [ "$p2" -eq 0 ] && none "No writable periodic directories."

    # ---- P10: cron/at command paths writable by you (full content parse) ----
    # Extract every absolute path referenced by crontabs and flag the ones you
    # can overwrite (the crontab owner - often root - executes them).
    subtitle "Cron/at command paths writable by you" "T1053.003"
    local c10 cp p10hits
    c10="$( { crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; cat /usr/lib/cron/tabs/* 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; } \
            | grep -vE '^[[:space:]]*#|^[[:space:]]*$' )"
    p10hits=0
    if [ -n "$c10" ]; then
        while read -r cp; do
            [ -n "$cp" ] || continue
            if [ -f "$cp" ] && [ -w "$cp" ]; then
                crit "Cron-referenced path is writable: $cp (executed by its crontab owner - root if a system crontab)." "T1053.003"
                p10hits=$((p10hits+1))
            fi
        done < <(printf '%s\n' "$c10" | grep -oE '/[A-Za-z0-9_][A-Za-z0-9_./-]+' | sort -u)
    fi
    [ "$p10hits" -eq 0 ] && none "No writable binaries referenced by readable crontabs."

    # ---- P11: writable boot/maintenance config ------------------------------
    subtitle "Writable boot / maintenance config" "T1037"
    local p11=0
    for f in /etc/periodic.conf /etc/periodic.conf.local /etc/rc.common /etc/rc.local /etc/launchd.conf /etc/profile /etc/zprofile /etc/zshenv; do
        if [ -f "$f" ] && [ -w "$f" ]; then crit "Writable root-executed config: $f" "T1037"; p11=1; fi
    done
    [ "$p11" -eq 0 ] && none "No writable boot/maintenance configs."

    # ---- P3: newsyslog (arbitrary root file create/chmod) -------------------
    subtitle "Writable newsyslog config (root file create/chmod on rotation)" "T1222.002"
    local p3=0
    if [ -f /etc/newsyslog.conf ] && [ -w /etc/newsyslog.conf ]; then crit "/etc/newsyslog.conf writable - root creates/chmods attacker-specified files on rotation." "T1222.002"; p3=1; fi
    if [ -d /etc/newsyslog.d ]; then
        if [ -w /etc/newsyslog.d ]; then crit "/etc/newsyslog.d writable - drop a rule to create/chmod files as root." "T1222.002"; p3=1; fi
        find /etc/newsyslog.d -maxdepth 1 -type f 2>/dev/null | while read -r f; do [ -n "$f" ] && [ -w "$f" ] && crit "Writable newsyslog rule: $f" "T1222.002"; done
    fi
    [ "$p3" -eq 0 ] && none "newsyslog config not writable."

    # ---- P6: writable PAM directories ---------------------------------------
    subtitle "Writable PAM directories (auth bypass / root)" "T1556"
    local p6=0
    for d in /etc/pam.d /usr/lib/pam /usr/local/lib/pam; do
        if [ -d "$d" ] && [ -w "$d" ]; then crit "Writable PAM directory $d - drop/replace a module to bypass auth as root." "T1556"; p6=1; fi
    done
    [ "$p6" -eq 0 ] && none "PAM directories not writable."

    # ---- P7: CUPS / printing privesc surface --------------------------------
    subtitle "CUPS / printing privesc surface" "T1543"
    local p7=0
    if [ -f /etc/cups/cupsd.conf ] && [ -w /etc/cups/cupsd.conf ]; then crit "/etc/cups/cupsd.conf writable - cupsd runs as root." "T1543"; p7=1; fi
    for b in /usr/sbin/cupsd /usr/sbin/cupsctl /usr/bin/lppasswd /usr/sbin/lpadmin; do
        if [ -f "$b" ] && [ -u "$b" ]; then warn "SUID CUPS binary: $b" "T1548.001"; p7=1; fi
    done
    [ "$p7" -eq 0 ] && none "No obvious CUPS privesc surface."

    # ---- P8: writable launchd/StartupItems directories ----------------------
    subtitle "Writable launchd / StartupItems directories (drop new root job)" "T1543.001"
    local p8=0
    for d in /Library/LaunchDaemons /Library/LaunchAgents /Library/StartupItems /System/Library/LaunchDaemons; do
        if [ -d "$d" ] && [ -w "$d" ]; then crit "Writable $d - drop a new plist to execute code (root if a LaunchDaemons dir)." "T1543.001"; p8=1; fi
    done
    [ "$p8" -eq 0 ] && none "launchd/StartupItems directories not writable."

    # ---- P9: full launchd plist abuse (args / WorkingDirectory / DYLD env) --
    subtitle "Root LaunchDaemon abuse: writable args / workdir / DYLD env" "T1543.001"
    local p9=0 lf un wd ev i a
    for lf in /Library/LaunchDaemons/*.plist; do
        [ -f "$lf" ] || continue
        un="$(/usr/libexec/PlistBuddy -c 'Print :UserName' "$lf" 2>/dev/null)"
        [ -n "$un" ] && [ "$un" != "root" ] && continue
        wd="$(/usr/libexec/PlistBuddy -c 'Print :WorkingDirectory' "$lf" 2>/dev/null)"
        if [ -n "$wd" ] && [ -d "$wd" ] && [ -w "$wd" ]; then crit "Root daemon WorkingDirectory writable: $wd ($lf)." "T1543.001"; p9=1; fi
        ev="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables' "$lf" 2>/dev/null)"
        echo "$ev" | grep -qi 'DYLD_' && { warn "Root daemon sets DYLD_* env (injection vector): $lf" "T1574.006"; p9=1; }
        i=1
        while [ "$i" -le 6 ]; do
            a="$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:$i" "$lf" 2>/dev/null)"
            [ -z "$a" ] && break
            case "$a" in /*) if [ -e "$a" ] && [ -w "$a" ]; then crit "Root daemon argument path writable: $a ($lf)." "T1543.001"; p9=1; fi;; esac
            i=$((i+1))
        done
    done
    [ "$p9" -eq 0 ] && none "No writable args/workdir/DYLD env in root LaunchDaemons."

    # ---- P12: ACL-granted write on sensitive paths --------------------------
    subtitle "macOS ACL-granted write access (beyond POSIX)" "T1222.002"
    local p12=0 acl hit pth
    for pth in /etc/sudoers.d /etc/pam.d /Library/LaunchDaemons /Library/LaunchAgents \
               /usr/local/bin "$BREWP/bin" /etc/synthetic.conf /private/etc/hosts; do
        [ -e "$pth" ] || continue
        acl="$(ls -lde "$pth" 2>/dev/null | grep -E '^[[:space:]]*[0-9]+:')"
        [ -z "$acl" ] && continue
        hit="$(printf '%s\n' "$acl" | grep -i 'allow' | grep -iE 'write|add_file|add_subdirectory|delete|append' | grep -iE "user:${CURRENT_USER}( |	)|group:(staff|everyone|admin)( |	)")"
        if [ -n "$hit" ]; then
            warn "ACL grants write to a non-owner principal on $pth:" "T1222.002"
            _suppress || printf '%s\n' "$hit" | sed 's/^/        /'
            p12=1
        fi
    done
    [ "$p12" -eq 0 ] && none "No abusable ACL write grants on checked paths."

    # ---- P13: SIP 'restricted' flag mapping (real vs decoy writables) -------
    subtitle "SIP-protected flags on sensitive paths (context for writables)" "T1518.001"
    local fp
    for pth in /usr/bin/sudo /etc/sudoers /Library/LaunchDaemons /System/Library/LaunchDaemons; do
        [ -e "$pth" ] || continue
        fp="$(stat -f '%Sf' "$pth" 2>/dev/null)"
        [ -n "$fp" ] && data "$pth -> flags=[${fp:-none}]"
    done
    none "(a 'restricted' flag = SIP-protected; ignore 'writable' findings on those)"

    # ---- P16: dangerous group memberships -----------------------------------
    subtitle "Dangerous group memberships" "T1078"
    local mygroups g p16=0
    # Only groups that actually confer elevated capability. NOTE: _appserveradm /
    # _appserverusr are default benign groups on every account - intentionally
    # excluded to avoid false positives.
    mygroups=" $(id -Gn 2>/dev/null) "
    for g in admin _developer _lpadmin wheel com.apple.access_ssh kmem procmod procview; do
        case "$mygroups" in
            *" $g "*)
                p16=1
                case "$g" in
                    admin)       warn "Member of 'admin' (can sudo / escalate to root)." "T1078" ;;
                    _developer)  warn "Member of '_developer' (dtrace/Developer tools - kernel tracing surface)." "T1078" ;;
                    _lpadmin)    warn "Member of '_lpadmin' (printer admin - CUPS config control)." "T1078" ;;
                    kmem|procmod|procview) warn "Member of '$g' (kernel/process memory access)." "T1078" ;;
                    wheel)       lowf "Member of 'wheel' (gid 0 group; not sudo by itself on macOS)." "T1078" ;;
                    com.apple.access_ssh) lowf "Member of 'com.apple.access_ssh' (permitted to SSH in)." "T1078" ;;
                esac ;;
        esac
    done
    [ "$p16" -eq 0 ] && none "No notable privileged group memberships."

    # ---- P17: sudo currently works without a password -----------------------
    subtitle "Live sudo / cached-credential check" "T1548.003"
    if sudo -n true 2>/dev/null; then
        crit "sudo works RIGHT NOW without a password (NOPASSWD or a warm timestamp) - immediate root via 'sudo -s'." "T1548.003"
    else
        none "sudo requires a password (no warm timestamp / not in sudoers)."
    fi

    # ---- P21: writable app holding Full Disk Access (TCC chain) -------------
    subtitle "Writable app with Full Disk Access (TCC privesc chain)" "T1548"
    local tu="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"
    local tsys="/Library/Application Support/com.apple.TCC/TCC.db"
    if have sqlite3 && { [ -r "$tu" ] || [ -r "$tsys" ]; }; then
        local fda app bin bid p21=0
        fda="$( { [ -r "$tu" ] && sqlite3 "$tu" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value IN (2,3)" 2>/dev/null; [ -r "$tsys" ] && sqlite3 "$tsys" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value IN (2,3)" 2>/dev/null; } | sort -u)"
        for app in /Applications/*.app "$HOME_DIR"/Applications/*.app; do
            [ -d "$app" ] || continue
            bid="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null)"
            [ -z "$bid" ] && continue
            if printf '%s\n' "$fda" | grep -qx "$bid"; then
                bin="$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
                if [ -w "$app" ] || { [ -f "$bin" ] && [ -w "$bin" ]; }; then
                    crit "Writable app holds Full Disk Access: $app ($bid) - trojan it to inherit FDA (read TCC.db / all users' data)." "T1548"
                    p21=1
                fi
            fi
        done
        [ "$p21" -eq 0 ] && none "No writable FDA-holding apps."
    else
        none "Cannot evaluate (TCC.db not readable - needs Full Disk Access / root)."
    fi

    # ---- P22: TCC.db writable -----------------------------------------------
    subtitle "Writable TCC database (grant yourself permissions)" "T1548"
    local p22=0
    [ -w "$tu" ]   && { crit "User TCC.db is writable: $tu - insert your own privacy grants." "T1548"; p22=1; }
    [ -w "$tsys" ] && { crit "System TCC.db is writable: $tsys - grant any app any permission." "T1548"; p22=1; }
    [ "$p22" -eq 0 ] && none "TCC databases not writable."

    # ---- P23: SIP custom/partial configuration ------------------------------
    subtitle "SIP custom/partial configuration" "T1518.001"
    local csr nvcsr
    csr="$(csrutil status 2>/dev/null)"
    if echo "$csr" | grep -qiE 'custom|unknown'; then
        warn "SIP reports a CUSTOM configuration (some protections disabled):" "T1518.001"
        _suppress || echo "$csr" | sed 's/^/        /'
    elif echo "$csr" | grep -qi 'disabled'; then
        # Same wording/technique as the SECURITY section's SIP check so the
        # two are recognized as the same finding and not double-counted.
        vuln "SIP is DISABLED - system files & protections can be tampered with." "T1518.001"
    else
        none "SIP configuration is standard (enabled)."
    fi
    nvcsr="$(nvram csr-active-config 2>/dev/null | awk '{print $2}')"
    [ -n "$nvcsr" ] && [ "$nvcsr" != "%00%00%00%00" ] && data "csr-active-config=$nvcsr (non-zero = customized SIP flags)"

    # ---- P14: writable files held open by root processes (thorough) ---------
    subtitle "Writable files open in root processes (thorough)" "T1574"
    if [ "$THOROUGH" -eq 1 ] && have lsof; then
        local rp p14=0
        ps -axo pid,user 2>/dev/null | awk '$2=="root"{print $1}' | head -40 | while read -r rp; do
            lsof -p "$rp" -nP -Fn 2>/dev/null | sed -n 's/^n//p' | grep '^/' | while read -r pth; do
                case "$pth" in /dev/*|/System/*|/usr/lib/*|/private/var/db/*) continue;; esac
                [ -f "$pth" ] && [ -w "$pth" ] && crit "Root pid $rp has a writable open file: $pth" "T1574"
            done
        done
        none "(scanned open files of up to 40 root processes)"
    else
        none "(enable -t to inspect files held open by root processes)"
    fi

    # ---- P15: group-writable root-owned executables in YOUR groups ----------
    # Precise: only executables (owner-exec bit), root-owned, group-writable,
    # AND whose group you actually belong to -> genuinely abusable. This avoids
    # flagging the thousands of group-writable resource files some installers
    # leave behind, and avoids false positives for groups you are not in.
    # Real finding = a root-owned Mach-O you can actually overwrite (verified via
    # [ -w ]); resource files (.strings/CodeResources/XML) are filtered out to
    # avoid a flood, since only overwriting an executable yields code execution.
    subtitle "Group-writable root-owned Mach-O binaries you can overwrite (thorough)" "T1574"
    if [ "$THOROUGH" -eq 1 ]; then
        local myg fg p15=0
        myg=" $(id -Gn 2>/dev/null) "
        while read -r f; do
            [ -n "$f" ] || continue
            [ -w "$f" ] || continue
            fg="$(stat -f '%Sg' "$f" 2>/dev/null)"
            case "$myg" in *" $fg "*) ;; *) continue;; esac
            file "$f" 2>/dev/null | grep -q 'Mach-O' || continue
            warn "Root-owned Mach-O writable by you (group $fg) - overwrite to run code when it launches: $f" "T1574"
            p15=$((p15+1))
        done < <(find /Applications /Library /opt /usr/local -type f -perm -0020 -perm -0100 -user root 2>/dev/null | head -250)
        [ "$p15" -eq 0 ] && none "No group-writable root-owned Mach-O binaries you can overwrite."
    else
        none "(enable -t to find group-writable root-owned executables you can overwrite)"
    fi

    # ---- P18: apps using AuthorizationExecuteWithPrivileges (thorough) ------
    subtitle "Apps using AuthorizationExecuteWithPrivileges (thorough)" "T1548"
    if [ "$THOROUGH" -eq 1 ]; then
        local app bin appn=0
        for app in /Applications/*.app; do
            [ -d "$app" ] || continue
            appn=$((appn+1)); [ "$appn" -gt 80 ] && break
            bin="$app/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist" 2>/dev/null)"
            [ -f "$bin" ] || continue
            otool -Iv "$bin" 2>/dev/null | grep -q 'AuthorizationExecuteWithPrivileges' && warn "Uses deprecated AuthorizationExecuteWithPrivileges (root-exec API): $app" "T1548"
        done
        none "(scan complete)"
    else
        none "(enable -t to detect AuthorizationExecuteWithPrivileges usage)"
    fi
}

###############################################################################
# 20. KNOWN CVE / LPE EXPOSURE  (Features P19, P20)
###############################################################################
enum_cve() {
    title "KNOWN CVE / LOCAL-PRIVESC EXPOSURE"

    local prodver vk
    prodver="$(sw_vers -productVersion 2>/dev/null)"
    vk="$(ver_key "$prodver")"
    subtitle "macOS local-privesc / SIP-bypass CVE exposure (build $prodver)" "T1068"
    # entry: fixed_version|CVE|description  (flag if current OS older than fixed)
    # entry: fixed_version|CVE|description  (flag if current OS older than fixed).
    # Expanded, curated set of notable macOS local-root / SIP / TCC-bypass CVEs.
    local entry fv cve desc tmp any=0
    for entry in \
        "11.0|CVE-2020-9771|mount_apfs TCC bypass (mount snapshot to read protected files)" \
        "11.3|CVE-2021-30657|Gatekeeper/quarantine bypass (shlayer)" \
        "11.6.1|CVE-2021-30892|Shrootless SIP bypass via package post-install scripts" \
        "12.1|CVE-2021-30970|powerdir TCC bypass" \
        "12.3|CVE-2022-22639|root via SoftwareUpdate Install helper" \
        "12.4|CVE-2022-26766|codesign/cert validation bypass" \
        "12.5|CVE-2022-32893|WebKit + kernel chain (in-the-wild)" \
        "13.0|CVE-2022-42821|Achilles Gatekeeper bypass via ACL" \
        "13.4|CVE-2023-32369|Migraine SIP bypass via Migration Assistant" \
        "14.0|CVE-2023-42931|diskutil/SIP local privilege escalation" \
        "14.2|CVE-2023-42945|kernel local privilege escalation" \
        "14.4|CVE-2024-23225|kernel memory LPE (in-the-wild)" \
        "14.4|CVE-2024-23296|RTKit kernel LPE (in-the-wild)" \
        "15.0|CVE-2024-44131|FileProvider TCC bypass (symlink)" \
        "15.2|CVE-2024-54527|kernel local privilege escalation" ; do
        fv="${entry%%|*}"; tmp="${entry#*|}"; cve="${tmp%%|*}"; desc="${tmp#*|}"
        if [ -n "$vk" ] && [ "$vk" -lt "$(ver_key "$fv")" ] 2>/dev/null; then
            warn "$cve potentially applicable: OS $prodver is older than the fixed version $fv - $desc. VERIFY exact patch level." "T1068"
            any=1
        fi
    done
    [ "$any" -eq 0 ] && info "No listed LPE/SIP/TCC CVEs apply to $prodver (keep applying every security update)."
    none "Note: this is a curated, non-exhaustive list - always check Apple's latest security releases."

    # ---- P20: privileged-helper versions + known-vulnerable Sparkle ---------
    subtitle "Third-party privileged helpers (identifier + date)" "T1543.004"
    if [ -d /Library/PrivilegedHelperTools ]; then
        local h hid
        for h in /Library/PrivilegedHelperTools/*; do
            [ -e "$h" ] || continue
            hid="$(codesign -dvvv "$h" 2>&1 | awk -F= '/^Identifier=/{print $2}' | head -1)"
            data "$(basename "$h")  id=${hid:-?}  [$(stat -f '%Sm' "$h" 2>/dev/null)]"
        done
        none "(cross-check these helper identifiers/dates against vendor CVE advisories)"
    else
        none "No privileged helper tools installed."
    fi

    # ---- P20: Sparkle framework version check (real version-based flag) -----
    subtitle "Sparkle auto-update framework version check" "T1574"
    local sp spany=0 sver svk
    while IFS= read -r s; do
        [ -n "$s" ] || continue
        spany=1
        sver="$(defaults read "$s/Resources/Info" CFBundleShortVersionString 2>/dev/null)"
        [ -z "$sver" ] && sver="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$s/Resources/Info.plist" 2>/dev/null)"
        if [ -n "$sver" ]; then
            svk="$(ver_key "$sver")"
            # Sparkle < 1.16.0 = pre-fix era for several update/MITM/XPC CVEs
            # (e.g. CVE-2016-9892 / insecure-update class). 2.x is current.
            if [ -n "$svk" ] && [ "$svk" -lt "$(ver_key 1.16.0)" ] 2>/dev/null; then
                vuln "Vulnerable-era Sparkle $sver (< 1.16.0) in ${s%/Contents/*} - known update/MITM/LPE CVE class. Update the app." "T1574"
            else
                data "Sparkle $sver: ${s%/Contents/Frameworks/*}"
            fi
        else
            data "Sparkle (version unknown): $s"
        fi
    done < <(find /Applications "$HOME_DIR/Applications" -maxdepth 5 -name 'Sparkle.framework' 2>/dev/null | head -25)
    [ "$spany" -eq 0 ] && none "No Sparkle.framework found."
}

###############################################################################
# 21. EXPLOITATION SURFACE & LATERAL MOVEMENT  (Features P24-P29)
###############################################################################
enum_exploit() {
    title "EXPLOITATION SURFACE & LATERAL MOVEMENT"

    # ---- P24: lateral movement recon ----------------------------------------
    subtitle "Kerberos tickets (cached domain creds)" "T1558"
    if have klist; then
        local kt; kt="$(klist 2>/dev/null | grep -iE 'principal|krbtgt|expires|@' | head -15)"
        if [ -n "$kt" ]; then
            warn "Active Kerberos tickets present (reusable for lateral movement):" "T1558"
            _suppress || printf '%s\n' "$kt" | sed 's/^/        /'
        else
            none "No active Kerberos tickets."
        fi
    else
        none "klist not available."
    fi
    subtitle "SSH lateral-movement targets" "T1021.004"
    if [ -f "$HOME_DIR/.ssh/known_hosts" ]; then
        info "known_hosts targets ($(grep -cvE '^\s*$' "$HOME_DIR/.ssh/known_hosts" 2>/dev/null) entries):"
        _suppress || awk '{print $1}' "$HOME_DIR/.ssh/known_hosts" 2>/dev/null | tr ',' '\n' | grep -v '^|' | sort -u | head -25 | sed 's/^/        /'
    fi
    [ -f "$HOME_DIR/.ssh/config" ] && { info "SSH config Host targets:"; _suppress || grep -iE '^[[:space:]]*Host(name)?' "$HOME_DIR/.ssh/config" 2>/dev/null | sed 's/^/        /' | head -20; }

    # ---- P24: saved / recently-connected network servers (lateral targets) --
    subtitle "Saved & recent network servers (SMB/AFP/VNC/FTP)" "T1135"
    local srv
    srv="$( { defaults read com.apple.sidebarlists 2>/dev/null; \
              defaults read "$HOME_DIR/Library/Preferences/com.apple.NetworkBrowser" RecentServers 2>/dev/null; \
              defaults read com.apple.finder FXRecentFolders 2>/dev/null; \
              defaults read com.apple.recentitems 2>/dev/null; } \
            | grep -oiE '(smb|afp|cifs|vnc|ftp|ftps|nfs|ssh|https?)://[^"; )]+' | sort -u | head -25 )"
    if [ -n "$srv" ]; then
        warn "Recently/saved mounted network servers (lateral-movement targets):" "T1135"
        _suppress || printf '%s\n' "$srv" | sed 's/^/        /'
    else
        none "No saved/recent network servers found in preferences."
    fi
    # currently-mounted network shares (live targets)
    mount 2>/dev/null | grep -iE 'smbfs|afpfs|nfs|webdav' | while IFS= read -r m; do
        [ -n "$m" ] && data "mounted now: $m"
    done

    # ---- P27: sensitive env vars in readable processes ----------------------
    subtitle "Sensitive environment variables in readable processes" "T1552"
    local envhits
    envhits="$(ps -axeww 2>/dev/null | grep -oE '(DYLD_[A-Z_]+|[A-Z0-9_]*TOKEN|[A-Z0-9_]*SECRET|[A-Z0-9_]*API[_-]?KEY|[A-Z0-9_]*PASSWORD|AWS_[A-Z_]*KEY)=[^ ]+' | sort -u | head -15)"
    if [ -n "$envhits" ]; then
        printf '%s\n' "$envhits" | while IFS= read -r e; do
            warn "Sensitive env exposed: $(printf '%s' "$e" | sed -E 's/=(.{0,4}).*/=\1…REDACTED/')" "T1552"
        done
    else
        none "No sensitive env vars visible in readable processes."
    fi

    # ---- P25: defense-evasion / tamper indicators ---------------------------
    subtitle "Defense-evasion & tamper indicators" "T1562.001"
    local ar
    ar="$(csrutil authenticated-root status 2>/dev/null)"
    echo "$ar" | grep -qi 'disabled' && warn "Authenticated-root is DISABLED - the sealed system volume can be modified." "T1562.001"
    local xp="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"
    if [ -f "$xp" ]; then
        local xdays xnow xmtime
        xnow="$(date +%s 2>/dev/null)"; xmtime="$(stat -f '%m' "$xp" 2>/dev/null)"
        if [ -n "$xnow" ] && [ -n "$xmtime" ]; then
            xdays="$(( (xnow - xmtime) / 86400 ))"
            [ "$xdays" -gt 60 ] 2>/dev/null && warn "XProtect definitions are stale (~${xdays} days old) - signature AV may be outdated." "T1562.001"
        fi
    fi
    local tccu="$HOME_DIR/Library/Application Support/com.apple.TCC/TCC.db"
    if [ -f "$tccu" ]; then
        local td tnow tmtime
        tnow="$(date +%s 2>/dev/null)"; tmtime="$(stat -f '%m' "$tccu" 2>/dev/null)"
        if [ -n "$tnow" ] && [ -n "$tmtime" ]; then
            td="$(( (tnow - tmtime) / 86400 ))"
            [ "$td" -le 1 ] 2>/dev/null && lowf "User TCC.db modified within the last day (recent permission change - verify it was you)." "T1562.001"
        fi
    fi
    # Security-relevant launchd services that have been DISABLED (defense evasion)
    local dis
    dis="$( { launchctl print-disabled system 2>/dev/null; launchctl print-disabled gui/"$CURRENT_UID" 2>/dev/null; } \
            | grep -iE '=> (disabled|true)' \
            | grep -iE 'security|crowdstrike|sentinel|defender|wdav|fresno|falcon|jamf|qualys|santa|osquery|sophos|eset|carbonblack|netskope|zscaler|socketfilter|alf|auditd|mrt|xprotect|GateKeeper|syspolicy' )"
    if [ -n "$dis" ]; then
        vuln "Security-related launchd service(s) explicitly DISABLED (possible defense evasion):" "T1562.001"
        _suppress || printf '%s\n' "$dis" | sed 's/^/        /' | head -15
    else
        none "No security launchd services found disabled."
    fi
    none "(SIP/Gatekeeper/firewall states are in the SECURITY section)"

    # ---- P26: process-injection surface (thorough) --------------------------
    subtitle "Process-injection surface: debuggable root binaries (thorough)" "T1055"
    if [ "$THOROUGH" -eq 1 ]; then
        local rp rbin seen=""
        ps -axo pid,user,comm 2>/dev/null | awk '$2=="root"{print $1"\t"$3}' | head -50 | while IFS="$(printf '\t')" read -r rp rbin; do
            case "$rbin" in /System/*|/usr/lib*|/usr/libexec/*|/sbin/*|/usr/sbin/*) continue;; esac
            [ -f "$rbin" ] || continue
            if codesign -d --entitlements - "$rbin" 2>/dev/null | grep -q 'get-task-allow'; then
                warn "Root process binary allows task debugging (get-task-allow=true): $rbin (pid $rp) - injection target." "T1055"
            fi
        done
        none "(scan complete)"
    else
        none "(enable -t to find debuggable root processes)"
    fi

    # ---- P28: Mach-O hardening audit (hardened runtime + PIE/ASLR) ----------
    subtitle "Mach-O hardening of running non-Apple root binaries (thorough)" "T1574"
    if [ "$THOROUGH" -eq 1 ]; then
        local rbin hdr weak
        ps -axo user,comm 2>/dev/null | awk '$1=="root"{print $2}' | sort -u | grep -vE '^/System/|^/usr/(lib|libexec|sbin|bin)/|^/sbin/' | head -30 | while IFS= read -r rbin; do
            [ -f "$rbin" ] || continue
            file "$rbin" 2>/dev/null | grep -q 'Mach-O' || continue
            weak=""
            codesign -dv "$rbin" 2>&1 | grep -qi 'runtime' || weak="no-hardened-runtime"
            # PIE/ASLR: Mach-O header flags include 'PIE' when position-independent
            hdr="$(otool -hv "$rbin" 2>/dev/null | tail -1)"
            echo "$hdr" | grep -q 'PIE' || weak="$weak${weak:+, }no-PIE/ASLR"
            [ -n "$weak" ] && lowf "Weak Mach-O hardening ($weak) on root binary: $rbin (eases code injection/exploitation)." "T1574"
        done
        none "(scan complete)"
    else
        none "(enable -t for Mach-O hardening audit of root binaries)"
    fi

    # ---- P29: IR triage timeline --------------------------------------------
    subtitle "Recently added/modified binaries & accounts (IR triage)" "T1070"
    info "Newest files in common drop locations:"
    _suppress || { ls -lt /usr/local/bin "$( [ -n "$(command -v brew)" ] && brew --prefix 2>/dev/null)/bin" /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null | grep -vE '^total|^d|^l|->' | head -12 | sed 's/^/        /'; }
    info "Most recently created local users:"
    _suppress || dscl . -list /Users 2>/dev/null | grep -vE '^_|daemon|nobody|root' | head -10 | sed 's/^/        /'
}

###############################################################################
# Exploitation guidance (Feature P30) - read-only next-step hints
###############################################################################
print_exploit_hints() {
    [ -s "$FINDINGS_FILE" ] || return 0
    _suppress && { :; }   # hints are useful even in findings-only mode
    local msgs; msgs="$(cut -d"$FSEP" -f3 "$FINDINGS_FILE" 2>/dev/null)"
    title "EXPLOITATION GUIDANCE (read-only hints)"
    echo -e "  ${DIM}Suggested manual next steps for confirmed findings. Nothing is executed.${NC}\n"
    local shown=0
    _hint() { echo -e "  ${MAGENTA}->${NC} $1"; shown=1; }
    echo "$msgs" | grep -qiE 'NOPASSWD|sudo works RIGHT NOW|ALL.*sudo permission' && _hint "Passwordless sudo: run 'sudo -s' (or 'sudo /bin/sh') for a root shell."
    echo "$msgs" | grep -qi '/etc/sudoers.d is writable' && _hint "Writable sudoers.d: 'echo \"\$(id -un) ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/zz' then 'sudo -s'."
    echo "$msgs" | grep -qi 'synthetic.conf' && _hint "synthetic.conf: add 'evil<TAB>/path/you/control', reboot, then leverage a root writer to populate '/evil'."
    echo "$msgs" | grep -qiE 'PATH directory is writable|writable binary in PATH' && _hint "Writable PATH dir: plant a trojan named like a command root/others run; wait for execution."
    echo "$msgs" | grep -qiE 'Writable launchd plist|LaunchDaemon|launchd target is writable|Writable .* directories' && _hint "Writable launchd: set the plist Program to your payload; it runs as root on next load/boot ('sudo launchctl load -w <plist>')."
    echo "$msgs" | grep -qi 'Library Validation disabled' && _hint "Lib-validation off: 'DYLD_INSERT_LIBRARIES=/tmp/evil.dylib open -a <App>' to inject."
    echo "$msgs" | grep -qiE 'GTFOBins|shell-escapable' && _hint "SUID GTFOBins: use the binary's documented SUID breakout (e.g. 'vim -c :!/bin/sh', 'find . -exec /bin/sh \\;')."
    echo "$msgs" | grep -qi 'privileged helper' && _hint "Writable helper: replace the helper binary; it is invoked as root over XPC by its client app."
    echo "$msgs" | grep -qiE "docker.sock|'docker' group" && _hint "Docker: 'docker run -v /:/host -it alpine chroot /host sh' for root on the host."
    echo "$msgs" | grep -qi 'Full Disk Access' && _hint "Writable FDA app: trojan its binary; on next launch it runs with Full Disk Access (read TCC.db / other users)."
    echo "$msgs" | grep -qi 'TCC.db is writable' && _hint "Writable TCC.db: sqlite3 INSERT a grant row for your bundle id / service."
    echo "$msgs" | grep -qi 'kcpassword' && _hint "kcpassword: the decoded value above IS the account login password - reuse for sudo/login."
    echo "$msgs" | grep -qi 'periodic' && _hint "Writable periodic: drop a script in the periodic dir; root executes it on the periodic schedule."
    echo "$msgs" | grep -qi 'newsyslog' && _hint "Writable newsyslog: define a rule whose logfile path/mode causes root to create/chmod a target you control."
    echo "$msgs" | grep -qi 'forge a UID-0' && _hint "Writable dslocal: craft a user .plist with UniqueID 0 (or add to admin) under nodes/Default/users."
    echo "$msgs" | grep -qiE 'Kerberos tickets|known_hosts' && _hint "Lateral: reuse Kerberos tickets / known SSH hosts to pivot to other machines."
    [ "$shown" -eq 0 ] && echo -e "  ${DIM}No automated exploitation hints matched the current findings.${NC}"
    echo -e "\n  ${DIM}Always confirm authorization before attempting any of the above.${NC}"
}

###############################################################################
# Summary + risk score (Feature #33)
###############################################################################
print_summary() {
    title "SUMMARY OF NOTABLE FINDINGS"
    if [ ! -s "$FINDINGS_FILE" ]; then
        info "No high-severity issues were automatically flagged. Review section output manually."
        echo ""
        echo -e "${DIM}  Note: absence of automated flags does not mean the host is secure.${NC}"
        echo -e "${DIM}  Re-run with -t for deeper coverage. Validate every finding before reporting.${NC}"
        return
    fi

    cN=$(grep -c '^CRITICAL' "$FINDINGS_FILE" 2>/dev/null); cN=${cN:-0}
    hN=$(grep -c '^HIGH'     "$FINDINGS_FILE" 2>/dev/null); hN=${hN:-0}
    mN=$(grep -c '^MEDIUM'   "$FINDINGS_FILE" 2>/dev/null); mN=${mN:-0}
    lN=$(grep -c '^LOW'      "$FINDINGS_FILE" 2>/dev/null); lN=${lN:-0}
    score=$(( cN*10 + hN*5 + mN*2 + lN*1 ))
    if   [ "$cN" -gt 0 ]; then label="CRITICAL"; lc="$RED"
    elif [ "$hN" -gt 0 ]; then label="HIGH";     lc="$RED"
    elif [ "$mN" -gt 0 ]; then label="MEDIUM";   lc="$YELLOW"
    else                       label="LOW";      lc="$CYAN"; fi

    echo -e "  Overall host risk: ${lc}${BOLD}${label}${NC}  (risk score: ${score})"
    echo -e "  ${RED}CRITICAL: ${cN}${NC}   ${RED}HIGH: ${hN}${NC}   ${YELLOW}MEDIUM: ${mN}${NC}   ${CYAN}LOW: ${lN}${NC}\n"

    _emit_group() { # $1=key $2=color $3=label
        grep "^$1$FSEP" "$FINDINGS_FILE" 2>/dev/null | while IFS="$FSEP" read -r sev tech msg; do
            t=""; [ -n "$tech" ] && t="  ${DIM}[$tech]${NC}"
            echo -e "  ${2}[${3}]${NC} ${2}${msg}${NC}${t}"
        done
    }
    _emit_group "CRITICAL" "$RED" "CRIT"
    _emit_group "HIGH"     "$RED" "VULN"
    _emit_group "MEDIUM"   "$YELLOW" "!"
    _emit_group "LOW"      "$CYAN" "low"

    echo ""
    echo -e "${DIM}  Note: absence of automated flags does not mean the host is secure.${NC}"
    echo -e "${DIM}  Re-run with -t for deeper coverage. Validate every finding before reporting.${NC}"
}

###############################################################################
# Exporters (Features #34 JSON, #35 HTML)
###############################################################################
export_json() {
    [ -n "$JSON_OUT" ] || return 0
    {
        echo "{"
        printf '  "tool": "macEnum v%s",\n' "$VERSION"
        printf '  "author": "%s",\n' "$AUTHOR"
        printf '  "host": "%s",\n' "$(hostname 2>/dev/null)"
        printf '  "generated": "%s",\n' "$(date 2>/dev/null)"
        echo '  "findings": ['
        first=1
        while IFS="$FSEP" read -r sev tech msg; do
            [ -z "$sev" ] && continue
            # Collapse any stray control chars (messages are meant to be
            # single-line) before escaping, so embedded newlines/tabs can
            # never produce invalid JSON.
            msg=$(printf '%s' "$msg" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')
            tech=$(printf '%s' "$tech" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/"/\\"/g')
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    {"severity":"%s","technique":"%s","finding":"%s"}' "$sev" "$tech" "$msg"
        done < "$FINDINGS_FILE"
        printf '\n  ]\n}\n'
    } > "$JSON_OUT" 2>/dev/null
    echo -e "  ${GREEN}[+]${NC} JSON findings written to $JSON_OUT"
}

export_html() {
    [ -n "$HTML_OUT" ] || return 0
    {
        cat <<HEND
<!DOCTYPE html><html><head><meta charset="utf-8"><title>macEnum Report</title>
<style>
body{font-family:-apple-system,Helvetica,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:24px}
h1{color:#58a6ff} .meta{color:#8b949e;font-size:13px;margin-bottom:18px}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:8px;border-bottom:1px solid #30363d;vertical-align:top}
.CRITICAL{color:#ff7b72;font-weight:bold} .HIGH{color:#ff7b72} .MEDIUM{color:#d29922} .LOW{color:#79c0ff}
code{color:#8b949e}
</style></head><body>
<h1>macEnum Security Report</h1>
<div class="meta">Tool macEnum v${VERSION} &middot; Author ${AUTHOR} &middot; Host $(hostname 2>/dev/null) &middot; $(date 2>/dev/null)<br>&copy; ${COPYRIGHT}</div>
<table><tr><th>Severity</th><th>ATT&amp;CK</th><th>Finding</th></tr>
HEND
        while IFS="$FSEP" read -r sev tech msg; do
            [ -z "$sev" ] && continue
            msg=$(printf '%s' "$msg" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            printf '<tr><td class="%s">%s</td><td><code>%s</code></td><td>%s</td></tr>\n' "$sev" "$sev" "${tech:-—}" "$msg"
        done < "$FINDINGS_FILE"
        echo "</table></body></html>"
    } > "$HTML_OUT" 2>/dev/null
    echo -e "  ${GREEN}[+]${NC} HTML report written to $HTML_OUT"
}

###############################################################################
# Section dispatcher (Features #36 selector, #40 timing)
###############################################################################
should_run() {
    local key="$1"
    if [ -n "$ONLY_SECTIONS" ]; then
        echo ",$ONLY_SECTIONS," | grep -q ",$key," || return 1
    fi
    if [ -n "$SKIP_SECTIONS" ]; then
        echo ",$SKIP_SECTIONS," | grep -q ",$key," && return 1
    fi
    return 0
}

run_section() {
    local key="$1" func="$2"
    should_run "$key" || return 0
    local start end
    start=$(date +%s 2>/dev/null)
    "$func"
    if [ "$SHOW_TIMING" -eq 1 ]; then
        end=$(date +%s 2>/dev/null)
        echo -e "${DIM}  [timing] section '$key' took $(( ${end:-0} - ${start:-0} ))s${NC}"
    fi
}

###############################################################################
# Main
###############################################################################
main() {
    : > "$FINDINGS_FILE" 2>/dev/null
    banner
    run_section system      enum_system
    run_section users       enum_users
    run_section privileges  enum_privileges
    run_section privesc     enum_privesc
    run_section privesc2    enum_privesc2
    run_section cve         enum_cve
    run_section launch      enum_launch
    run_section persistence enum_persistence
    run_section processes   enum_processes
    run_section network     enum_network
    run_section apps        enum_applications
    run_section sensitive   enum_sensitive
    run_section discovery   enum_discovery
    run_section secrets     enum_secrets
    run_section browsers    enum_browsers
    run_section security    enum_security
    run_section trust       enum_trust
    run_section defensive   enum_defensive
    run_section hardening   enum_hardening
    run_section permissions enum_permissions
    run_section exploit     enum_exploit
    run_section sysrecon    enum_sysrecon
    run_section containers  enum_containers
    run_section devtools    enum_devtools

    print_summary
    print_exploit_hints
    export_json
    export_html

    echo ""
    title "SCAN COMPLETE"
    echo -e "  ${GREEN}macEnum finished at $(date)${NC}"
    echo -e "  ${MAGENTA}© ${COPYRIGHT}${NC}"
    echo -e "  ${DIM}macEnum.sh v${VERSION} — authored by ${AUTHOR}${NC}\n"
    rm -f "$FINDINGS_FILE" 2>/dev/null
}

if [ -n "$REPORT" ]; then
    main 2>/dev/null | tee "$REPORT"
    echo "[*] Report written to $REPORT"
else
    main 2>/dev/null
fi
# EndOfScript
