#!/bin/bash
#
# update-root-trust-anchors.sh  (v1)
#
# Keeps the DNSSEC root trust anchors of the EdgeRouter's dnsmasq
# ("service dns forwarding") up to date, using IANA's signed trust-anchor file.
#
# Usage:
#   update-root-trust-anchors.sh --check        verify + report only (default)
#   update-root-trust-anchors.sh --apply        add missing anchors (commit + save)
#   update-root-trust-anchors.sh --test-apply   --apply, plus inject ONE harmless fake
#                                               anchor (key tag 65000) to test the
#                                               write path end to end. You must delete
#                                               it afterwards (the command is logged).
#
# Safety properties:
#   * Only ADDS anchors. It never deletes anything from your configuration.
#   * IANA's detached S/MIME signature is verified BEFORE any data is parsed.
#     Because of that, the download path (DNS / https / http) is not trusted.
#   * Any download, verification or parsing problem -> no configuration change.
#   * Needs only tools the EdgeRouter already has: bash, curl, openssl, python
#     (2.7 or 3), vbash. No dig / nslookup / timeout needed.
#

set -u
umask 002

PATH=/usr/sbin:/usr/bin:/sbin:/bin:/opt/vyatta/sbin:/opt/vyatta/bin:/usr/local/bin
export PATH

# =============================================================================
#  USER SETTINGS  -  everything you may want to change is in this block
#
#  Each setting can also be overridden for a single run from the shell, e.g.:
#      LOOKAHEAD_DAYS=60 /config/scripts/trust-anchors-updater/update-root-trust-anchors.sh --check
# =============================================================================

# How many days BEFORE an anchor's "validFrom" date it is added to the router.
# Adding an anchor early is harmless (an anchor for a key that is not in use yet
# is simply ignored by dnsmasq), so a generous value is the safe choice.
# Rule of thumb: keep it at least 3x the interval between scheduled runs
# (weekly schedule -> 21 days or more). Use 0 to add anchors only on/after
# their validFrom date.
LOOKAHEAD_DAYS="${LOOKAHEAD_DAYS:-30}"

# Log file, and how many lines it may grow to before it is trimmed.
LOG="${LOG:-/var/log/update-root-trust-anchors.log}"
LOG_MAX_LINES="${LOG_MAX_LINES:-2000}"
LOG_KEEP_LINES="${LOG_KEEP_LINES:-1000}"

# If the router's own DNS cannot resolve data.iana.org (which is exactly what
# happens when a root anchor is missing and DNSSEC validation fails), the script
# asks these DNS servers directly (plain DNS, UDP port 53) for the IP address
# of data.iana.org and connects to that IP. Space separated list.
FALLBACK_DNS_SERVERS="${FALLBACK_DNS_SERVERS:-1.1.1.1 9.9.9.9 8.8.8.8}"

# Also try plain http:// if https:// fails (1 = yes, 0 = no). This is safe
# because the files are signature-verified; it helps if the router's
# CA-certificate bundle is outdated and https fails.
ALLOW_HTTP_FALLBACK="${ALLOW_HTTP_FALLBACK:-1}"

# Maximum seconds for each single download attempt.
CURL_MAX_TIME="${CURL_MAX_TIME:-40}"

# Optional file containing the ICANN root CA certificate (PEM). If this file
# exists and is not empty, it is used INSTEAD of the certificate embedded in this
# script. This is how you replace the certificate without editing the script.
CA_OVERRIDE_FILE="${CA_OVERRIDE_FILE:-/config/scripts/trust-anchors-updater/icann-root-ca.pem}"

# Log a warning when the CA certificate expires within this many days.
CA_WARN_DAYS="${CA_WARN_DAYS:-180}"

# 1 = run the vbash commands through "sg vyattacfg" (makes any file that EdgeOS
# creates belong to group vyattacfg). Leave at 0 unless the permissions of
# /config/config.boot are wrong after a --test-apply (the script warns about it).
USE_SG="${USE_SG:-0}"

# Seconds to wait for a vbash command before giving up.
VBASH_TIMEOUT="${VBASH_TIMEOUT:-120}"

# Saved (persistent) EdgeOS configuration file.
SAVED_CFG="${SAVED_CFG:-/config/config.boot}"

# After applying changes: ask this DNS server for DNS_TEST_NAME and log whether
# it answers (1 = do the test, 0 = skip). Set DNS_TEST_SERVER to the router's
# LAN IP (e.g. 192.168.1.1) if dnsmasq does not listen on 127.0.0.1.
ENABLE_DNS_TEST="${ENABLE_DNS_TEST:-1}"
DNS_TEST_SERVER="${DNS_TEST_SERVER:-127.0.0.1}"
DNS_TEST_NAME="${DNS_TEST_NAME:-iana.org}"

# 1 = log a NOTICE for configured anchors that IANA marks as expired.
# (Report only: the script never deletes anything.)
REPORT_STALE="${REPORT_STALE:-1}"

# Optional: a command that is called with the message as its only argument on
# every warning or error (for e-mail, push notification, healthcheck ping...).
# Example: NOTIFY_CMD="/config/scripts/trust-anchors-updater/my-notify.sh"
# Note: it cannot reach the internet if DNS is the thing that is broken.
NOTIFY_CMD="${NOTIFY_CMD:-}"

# Refuse to run if the router clock shows a year earlier than this
# (certificate and date checks need a correct clock).
MIN_CLOCK_YEAR="${MIN_CLOCK_YEAR:-2025}"

# --- advanced / testing ---
# 1 = skip the router's own DNS and use FALLBACK_DNS_SERVERS right away
# (lets you test the fallback path).
FORCE_FALLBACK="${FORCE_FALLBACK:-0}"
# UDP port for DNS queries (testing only).
DNS_PORT="${DNS_PORT:-53}"
LOCKDIR="${LOCKDIR:-/var/run/update-root-trust-anchors.lock}"
IANA_HOST="data.iana.org"
TAG="root-anchors"

# =============================================================================
#  END OF USER SETTINGS
# =============================================================================

APPLY=0
TESTAPPLY=0
TMP=""
LOCK_OWNED=0

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOG"
}

syslog() {   # level message
    if command -v logger >/dev/null 2>&1; then
        logger -t "$TAG" -p "daemon.$1" "$2" 2>/dev/null
    fi
    return 0
}

notify() {
    if [ -n "$NOTIFY_CMD" ]; then
        $NOTIFY_CMD "$1" >/dev/null 2>&1 || true
    fi
    return 0
}

warn() {
    log "WARNING: $*"
    syslog warning "$*"
    notify "WARNING: $*"
}

fail() {
    log "ERROR: $*"
    syslog err "$*"
    notify "ERROR: $*"
    exit 1
}

cleanup() {
    if [ -n "$TMP" ]; then
        rm -rf "$TMP"
    fi
    if [ "$LOCK_OWNED" -eq 1 ]; then
        rm -rf "$LOCKDIR"
    fi
    return 0
}

# EXIT runs on every exit path (normal, fail(), and the signals below).
# For signals we must call exit ourselves, otherwise bash would continue the
# script after the trap handler returns.
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

usage() {
    echo "Usage: $0 [--check|--apply|--test-apply]"
}

# ------------------------------ arguments ----------------------------------
if [ "$#" -gt 1 ]; then usage; exit 2; fi
case "${1:-}" in
    ""|--check)   APPLY=0 ;;
    --apply)      APPLY=1 ;;
    --test-apply) APPLY=1; TESTAPPLY=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            usage; exit 2 ;;
esac

MODE=check
[ "$APPLY" -eq 1 ] && MODE=apply
[ "$TESTAPPLY" -eq 1 ] && MODE=test-apply

case "$LOOKAHEAD_DAYS" in
    ""|*[!0-9]*) echo "LOOKAHEAD_DAYS must be a non-negative integer"; exit 2 ;;
esac

# ------------------------------ lock / log ---------------------------------
acquire_lock() {
    local old
    if mkdir "$LOCKDIR" 2>/dev/null; then
        LOCK_OWNED=1
        echo "$$" > "$LOCKDIR/pid"
        return 0
    fi
    old="$(cat "$LOCKDIR/pid" 2>/dev/null)"
    if [ -z "$old" ]; then
        sleep 1
        old="$(cat "$LOCKDIR/pid" 2>/dev/null)"
    fi
    if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
        log "Another instance (pid $old) is already running; exiting."
        exit 0
    fi
    log "Removing stale lock"
    rm -rf "$LOCKDIR"
    mkdir "$LOCKDIR" 2>/dev/null || fail "Could not acquire lock $LOCKDIR"
    LOCK_OWNED=1
    echo "$$" > "$LOCKDIR/pid"
}

rotate_log() {
    local n
    [ -f "$LOG" ] || return 0
    n="$(wc -l < "$LOG" 2>/dev/null | tr -d ' ')"
    case "$n" in ""|*[!0-9]*) return 0 ;; esac
    if [ "$n" -gt "$LOG_MAX_LINES" ]; then
        if tail -n "$LOG_KEEP_LINES" "$LOG" > "$LOG.tmp" 2>/dev/null; then
            cat "$LOG.tmp" > "$LOG"
        fi
        rm -f "$LOG.tmp"
    fi
    return 0
}

acquire_lock
rotate_log

# Remove temp dirs left behind by earlier runs that were killed (SIGKILL, power loss).
find /tmp -maxdepth 1 -name 'root-anchor-update.*' -mmin +60 -exec rm -rf {} + 2>/dev/null

# --------------------------- preflight checks ------------------------------
for cmd in curl openssl vbash grep sed awk date mktemp tail head wc tr find sleep kill; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: $cmd"
done

PY=""
for c in python3 python python2; do
    if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || fail "No python interpreter found (tried python3, python, python2)"

TODAY="$(date -u '+%Y-%m-%d')"
case "${TODAY%%-*}" in
    ""|*[!0-9]*) fail "Could not determine the date" ;;
esac
if [ "${TODAY%%-*}" -lt "$MIN_CLOCK_YEAR" ]; then
    fail "System clock looks wrong ($TODAY). Check NTP; refusing to continue."
fi

TMP="$(mktemp -d /tmp/root-anchor-update.XXXXXX)" || fail "Could not create temporary directory"

XML="$TMP/root-anchors.xml"
SIG="$TMP/root-anchors.p7s"
CA="$TMP/icann-root-ca.pem"
PYFILE="$TMP/parse_anchors.py"
DNSPY="$TMP/dnstool.py"
ANCHORS="$TMP/eligible-anchors.txt"
EXPIRED="$TMP/expired-anchors.txt"
REPORT="$TMP/anchor-report.txt"
CURRENT="$TMP/current-config.txt"
NEED_SET="$TMP/need-set.txt"
NEED_SAVE="$TMP/need-save.txt"
CURLERR="$TMP/curl.err"
VERIFYERR="$TMP/verify.err"
: > "$CURLERR"

log "---- start: mode=$MODE, lookahead=${LOOKAHEAD_DAYS}d, python=$PY ----"

# =============================================================================
#  EMBEDDED ICANN ROOT CA CERTIFICATE  -  PLEASE READ
#
#  IANA signs root-anchors.xml with a certificate that chains to the "ICANN Root
#  CA" below. This script trusts ONLY this certificate to decide whether the
#  downloaded anchor list is genuine.
#
#  This certificate is valid until 2029-12-18. If ICANN ever replaces it (or it
#  expires) signature verification will start FAILING. The script then makes NO
#  changes and writes a clear "CERTIFICATE PROBLEM" ERROR to its log and to
#  syslog (grep root-anchors /var/log/messages).
#
#  TO REPLACE THE CERTIFICATE - you do NOT have to edit this script:
#    1. Get the current ICANN root CA certificate in PEM format from IANA's
#       trust-anchor publication page (https://www.iana.org/dnssec/files;
#       the file is called icannbundle.pem or icann-ca.pem).
#    2. Save it on the router as /config/scripts/trust-anchors-updater/icann-root-ca.pem
#       (see CA_OVERRIDE_FILE in the settings above). If that file exists the
#       script uses it instead of the certificate below.
#  (Alternatively, replace the PEM block below with the new one.)
# =============================================================================
write_embedded_ca() {
cat > "$CA" <<'CERT'
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO
TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV
BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX
DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB
MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb
cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S
G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg
ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2
paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7
MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29
iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3
DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH
6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD
2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h
15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF
0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg
j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk
-----END CERTIFICATE-----
CERT
}

if [ -s "$CA_OVERRIDE_FILE" ]; then
    cp "$CA_OVERRIDE_FILE" "$CA" || fail "Could not copy $CA_OVERRIDE_FILE"
    CA_SRC="override file $CA_OVERRIDE_FILE"
else
    write_embedded_ca
    CA_SRC="embedded certificate"
fi

openssl x509 -in "$CA" -noout >/dev/null 2>&1 ||
    fail "CERTIFICATE PROBLEM: the CA certificate ($CA_SRC) is not a valid PEM certificate. Replace it (see the notes next to the embedded certificate in this script)."
if ! openssl x509 -in "$CA" -noout -checkend 0 >/dev/null 2>&1; then
    warn "CERTIFICATE PROBLEM: the ICANN CA certificate ($CA_SRC) has EXPIRED. Replace it: save the current ICANN root CA PEM as $CA_OVERRIDE_FILE."
elif ! openssl x509 -in "$CA" -noout -checkend $((CA_WARN_DAYS * 86400)) >/dev/null 2>&1; then
    warn "The ICANN CA certificate ($CA_SRC) expires within $CA_WARN_DAYS days. Plan to replace it: save the current ICANN root CA PEM as $CA_OVERRIDE_FILE."
fi

# ------------------ tiny built-in DNS client (python 2/3) ------------------
# Replaces dig/nslookup, which the EdgeRouter does not have.
#   resolve <host> <server>   print the first IPv4 address of <host>
#   test <server> <name>      query with DNSSEC flags; print rcode / AD flag
cat > "$DNSPY" <<'PY'
from __future__ import print_function
import os
import random
import socket
import struct
import sys

PORT = int(os.environ.get("DNS_PORT", "53"))

def build(name, do):
    qid = random.randint(0, 65535)
    flags = 0x0100 | (0x0020 if do else 0)           # RD (+ AD requested)
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 1 if do else 0)
    question = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        question += struct.pack("!B", len(enc)) + enc
    question += b"\x00" + struct.pack("!HH", 1, 1)  # type A, class IN
    extra = b""
    if do:                                           # EDNS0 OPT record, DO bit
        extra = b"\x00" + struct.pack("!HHIH", 41, 4096, 0x00008000, 0)
    return qid, header + question + extra

def skip_name(data, off):
    while True:
        length = ord(data[off:off + 1])
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length

def parse(data):
    flags = struct.unpack("!H", data[2:4])[0]
    rcode = flags & 0xF
    ad = 1 if flags & 0x0020 else 0
    qd, an = struct.unpack("!HH", data[4:8])
    off = 12
    for _ in range(qd):
        off = skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = skip_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(ord(data[off + i:off + i + 1])) for i in range(4)))
        off += rdlen
    return rcode, ad, ips

def query(server, name, do, timeout):
    qid, packet = build(name, do)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, PORT))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                return data
    finally:
        sock.close()

try:
    mode = sys.argv[1]
    if mode == "resolve":
        rcode, ad, ips = parse(query(sys.argv[3], sys.argv[2], False, 4))
        if rcode == 0 and ips:
            print(ips[0])
            sys.exit(0)
        sys.exit(1)
    if mode == "test":
        rcode, ad, ips = parse(query(sys.argv[2], sys.argv[3], True, 5))
        print("rcode=%d ad=%d answers=%d" % (rcode, ad, len(ips)))
        sys.exit(0 if rcode == 0 else 1)
except Exception as e:
    sys.stderr.write("dns error: %s\n" % e)
    sys.exit(2)
sys.exit(2)
PY

resolve_ip() {   # host dns-server -> prints an IPv4 address or nothing
    "$PY" "$DNSPY" resolve "$1" "$2" 2>/dev/null |
        grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | head -1
}

# ------------------------------ download -----------------------------------
curl_get() {   # scheme filename outfile [resolve-spec]
    local url="${1}://${IANA_HOST}/root-anchors/${2}"
    local args=(--fail --silent --show-error --location --max-redirs 3
                --connect-timeout 10 --max-time "$CURL_MAX_TIME")
    if [ -n "${4:-}" ]; then
        args+=(--resolve "$4")
    fi
    curl "${args[@]}" "$url" -o "$3" 2>>"$CURLERR"
}

DL_METHOD=""
fetch_one() {   # filename outfile
    local name="$1" out="$2" scheme schemes srv ip port
    schemes="https"
    [ "$ALLOW_HTTP_FALLBACK" = "1" ] && schemes="https http"
    for scheme in $schemes; do
        if [ "$FORCE_FALLBACK" != "1" ]; then
            rm -f "$out"
            if curl_get "$scheme" "$name" "$out" ""; then
                DL_METHOD="$scheme via the router's DNS"
                return 0
            fi
        fi
        port=443
        [ "$scheme" = "http" ] && port=80
        for srv in $FALLBACK_DNS_SERVERS; do
            ip="$(resolve_ip "$IANA_HOST" "$srv")"
            [ -n "$ip" ] || continue
            rm -f "$out"
            if curl_get "$scheme" "$name" "$out" "$IANA_HOST:$port:$ip"; then
                DL_METHOD="$scheme via DNS server $srv ($ip)"
                return 0
            fi
        done
    done
    return 1
}

log "Downloading IANA trust-anchor XML and detached signature"
if ! fetch_one "root-anchors.xml" "$XML"; then
    log "curl said: $(tail -n 3 "$CURLERR" | tr '\n' ' ')"
    fail "Could not download root-anchors.xml (tried the router's DNS and fallback DNS servers). No configuration changes made."
fi
log "root-anchors.xml downloaded: $DL_METHOD"
if ! fetch_one "root-anchors.p7s" "$SIG"; then
    log "curl said: $(tail -n 3 "$CURLERR" | tr '\n' ' ')"
    fail "Could not download root-anchors.p7s. No configuration changes made."
fi
log "root-anchors.p7s downloaded: $DL_METHOD"

[ -s "$XML" ] || fail "Downloaded XML is empty"
[ -s "$SIG" ] || fail "Downloaded signature is empty"
[ "$(wc -c < "$XML" | tr -d ' ')" -lt 1048576 ] || fail "Downloaded XML is unexpectedly large"
[ "$(wc -c < "$SIG" | tr -d ' ')" -lt 1048576 ] || fail "Downloaded signature is unexpectedly large"

# --------------------------- signature check -------------------------------
verify_signature() {
    : > "$VERIFYERR"
    if openssl smime -verify -CAfile "$CA" -inform DER -in "$SIG" \
            -content "$XML" -out /dev/null >/dev/null 2>>"$VERIFYERR"; then
        return 0
    fi
    # Fallback for OpenSSL builds where "smime" misbehaves (best effort).
    if openssl cms -verify -CAfile "$CA" -inform DER -in "$SIG" \
            -content "$XML" -out /dev/null >/dev/null 2>>"$VERIFYERR"; then
        log "Signature verified using 'openssl cms' (smime failed)"
        return 0
    fi
    return 1
}

diagnose_verify_error() {
    local e
    e="$(cat "$VERIFYERR" 2>/dev/null)"
    if echo "$e" | grep -qiE 'not yet valid'; then
        fail "Signature verification FAILED: a certificate is 'not yet valid'. The router clock is probably wrong - check NTP. No configuration changes made."
    elif echo "$e" | grep -qiE 'expired|issuer|self[ -]signed|certificate verify error|untrusted|unable to get'; then
        fail "CERTIFICATE PROBLEM: the ICANN root CA ($CA_SRC) no longer validates IANA's signature (it has probably expired or been replaced). ACTION: save the current ICANN root CA PEM from IANA as $CA_OVERRIDE_FILE (details are in the comments next to the embedded certificate in this script). No configuration changes made."
    elif echo "$e" | grep -qiE 'signature failure|digest failure|content verify|verification failure'; then
        fail "Signature verification FAILED: the downloaded XML does not match its signature (corrupted download or tampering). The CA certificate is probably fine; the next run will retry. No configuration changes made."
    else
        fail "Signature verification FAILED for an unknown reason (see the openssl output above). No configuration changes made."
    fi
}

log "Verifying IANA XML signature (CA: $CA_SRC)"
if ! verify_signature; then
    log "openssl said: $(tail -n 4 "$VERIFYERR" | tr '\n' ' ')"
    diagnose_verify_error
fi
log "Signature OK"

# ------------------------------ parse XML ----------------------------------
cat > "$PYFILE" <<'PY'
from __future__ import print_function
import sys
import datetime
import xml.etree.ElementTree as ET

xml_path, today_s, lookahead_s, report_path, expired_path = sys.argv[1:6]
today = datetime.datetime.strptime(today_s, "%Y-%m-%d").date()
cutoff = today + datetime.timedelta(days=int(lookahead_s))
DIGEST_LEN = {"1": 40, "2": 64, "4": 96}   # SHA-1, SHA-256, SHA-384

try:
    root = ET.parse(xml_path).getroot()
except Exception as e:
    sys.stderr.write("XML parse error: %s\n" % e)
    sys.exit(2)

def localname(tag):
    return tag.split("}")[-1]

def child_text(parent, wanted):
    for node in list(parent):
        if localname(node.tag) == wanted:
            return (node.text or "").strip()
    return ""

def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    return datetime.datetime.strptime(s[:10], "%Y-%m-%d").date()

report = []
expired = []
found = 0
for node in root.iter():
    if localname(node.tag) != "KeyDigest":
        continue
    tag = child_text(node, "KeyTag")
    alg = child_text(node, "Algorithm")
    dtype = child_text(node, "DigestType")
    digest = child_text(node, "Digest")
    vf = node.attrib.get("validFrom", "").strip()
    vu = node.attrib.get("validUntil", "").strip()
    label = "KeyTag %s alg %s digest-type %s validFrom %s validUntil %s" % (
        tag or "?", alg or "?", dtype or "?", vf[:10] or "-", vu[:10] or "-")

    # Fail closed on anything malformed.
    ok = tag.isdigit() and alg.isdigit() and dtype.isdigit() and bool(vf)
    ok = ok and len(digest) >= 32 and all(c in "0123456789abcdefABCDEF" for c in digest)
    if ok and dtype in DIGEST_LEN and len(digest) != DIGEST_LEN[dtype]:
        ok = False
    from_date = until_date = None
    try:
        from_date = parse_date(vf)
        until_date = parse_date(vu)
    except ValueError:
        ok = False
    if not ok or from_date is None:
        report.append("%s => SKIPPED (malformed record)" % label)
        continue

    item = "%s,%s,%s,%s" % (tag, alg, dtype, digest.upper())
    if until_date is not None and until_date < today:
        report.append("%s => ignored (expired)" % label)
        expired.append(item)
        continue
    if from_date > cutoff:
        report.append("%s => not eligible yet (starts in %d days)" % (
            label, (from_date - today).days))
        continue

    report.append("%s => ELIGIBLE" % label)
    print(item)
    found += 1

with open(report_path, "w") as fh:
    for line in report:
        fh.write(line + "\n")
with open(expired_path, "w") as fh:
    for line in expired:
        fh.write(line + "\n")

if found == 0:
    sys.stderr.write("No eligible trust anchors found; refusing to continue.\n")
    sys.exit(3)
PY

"$PY" "$PYFILE" "$XML" "$TODAY" "$LOOKAHEAD_DAYS" "$REPORT" "$EXPIRED" > "$ANCHORS"
PARSE_RC=$?
[ "$PARSE_RC" -eq 0 ] || fail "Could not parse eligible anchors safely (python exit code $PARSE_RC)"

log "Anchors found in the signed IANA data (lookahead ${LOOKAHEAD_DAYS} days):"
while IFS= read -r line; do
    log "  $line"
done < "$REPORT"

TEST_ANCHOR_ITEM=""
if [ "$TESTAPPLY" -eq 1 ]; then
    TEST_ANCHOR_ITEM="65000,8,2,$(printf '%064d' 0)"
    echo "$TEST_ANCHOR_ITEM" >> "$ANCHORS"
    warn "TEST MODE: injecting harmless fake anchor .,$TEST_ANCHOR_ITEM"
fi

# ------------------------ read current configuration -----------------------
# Run a command with a time limit (the router has no "timeout" command).
run_timeout() {   # seconds command [args...]
    local limit="$1" pid i=0
    shift
    "$@" </dev/null &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$i" -ge "$limit" ]; then
            kill -TERM "$pid" 2>/dev/null
            sleep 1
            kill -KILL "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            return 124
        fi
        sleep 1
        i=$((i + 1))
    done
    wait "$pid"
}

run_vbash() {   # one command string
    local cmd="$1"
    if [ "$USE_SG" = "1" ] && command -v sg >/dev/null 2>&1; then
        run_timeout "$VBASH_TIMEOUT" sg vyattacfg -c "vbash -ic '$cmd'"
    else
        run_timeout "$VBASH_TIMEOUT" vbash -ic "$cmd"
    fi
}

read_running_config() {
    run_vbash 'show configuration commands' > "$CURRENT" 2>/dev/null || return 1
    grep -q '^set ' "$CURRENT"
}

# Substring match, case-insensitive: works whether EdgeOS quotes the value or not.
anchor_in() {   # file anchor
    grep -Fqi -e "trust-anchor=$2" "$1" 2>/dev/null
}

SAVED_READABLE=1
if [ ! -r "$SAVED_CFG" ]; then
    SAVED_READABLE=0
    warn "Cannot read $SAVED_CFG; can only check the running configuration, not the saved one"
fi

anchor_in_saved() {
    [ "$SAVED_READABLE" -eq 1 ] || return 0
    anchor_in "$SAVED_CFG" "$1"
}

read_running_config || fail "Could not read the EdgeOS configuration using vbash (timeout ${VBASH_TIMEOUT}s)"

: > "$NEED_SET"
: > "$NEED_SAVE"
while IFS= read -r item; do
    anchor=".,$item"
    in_run=0; in_saved=0
    anchor_in "$CURRENT" "$anchor" && in_run=1
    anchor_in_saved "$anchor" && in_saved=1
    if [ "$in_run" -eq 0 ]; then
        echo "$anchor" >> "$NEED_SET"
    elif [ "$in_saved" -eq 0 ]; then
        echo "$anchor" >> "$NEED_SAVE"
    fi
done < "$ANCHORS"

# Report (never delete) configured anchors that IANA marks as expired.
if [ "$REPORT_STALE" = "1" ] && [ -s "$EXPIRED" ]; then
    while IFS= read -r item; do
        anchor=".,$item"
        if anchor_in "$CURRENT" "$anchor"; then
            log "NOTICE: expired anchor still configured (harmless; remove it manually if you like): configure; delete service dns forwarding options trust-anchor=$anchor; commit; save; exit"
        fi
    done < "$EXPIRED"
fi

if [ ! -s "$NEED_SET" ] && [ ! -s "$NEED_SAVE" ]; then
    log "No missing eligible anchors (running and saved config both up to date). No changes needed."
    exit 0
fi

if [ -s "$NEED_SET" ]; then
    log "Missing from the running configuration:"
    while IFS= read -r a; do log "  $a"; done < "$NEED_SET"
fi
if [ -s "$NEED_SAVE" ]; then
    warn "Present in the running configuration but NOT saved (would be lost at reboot):"
    while IFS= read -r a; do log "  $a"; done < "$NEED_SAVE"
fi

if [ "$APPLY" -ne 1 ]; then
    log "CHECK ONLY: no changes made. Run with --apply to fix this."
    exit 0
fi

# ------------------------------ apply --------------------------------------
# Validate every anchor before it is placed into a CLI command.
for f in "$NEED_SET" "$NEED_SAVE"; do
    while IFS= read -r a; do
        echo "$a" | grep -Eq '^\.,[0-9]+,[0-9]+,[0-9]+,[A-F0-9]+$' ||
            fail "Unexpected anchor format ($a); refusing to modify configuration"
    done < "$f"
done

CMD="configure;"
if [ -s "$NEED_SET" ]; then
    while IFS= read -r a; do
        CMD="$CMD set service dns forwarding options trust-anchor=$a;"
    done < "$NEED_SET"
    CMD="$CMD commit && save; exit discard"
else
    CMD="$CMD save; exit discard"
fi

log "Applying changes to the EdgeOS configuration (commit + save)"
run_vbash "$CMD" >> "$LOG" 2>&1 ||
    fail "EdgeOS configuration command reported an error or timed out. Review $LOG and check the router configuration."

# ------------------------------ verify -------------------------------------
read_running_config || fail "Could not re-read the running configuration after applying changes"

for f in "$NEED_SET" "$NEED_SAVE"; do
    while IFS= read -r a; do
        anchor_in "$CURRENT" "$a" ||
            fail "Anchor is not in the running config after apply: $a"
        anchor_in_saved "$a" ||
            fail "Anchor is in the running config but was NOT saved to $SAVED_CFG: $a"
    done < "$f"
done
log "Update completed and verified in the running and saved EdgeOS configuration."

# Config file ownership sanity check (running vbash as root can change it).
# Note: the router's ls truncates the group name to "vyattacf".
if [ -e "$SAVED_CFG" ]; then
    perm="$(ls -l "$SAVED_CFG" 2>/dev/null)"
    log "Saved config file: $perm"
    case "$perm" in
        *vyattacf*) ;;
        *) warn "$SAVED_CFG does not belong to group vyattacfg. If admin users can no longer commit/save, set USE_SG=1 in the settings of this script or run: chgrp vyattacfg $SAVED_CFG" ;;
    esac
fi

# Informational DNS test (does not affect the exit status).
if [ "$ENABLE_DNS_TEST" = "1" ]; then
    sleep 3
    dnsout="$("$PY" "$DNSPY" test "$DNS_TEST_SERVER" "$DNS_TEST_NAME" 2>&1)"
    dnsrc=$?
    case "$dnsrc" in
        0) log "DNS test ($DNS_TEST_NAME via $DNS_TEST_SERVER): OK ($dnsout; ad=1 means DNSSEC-validated)" ;;
        1) warn "DNS test ($DNS_TEST_NAME via $DNS_TEST_SERVER) returned an error ($dnsout). If rcode=2 (SERVFAIL) persists, DNSSEC validation is failing - check the trust anchors." ;;
        *) log "DNS test: no usable answer from $DNS_TEST_SERVER ($dnsout). dnsmasq may not listen there - set DNS_TEST_SERVER to the router's LAN IP, or test from a LAN client." ;;
    esac
fi

if [ -n "$TEST_ANCHOR_ITEM" ]; then
    log "TEST MODE: remove the fake test anchor with:"
    log "  configure; delete service dns forwarding options trust-anchor=.,$TEST_ANCHOR_ITEM; commit; save; exit"
fi

exit 0
