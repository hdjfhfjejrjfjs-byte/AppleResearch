#!/bin/bash
# build.sh — compile every fuzzers/**/*.c into one FuzzHarness app, package
# FuzzHarness.ipa, then optionally sign and install it with plumesign.
# Bash 3.2 compatible (macOS /bin/bash): no mapfile, no associative arrays.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH=arm64
MIN_IOS=14.0
TIMEOUT_SECONDS=${RUN_SECONDS:-60}
APP_NAME=FuzzHarness
PLUMESIGN="${PLUMESIGN:-/Applications/Impactor.app/Contents/MacOS/plumesign}"
SKIP_FUZZERS=${SKIP_FUZZERS-uc_zpfuzz}

BUILD="$ROOT/harness/build"
COMPAT="$BUILD/compat"
OBJ="$BUILD/obj"
PAYLOAD="$BUILD/Payload"
APP="$PAYLOAD/$APP_NAME.app"
IPA="$ROOT/$APP_NAME.ipa"

NO_INSTALL=0
DEVICE_ID="${UDID:-${DEVICE_UDID:-}}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--no-install] [--device UDID] [-h|--help]

Builds every fuzzer under fuzzers/ into one $APP_NAME.ipa, then (unless
--no-install) signs and installs it with plumesign.

Options:
  --no-install       build and package only
  --device, --udid   target device UDID (also: UDID / DEVICE_UDID env)
  -h, --help         show this help

Environment:
  RUN_SECONDS        per-fuzzer timeout in seconds (default 60)
  SKIP_FUZZERS       space-separated fuzzer names or paths to exclude
                     (default "uc_zpfuzz"; set empty to include all)
  PLUMESIGN          plumesign path (default $PLUMESIGN)
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# SKIP_FUZZERS tokens match a source basename without .c, the repo-relative
# path, or that path without .c. Space-separated; empty includes everything.
is_skipped() {
    local _rel="$1" _base _rel_noext _tok
    _base="${_rel##*/}"
    _base="${_base%.c}"
    _rel_noext="${_rel%.c}"
    set -f
    for _tok in $SKIP_FUZZERS; do
        case "$_tok" in
            "$_base"|"$_rel"|"$_rel_noext")
                set +f
                return 0
                ;;
        esac
    done
    set +f
    return 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-install) NO_INSTALL=1 ;;
        --device|--udid)
            [ $# -ge 2 ] || die "$1 requires an argument"
            DEVICE_ID="$2"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

command -v xcrun >/dev/null 2>&1 || die "xcrun not found"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v zip >/dev/null 2>&1 || die "zip not found"
[ -d "$ROOT/fuzzers" ] || die "fuzzers/ not found"
[ -f "$ROOT/harness/main.m" ] || die "harness/main.m not found"
[ -f "$ROOT/harness/Info.plist" ] || die "harness/Info.plist not found"

SDK="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)" || die "iPhoneOS SDK not found"
CLANG="$(xcrun --sdk iphoneos -f clang 2>/dev/null)" || die "clang not found"
[ -n "$SDK" ] && [ -d "$SDK" ] || die "iPhoneOS SDK not found"
[ -n "$CLANG" ] && [ -x "$CLANG" ] || die "clang not found"

log "cleaning $BUILD and $IPA"
rm -rf "$BUILD"
rm -f "$IPA"
mkdir -p "$COMPAT" "$OBJ" "$APP"

DECLS="$BUILD/poc_decls.h"
ENTRIES="$BUILD/poc_entries.h"
: > "$DECLS"
: > "$ENTRIES"

TAB="$(printf '\t')"
RECORDS="$BUILD/poc_records.tsv"
: > "$RECORDS"

# Run order for kPocs: harmless/fast fuzzers first, then io80211/sc246,
# then the panic-heavy ios_iokit/aio, and apfs_xattr last (it idles on iOS
# without /Volumes/SCRATCH). Equal ranks keep alphabetical order; unknown
# files default to the middle.
poc_rank() {
    case "$1" in
        fuzzers/caf/harness.c|\
        fuzzers/opack/http_parse_fuzz.c|\
        fuzzers/opack/opack_extlen.c|\
        fuzzers/opack/opack_fuzz.c|\
        fuzzers/opack/opack_tagmap.c|\
        fuzzers/opack/tlv8_fuzz.c|\
        fuzzers/nfs/uc_zpfuzz.c|\
        fuzzers/nfs/apfs_sel_fuzz.c|\
        fuzzers/kflag/image4_struct_fuzz.c)
            echo 1 ;;
        fuzzers/io80211/apple80211_ioctl_fuzz.c|\
        fuzzers/kflag/sc246_fuzz.c)
            echo 2 ;;
        fuzzers/iokit/ios_iokit_fuzz.c|\
        fuzzers/kflag/aio_fuzz.c)
            echo 3 ;;
        fuzzers/kflag/apfs_xattr_fuzz.c)
            echo 4 ;;
        *) echo 2 ;;
    esac
}

COUNT=0
SKIPPED=0
OBJS=()

log "compiling fuzzers for $ARCH / iOS $MIN_IOS"
while IFS= read -r src; do
    rel="${src#"$ROOT"/}"

    if is_skipped "$rel"; then
        warn "skip $rel (excluded by SKIP_FUZZERS)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    name="${rel%.c}"
    name="${name//\//_}"
    func="poc_$name"

    if ! grep -Eq '(^|[^[:alnum:]_])(int|void)[[:space:]]+main[[:space:]]*\(' "$src"; then
        warn "skipping $rel (no int/void main)"
        continue
    fi

    sed 's/kIOMasterPortDefault/MACH_PORT_NULL/g' "$src" > "$COMPAT/$name.c"

    if "$CLANG" -target "$ARCH-apple-ios$MIN_IOS" -isysroot "$SDK" \
        -fobjc-arc -O1 -w -Dmain="$func" \
        -c "$COMPAT/$name.c" -o "$OBJ/$name.o" 2> "$OBJ/$name.err"; then
        printf '%s\t%s\t%s\n' "$(poc_rank "$rel")" "$rel" "$func" >> "$RECORDS"
        OBJS+=("$OBJ/$name.o")
        COUNT=$((COUNT + 1))
        log "compiled $rel -> $func"
    else
        warn "skipping $rel (compile failed; see $OBJ/$name.err)"
        sed -n '1,3p' "$OBJ/$name.err" >&2 || true
    fi
done < <(find "$ROOT/fuzzers" -type f -name '*.c' | sort)

[ "$COUNT" -gt 0 ] || die "no fuzzers compiled"

log "ordering $COUNT fuzzers by run priority"
LC_ALL=C sort -t "$TAB" -k1,1n -k2,2 "$RECORDS" > "$RECORDS.sorted"
while IFS="$TAB" read -r _rank rel func; do
    printf 'extern int %s(int, char **);\n' "$func" >> "$DECLS"
    printf '    {"%s", %s},\n' "$rel" "$func" >> "$ENTRIES"
done < "$RECORDS.sorted"

log "generating $BUILD/poc_table.h ($COUNT entries)"
{
    printf '#ifndef POC_TABLE_H\n#define POC_TABLE_H\n\n'
    printf 'typedef struct { const char *name; int (*func)(int, char **); } PocEntry;\n\n'
    cat "$DECLS"
    printf '\nstatic const PocEntry kPocs[] = {\n'
    cat "$ENTRIES"
    printf '};\n\nenum { POC_COUNT = %d };\n\n#endif\n' "$COUNT"
} > "$BUILD/poc_table.h"

log "building $APP_NAME.app"
cp "$ROOT/harness/Info.plist" "$APP/Info.plist"
"$CLANG" -target "$ARCH-apple-ios$MIN_IOS" -isysroot "$SDK" \
    -fobjc-arc -O1 -w \
    -DPOC_TIMEOUT_SECONDS="$TIMEOUT_SECONDS" \
    -I "$BUILD" \
    -Wl,-undefined,dynamic_lookup \
    -framework UIKit -framework Foundation -framework IOKit \
    -framework IOSurface -framework Metal -framework AudioToolbox \
    -framework CoreFoundation -framework CoreGraphics -framework Security \
    -o "$APP/$APP_NAME" \
    "$ROOT/harness/main.m" "${OBJS[@]}"
chmod 755 "$APP/$APP_NAME"

log "packaging $IPA"
(cd "$BUILD" && zip -qry "$IPA" Payload)
[ -s "$IPA" ] || die "IPA not created"

log "built $IPA ($COUNT fuzzers, $SKIPPED skipped, ${TIMEOUT_SECONDS}s timeout each)"

if [ "$NO_INSTALL" -eq 1 ]; then
    log "--no-install: skipping sign/install"
    exit 0
fi

[ -x "$PLUMESIGN" ] || die "plumesign not found: $PLUMESIGN"

if [ -z "$DEVICE_ID" ]; then
    log "no UDID given; enumerating USB devices via usbmuxd"
    DEVICE_LINE="$(python3 - <<'PY'
import plistlib, socket, struct, sys

try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/var/run/usbmuxd")
except OSError as exc:
    sys.exit("usbmuxd connect failed: %s" % exc)

body = plistlib.dumps({
    "MessageType": "ListDevices",
    "ClientVersionString": "1",
    "ProgName": "build.sh",
})
sock.sendall(struct.pack("<IIII", 16 + len(body), 1, 8, 1) + body)


def recv_exact(n):
    chunks = []
    while n > 0:
        chunk = sock.recv(n)
        if not chunk:
            raise EOFError("usbmuxd closed connection")
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


length = struct.unpack("<I", recv_exact(16)[:4])[0]
reply = plistlib.loads(recv_exact(length - 16))
found = 0
for dev in reply.get("DeviceList", []):
    props = dev.get("Properties", {})
    if props.get("ConnectionType") != "USB":
        continue
    print("%s\t%s" % (dev.get("DeviceID", ""), props.get("SerialNumber", "")))
    found += 1
if not found:
    sys.exit(1)
PY
    )" || die "no USB device found"

    DEVICE_COUNT="$(printf '%s\n' "$DEVICE_LINE" | wc -l | tr -d ' ')"
    FIRST_DEVICE="${DEVICE_LINE%%$'\n'*}"
    DEVICE_ID="${FIRST_DEVICE%%$'\t'*}"
    [ -n "$DEVICE_ID" ] || die "could not read DeviceID from usbmuxd response"
    if [ "$DEVICE_COUNT" -gt 1 ]; then
        log "multiple USB devices found ($DEVICE_COUNT); using the first"
    fi
    log "usb device: $FIRST_DEVICE (DeviceID $DEVICE_ID)"
fi

SIGN_DIR="$(mktemp -d)"
trap 'rm -rf "$SIGN_DIR"' EXIT
cp "$IPA" "$SIGN_DIR/$APP_NAME.ipa"

log "signing and installing with $PLUMESIGN"
"$PLUMESIGN" sign \
    --package "$SIGN_DIR/$APP_NAME.ipa" \
    --apple-id \
    --register-and-install \
    --udid "$DEVICE_ID"

log "installed and launched $APP_NAME"
log "results: Documents/harness.log on the device"
