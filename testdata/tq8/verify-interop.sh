#!/bin/sh
# Offline cross-implementation interop verification between go-gabbi and
# Debian TrustedQSL 2.8.7-1. Uses only disposable keys inside a temporary
# directory and never contacts any network service.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/gabbi-interop.XXXXXX")
chmod 700 "$work"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if ! podman image exists localhost/go-gabbi-tq5-fixture; then
    podman build -t localhost/go-gabbi-tq5-fixture -f "$root/testdata/tq5/Containerfile" "$root/testdata/tq5"
fi

echo "==> Step 1: TestInteropGenerate (go-gabbi)"
(cd "$root" && GABBI_INTEROP_DIR="$work" CGO_ENABLED=0 go test -v -run '^TestInteropGenerate$' -count=1 .)

echo "==> Step 2: TrustedQSL 2.8.7-1 checks (offline container)"
podman run --rm --network=none --userns=keep-id \
    -v "$root/testdata/tq8:/fixtures:ro,Z" \
    -v "$work:/work:Z" \
    localhost/go-gabbi-tq5-fixture sh -eu -c '
        export HOME=/tmp/home
        mkdir -p "$HOME"
        g++ -x c++ -I /reference/trustedqsl-2.8.7/src /fixtures/interop.c \
            -L/usr/lib/trustedqsl -Wl,-rpath,/usr/lib/trustedqsl -ltqsllib -o /tmp/interop

        # Check A: import empty-password and password-protected .p12 in isolated TQSLDIRs.
        mkdir -p /tmp/tqsl-a1
        TQSLDIR=/tmp/tqsl-a1 /tmp/interop p12 /work/cert1.p12 ""
        mkdir -p /tmp/tqsl-a2
        TQSLDIR=/tmp/tqsl-a2 /tmp/interop p12 /work/cert1-pass.p12 "testpass"

        # Check B: seed key from cert2.p12, delete cert stores, restore from ca-update.tq6.
        mkdir -p /tmp/tqsl-b
        TQSLDIR=/tmp/tqsl-b /tmp/interop p12 /work/cert2.p12 ""
        rm -f /tmp/tqsl-b/certs/root /tmp/tqsl-b/certs/authorities /tmp/tqsl-b/certs/user
        TQSLDIR=/tmp/tqsl-b /tmp/interop tq6 /work/ca-update.tq6

        # Check C: import both cert1.p12 and cert2.p12, sign contacts.adi to /work/tqsl.gabbi.
        mkdir -p /tmp/tqsl-c
        TQSLDIR=/tmp/tqsl-c /tmp/interop sign /work/cert1.p12 /work/cert2.p12 /work/contacts.adi /work/tqsl.gabbi
    '

echo "==> Step 3: TestInteropVerify (byte-for-byte comparison)"
(cd "$root" && GABBI_INTEROP_DIR="$work" CGO_ENABLED=0 go test -v -run '^TestInteropVerify$' -count=1 .)
