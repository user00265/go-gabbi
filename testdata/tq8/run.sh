#!/bin/sh
set -eu
export HOME=/tmp/home TQSLDIR=/tmp/tqsl
mkdir -p "$HOME" "$TQSLDIR" /tmp/work
g++ -x c++ -I /reference/trustedqsl-2.8.7/src /fixtures/converter.c -L/usr/lib/trustedqsl -Wl,-rpath,/usr/lib/trustedqsl -ltqsllib -o /tmp/converter
cd /tmp/work

# Disposable CA and certificates, kept strictly inside /tmp/work and never exported.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 \
    -subj '/CN=Disposable Fixture CA/emailAddress=ca@example.org' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1

make_cert() {
    name=$1
    serial=$2
    ext=$3
    openssl req -new -newkey rsa:1024 -nodes -keyout "$name.key" -out "$name.csr" \
        -subj '/1.3.6.1.4.1.12348.1.1=KF0TST/CN=Fixture Operator' \
        -config /fixtures/openssl.cnf >/dev/null 2>&1
    openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -set_serial "$serial" \
        -days 3650 -out "$name.pem" -extfile /fixtures/openssl.cnf -extensions "$ext" >/dev/null 2>&1
    openssl pkcs12 -export -out "$name.p12" -inkey "$name.key" -in "$name.pem" \
        -certfile ca.pem -passout pass:
}

reset_store() {
    rm -rf "$TQSLDIR"
    mkdir -p "$TQSLDIR"
}

make_cert signer 12345 cert_single
make_cert cert_a 12345 cert_a
make_cert cert_b 12346 cert_b

# 1. normal.gabbi
reset_store
/tmp/converter normal /fixtures/contacts.adi /tmp/normal.gabbi signer.p12

# 2. chained.gabbi (fresh store keeps mode mapping independent)
reset_store
/tmp/converter chained /fixtures/contacts.adi /tmp/chained.gabbi signer.p12

# 3. switch.gabbi (Cert A + Cert B, 4 contacts selecting A, A, B, A)
reset_store
/tmp/converter normal /fixtures/switch.adi /tmp/switch.gabbi cert_a.p12 cert_b.p12

# 4. switch-chained.gabbi (same A, A, B, A with chained mode map CW->SSB, SSB->DATA)
reset_store
/tmp/converter chained /fixtures/switch.adi /tmp/switch-chained.gabbi cert_a.p12 cert_b.p12

# 5. dupe-preamble.gabbi (commit W1AW 2026-11-01 to dupe DB, then convert [dupe B, new A])
reset_store
/tmp/converter commit /fixtures/dupe-seed.adi /tmp/dupe-seed.gabbi cert_a.p12 cert_b.p12
/tmp/converter dupe-preamble /fixtures/dupe-preamble.adi /tmp/dupe-preamble.gabbi

# Export only GAbbI text outputs; never copy keys, .p12, or .pem out of /tmp/work.
cp /tmp/normal.gabbi /tmp/chained.gabbi /tmp/switch.gabbi /tmp/switch-chained.gabbi /tmp/dupe-preamble.gabbi /output/
