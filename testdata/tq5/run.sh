#!/bin/sh
set -eu
export HOME=/tmp/home TQSLDIR=/tmp/tqsl
mkdir -p "$HOME" "$TQSLDIR" /tmp/work
g++ -x c++ -I /reference/trustedqsl-2.8.7/src /fixtures/generate.c -L/usr/lib/trustedqsl -Wl,-rpath,/usr/lib/trustedqsl -ltqsllib -o /tmp/generate-tq5
cd /tmp/work
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj '/CN=Disposable Fixture CA/emailAddress=ca@example.org' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:1024 -nodes -keyout signer.key -out signer.csr -subj '/1.3.6.1.4.1.12348.1.1=KF0TST/CN=Fixture Operator' -config /fixtures/openssl.cnf
openssl x509 -req -in signer.csr -CA ca.pem -CAkey ca.key -set_serial 12345 -days 3650 -out signer.pem -extfile /fixtures/openssl.cnf -extensions user_cert
openssl pkcs12 -export -out signer.p12 -inkey signer.key -in signer.pem -certfile ca.pem -passout pass:
/tmp/generate-tq5 /tmp/work
cp new.tq5 additional.tq5 signer.pem /output/
