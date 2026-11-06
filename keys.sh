#!/usr/bin/env bash
set -euo pipefail
umask 077
output=${1:-keys}
mkdir -p "$output"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl req -new -x509 -newkey ed25519 -noenc -days 30 -subj /CN=TagLink-lab-CA \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$work/root.key" -out "$output/root.pem"
for role in west east; do
    openssl req -new -newkey ed25519 -noenc -subj "/CN=$role.taglink" \
        -keyout "$work/identity.key" -out "$work/identity.csr"
    purpose=clientAuth
    if [[ $role == east ]]; then purpose=serverAuth; fi
    printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
        "subjectAltName=DNS:$role.taglink" "extendedKeyUsage=$purpose" > "$work/identity.ext"
    openssl x509 -req -in "$work/identity.csr" -days 30 -CA "$output/root.pem" \
        -CAkey "$work/root.key" -CAserial "$work/root.srl" -CAcreateserial \
        -extfile "$work/identity.ext" -out "$work/identity.crt"
    cat "$work/identity.crt" "$work/identity.key" > "$output/$role.pem"
done
