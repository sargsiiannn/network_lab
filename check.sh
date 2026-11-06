#!/usr/bin/env bash
set -euo pipefail
umask 077
tmp=$(mktemp -d)
server=
trap 'if [[ -n $server ]]; then kill "$server" 2>/dev/null || true; fi; rm -rf "$tmp"' EXIT
./build/check
./keys.sh "$tmp/good" > "$tmp/certs.log" 2>&1 || { cat "$tmp/certs.log"; exit 1; }
./keys.sh "$tmp/untrusted" >> "$tmp/certs.log" 2>&1 || { cat "$tmp/certs.log"; exit 1; }

pair() {
    local name=$1 identity=$2 should_pass=$3 p a=0 b=0
    p=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    ./build/check 1 "$p" "$tmp/good/root.pem" "$tmp/good/east.pem" "$tmp/$name-east" 2>"$tmp/east.log" &
    server=$!
    for _ in {1..100}; do
        if grep -q Listening "$tmp/east.log"; then break; fi
        sleep 0.03
    done
    ./build/check 0 "$p" "$tmp/good/root.pem" "$identity" "$tmp/$name-west" 2>"$tmp/west.log" || a=$?
    wait "$server" || b=$?
    server=
    if [[ $should_pass == yes && $a == 0 && $b == 0 ]]; then
        cmp "$tmp/$name-west" "$tmp/$name-east"
    elif [[ $should_pass == no && $a == 1 && $b == 1 &&
            ! -e $tmp/$name-west && ! -e $tmp/$name-east ]]; then
        return
    else
        cat "$tmp/east.log" "$tmp/west.log" >&2
        return 1
    fi
}
pair one "$tmp/good/west.pem" yes
pair two "$tmp/good/west.pem" yes
pair impostor "$tmp/untrusted/west.pem" no
if cmp -s "$tmp/one-west" "$tmp/two-west"; then exit 1; fi
echo 'PASS authenticated FFDHE, matching fresh keys and announcement/acknowledgment'
