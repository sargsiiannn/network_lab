#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if (( EUID != 0 )); then echo 'Use sudo make integration on Linux.' >&2; exit 1; fi
for command in ip tcpdump ethtool python3 openssl; do command -v "$command" >/dev/null; done
work=$(mktemp -d)
hosts=()
jobs=()
cleanup() {
    local status=$?
    trap - EXIT
    for child in "${jobs[@]}"; do kill "$child" 2>/dev/null || true; done
    for child in "${jobs[@]}"; do wait "$child" 2>/dev/null || true; done
    for host in "${hosts[@]}"; do ip netns del "$host" 2>/dev/null || true; done
    if (( status )); then cat "$work"/*.log >&2 || true; fi
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
left="tl-l-$$"
west="tl-w-$$"
east="tl-e-$$"
right="tl-r-$$"

for node in "$left" "$west" "$east" "$right"; do
    ip netns add "$node"
    hosts+=("$node")
done

cable() {
    local x=$1 a=$2 y=$3 b=$4 mtu=$5
    ip -n "$x" link add "$a" type veth peer name "$b" netns "$y"
    ip -n "$x" link set "$a" mtu "$mtu" up
    ip -n "$y" link set "$b" mtu "$mtu" up
    ip netns exec "$x" ethtool -K "$a" tx off tso off gro off gso off
    ip netns exec "$y" ethtool -K "$b" tx off tso off gro off gso off
}
cable "$left" eth0 "$west" lan 1484
cable "$west" wire "$east" wire 1500
cable "$east" lan "$right" eth0 1484
ip -n "$left" addr add 10.55.0.1/24 dev eth0
ip -n "$right" addr add 10.55.0.2/24 dev eth0
ip -n "$west" addr add 172.27.9.1/30 dev wire
ip -n "$east" addr add 172.27.9.2/30 dev wire

wait_for() {
    for _ in {1..200}; do
        if grep -q "$1" "$2"; then return; fi
        sleep 0.02
    done
    echo "Timed out waiting for $1" >&2
    return 1
}

./keys.sh "$work/keys" >"$work/keys.log" 2>&1
capture() {
    ip netns exec "$west" tcpdump -i "$1" -U -s 0 -w "$work/$1.pcap" \
        'tcp and port 9090' >"$work/$1.log" 2>&1 &
    jobs+=("$!")
    wait_for 'listening on' "$work/$1.log"
}
capture lan
capture wire
ip netns exec "$right" python3 tests/lab.py listen >"$work/server.log" 2>&1 &
server=$!
jobs+=("$server")
wait_for Ready "$work/server.log"
ip netns exec "$east" ./build/taglink east lan wire 172.27.9.2 172.27.9.1 7444 \
    10.55.0.1 10.55.0.2 9090 "$work/keys/root.pem" "$work/keys/east.pem" >"$work/east.log" 2>&1 &
jobs+=("$!")
wait_for Listening "$work/east.log"
ip netns exec "$west" ./build/taglink west lan wire 172.27.9.1 172.27.9.2 7444 \
    10.55.0.1 10.55.0.2 9090 "$work/keys/root.pem" "$work/keys/west.pem" >"$work/west.log" 2>&1 &
jobs+=("$!")
wait_for 'west ready' "$work/west.log"
wait_for 'east ready' "$work/east.log"
ip netns exec "$left" python3 tests/lab.py connect
wait "$server"
kill -INT "${jobs[0]}" "${jobs[1]}"
wait "${jobs[0]}"
wait "${jobs[1]}"
python3 tests/lab.py compare "$work/lan.pcap" "$work/wire.pcap"
