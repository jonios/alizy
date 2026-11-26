#!/usr/bin/env bash
# Runs as root INSIDE the screenshot container (see shoot.sh). Builds a fake
# "internet" network namespace with real WireGuard servers and a DNS server on
# documentation addresses (RFC 5737: 198.51.100.0/24, 203.0.113.0/24) and a generic
# private LAN (192.168.50.0/24) so the LAN proxy has a local address to show;
# starts the real alizyd, writes demo profiles and starts Xvfb.
set -euo pipefail
N="nsenter --net=/run/netns/inet"

ip link set lo up
ip netns add inet
ip link add eth0 type veth peer name veth1
ip link set veth1 netns inet
ip addr add 192.168.50.23/24 dev eth0
ip link set eth0 up
ip route add default via 192.168.50.1
$N ip link set lo up
$N ip addr add 192.168.50.1/24 dev veth1
$N ip link set veth1 up
$N ip link add dummy0 type dummy
for a in 10 11 12 20 21 22 23 53; do $N ip addr add "198.51.100.$a/32" dev dummy0; done
$N ip link set dummy0 up

# DNS server for the tunnel (198.51.100.53) with the split-tunnel demo domains.
cat > /tmp/records.json <<'EOF'
{
  "bank.example.com": {"A": ["198.51.100.20"], "ttl": 300},
  "www.bank.example.com": {"cname": "bank.example.com", "ttl": 300},
  "media.example.org": {"A": ["198.51.100.21", "198.51.100.22"], "ttl": 120},
  "intranet.example.net": {"A": ["198.51.100.23"], "ttl": 600}
}
EOF
$N python3 /shots/helper.py dns 198.51.100.53 /tmp/records.json /tmp/dns.log &

# Two real WireGuard servers; the third profile's server does not exist.
mkdir -p /home/demo/demo-profiles
server() { # iface port tunnel-net name endpoint
  local sk ck
  sk=$(wg genkey); ck=$(wg genkey)
  $N ip link add "$1" type wireguard
  echo "$sk" > "/tmp/$1.key"
  $N wg set "$1" private-key "/tmp/$1.key" listen-port "$2" peer "$(wg pubkey <<<"$ck")" allowed-ips "$3.2/32"
  $N ip addr add "$3.1/24" dev "$1"
  $N ip link set "$1" up
  cat > "/home/demo/demo-profiles/$4.conf" <<EOF
[Interface]
PrivateKey = $ck
Address = $3.2/32
DNS = 198.51.100.53

[Peer]
PublicKey = $(wg pubkey <<<"$sk")
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $5:$2
PersistentKeepalive = 25
EOF
}
server wgs0 51820 10.66.0 "Frankfurt" 198.51.100.10
server wgs1 51821 10.67.0 "Amsterdam" 198.51.100.11
cat > /home/demo/demo-profiles/Tokyo.conf <<EOF
[Interface]
PrivateKey = $(wg genkey)
Address = 10.68.0.2/32
DNS = 198.51.100.53

[Peer]
PublicKey = $(wg genkey | wg pubkey)
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.40:51820
EOF
chown -R demo: /home/demo/demo-profiles

install -m0755 /dist/alizyd /usr/local/bin/alizyd
mkdir -p /run/alizy
cp /etc/resolv.conf /run/demo-resolv.conf 2>/dev/null || echo "nameserver 192.168.50.1" > /run/demo-resolv.conf
/usr/local/bin/alizyd --dns-backend file --resolv-conf /run/demo-resolv.conf > /tmp/alizyd.log 2>&1 &
for _ in $(seq 1 50); do [[ -S /run/alizy/alizyd.sock ]] && break; sleep 0.2; done
[[ -S /run/alizy/alizyd.sock ]] || { cat /tmp/alizyd.log; exit 1; }

Xvfb :1 -screen 0 1440x900x24 -nolisten tcp > /tmp/xvfb.log 2>&1 &
echo "setup done"
