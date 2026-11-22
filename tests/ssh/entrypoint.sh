#!/bin/sh
set -e
echo "alice:$(cat /run/secrets/alice_pw)" | chpasswd
for a in 1.1.1.1/32 9.9.9.9/32 10.99.0.1/32; do ip addr add "$a" dev lo; done
dnsmasq
cd /srv/www && python3 -m http.server 80 --bind 10.99.0.1 >/dev/null 2>&1 &
exec /usr/sbin/sshd -D -e
