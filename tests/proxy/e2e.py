#!/usr/bin/env python3
"""End-to-end checks for proxy mode, the kill-switch rule and VPN sharing
(authentication, UDP) against the REAL alizyd and a REAL WireGuard server.

Runs as root inside the isolated screenshot environment (no host network):

    tests/screenshots/shoot.sh start
    podman cp tests/proxy/e2e.py alizy-shots:/tmp/e2e.py
    podman exec alizy-shots python3 /tmp/e2e.py

The "internet" is the `inet` network namespace (tests/screenshots/setup.sh):
WireGuard server Frankfurt (tunnel address 10.66.0.2) and a web/UDP echo on
198.51.100.20, which is also reachable directly (via 192.168.50.23). The echo
answers with the client address it sees, so each check knows whether a
connection went through the tunnel (10.66.0.2) or not (192.168.50.23).
"""
import json
import socket
import struct
import subprocess
import sys
import time

SOCK = "/run/alizy/alizyd.sock"
INET = ["nsenter", "--net=/run/netns/inet"]
WEB = ("198.51.100.20", 8000)
UDP = ("198.51.100.20", 9000)
TUNNEL_IP = "10.66.0.2"
DIRECT_IP = "192.168.50.23"
RESOLV = "/run/demo-resolv.conf"
FAILED = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def ipc(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(json.dumps({"id": 1, **cmd}).encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    r = json.loads(buf)["result"]
    if "Err" in r:
        raise RuntimeError(r["Err"])
    return r["Ok"].get("data")


def status():
    return ipc({"cmd": "get_status"})


def set_policy(**patch):
    p = ipc({"cmd": "get_policy"})
    p.update(patch)
    ipc({"cmd": "set_policy", "policy": p})
    return p


def wait_state(want, secs=20):
    for _ in range(secs * 5):
        if status()["state"] == want:
            return True
        time.sleep(0.2)
    return False


# ── clients ──────────────────────────────────────────────────────────────────

def http_get(sock):
    sock.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    data = b""
    while True:
        c = sock.recv(4096)
        if not c:
            break
        data += c
    return data.split(b"\r\n\r\n", 1)[-1].decode().strip()


def direct():
    return http_get(socket.create_connection(WEB, timeout=5))


def socks_greet(proxy, auth=None):
    s = socket.create_connection(proxy, timeout=5)
    if auth:
        s.sendall(b"\x05\x01\x02")
        if s.recv(2) != b"\x05\x02":
            raise ConnectionError("no username/password method")
        u, p = (x.encode() for x in auth)
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        if s.recv(2) != b"\x01\x00":
            raise ConnectionError("login refused")
    else:
        s.sendall(b"\x05\x01\x00")
        g = s.recv(2)
        if g != b"\x05\x00":
            raise ConnectionError(f"method refused {g!r}")
    return s


def addr_bytes(host, port):
    try:
        return b"\x01" + socket.inet_aton(host) + struct.pack(">H", port)
    except OSError:
        h = host.encode()
        return b"\x03" + bytes([len(h)]) + h + struct.pack(">H", port)


def socks_reply(s):
    h = s.recv(4)
    n = {1: 6, 4: 18}.get(h[3], 0) if len(h) == 4 else 0
    rest = s.recv(n) if n else b""
    return h[1] if len(h) >= 2 else -1, rest


def socks_get(proxy, host, port, auth=None):
    s = socks_greet(proxy, auth)
    s.sendall(b"\x05\x01\x00" + addr_bytes(host, port))
    code, _ = socks_reply(s)
    if code != 0:
        raise ConnectionError(f"socks reply {code}")
    return http_get(s)


def socks_code(proxy, host, port):
    s = socks_greet(proxy)
    s.sendall(b"\x05\x01\x00" + addr_bytes(host, port))
    return socks_reply(s)[0]


def socks_udp(proxy, target, payload, auth=None):
    s = socks_greet(proxy, auth)
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    code, bnd = socks_reply(s)
    if code != 0:
        raise ConnectionError(f"udp associate reply {code}")
    relay = (socket.inet_ntoa(bnd[:4]), struct.unpack(">H", bnd[4:6])[0])
    if relay[0] == "0.0.0.0":
        relay = (proxy[0], relay[1])
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(5)
    u.sendto(b"\x00\x00\x00" + addr_bytes(*target) + payload, relay)
    data, _ = u.recvfrom(4096)
    s.close()
    return data[10:].decode()


def http_proxy(proxy, auth=None):
    s = socket.create_connection(proxy, timeout=5)
    hdr = ""
    if auth:
        import base64
        hdr = "Proxy-Authorization: Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode() + "\r\n"
    s.sendall(f"GET http://{WEB[0]}:{WEB[1]}/ HTTP/1.1\r\nHost: x\r\n{hdr}\r\n".encode())
    data = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        data += c
    head, _, body = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode(), body.decode().strip()


def in_lan(*args):
    """Run this script's client sub-command from the LAN side (192.168.50.1)."""
    out = subprocess.run(INET + ["python3", __file__, *args], capture_output=True, text=True, timeout=30)
    return out.stdout.strip() or out.stderr.strip().splitlines()[-1]


def try_(f, *a, **k):
    try:
        return f(*a, **k)
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"


# ── servers in the "internet" namespace ─────────────────────────────────────

SERVERS = r"""
import socket, threading, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = self.client_address[0].encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("198.51.100.20", 9000))
    while True:
        d, a = u.recvfrom(4096); u.sendto(a[0].encode() + b"|" + d, a)
threading.Thread(target=udp, daemon=True).start()
http.server.ThreadingHTTPServer(("198.51.100.20", 8000), H).serve_forever()
"""


def main():
    srv = subprocess.Popen(INET + ["python3", "-c", SERVERS])
    time.sleep(1)
    try:
        run()
    finally:
        srv.kill()
        try:
            ipc({"cmd": "disconnect"})
            set_policy(mode="tunnel", kill_switch=False, allow_lan=True)
            ipc({"cmd": "set_lan_proxy", "config": {"enabled": False, "port": 8080, "socks_port": 1080}})
        except Exception as e:  # noqa: BLE001
            print("cleanup:", e)
    print(f"\n{'ALL PASSED' if not FAILED else f'{len(FAILED)} FAILED: ' + ', '.join(FAILED)}")
    sys.exit(1 if FAILED else 0)


def connect_frankfurt():
    out = subprocess.run(
        ["su", "demo", "-c", "cd ~ && dbus-run-session -- /dist/alizyctl list"], capture_output=True, text=True
    ).stdout
    pid = next(line.split()[0] for line in out.splitlines() if "Frankfurt" in line)
    subprocess.run(["su", "demo", "-c", f"cd ~ && dbus-run-session -- /dist/alizyctl connect {pid}"], capture_output=True)
    return wait_state("connected")


def run():
    socks, http = ("127.0.0.1", 10808), ("127.0.0.1", 10809)
    set_policy(mode="tunnel", kill_switch=False, allow_lan=True, proxy_socks_port=10808, proxy_http_port=10809)

    print("Tunnel mode (regression)")
    check("connects", connect_frankfurt())
    check("direct traffic goes through the tunnel", try_(direct) == TUNNEL_IP, try_(direct))
    check("system DNS points at the tunnel", "198.51.100.53" in open(RESOLV).read())
    check("no local proxy in tunnel mode", try_(socket.create_connection, socks, timeout=1).__class__ is str)

    print("Proxy mode")
    set_policy(mode="proxy", kill_switch=True)
    check("still connected after the switch", wait_state("connected"))
    st = status()
    check("kill switch inactive (preference kept)", not st["kill_switch"]["enabled"] and st["policy"]["kill_switch"])
    check("local proxy listening", st["local_proxy"]["socks_listening"] and st["local_proxy"]["http_listening"], st["local_proxy"])
    check("system traffic no longer captured", try_(direct) == DIRECT_IP, try_(direct))
    check("system DNS restored", "198.51.100.53" not in open(RESOLV).read())
    check("SOCKS5 (IP) goes through the tunnel", try_(socks_get, socks, *WEB) == TUNNEL_IP, try_(socks_get, socks, *WEB))
    r = try_(socks_get, socks, "bank.example.com", WEB[1])
    check("SOCKS5 (name) resolved through the tunnel's DNS", r == TUNNEL_IP, r)
    r = try_(http_proxy, http)
    check("HTTP proxy goes through the tunnel", isinstance(r, tuple) and r[1] == TUNNEL_IP, r)
    r = try_(socks_udp, socks, UDP, b"hi")
    check("SOCKS5 UDP goes through the tunnel", r == f"{TUNNEL_IP}|hi", r)
    nft = subprocess.run(["nft", "list", "table", "inet", "alizy"], capture_output=True, text=True).stdout
    check("firewall: proxy guard installed", "proxy-guard" in nft)
    check("firewall: no kill-switch rule", "kill-switch" not in nft)
    rules = subprocess.run(["ip", "rule"], capture_output=True, text=True).stdout
    check("routing: only the proxy mark is routed", "fwmark 0x4a5c" in rules and "not from all fwmark" not in rules, rules)

    print("Proxy mode, VPN down")
    ipc({"cmd": "disconnect"})
    check("disconnected, not protected", wait_state("disconnected"))
    check("proxy refuses instead of connecting directly", try_(socks_code, socks, *WEB) == 2)
    check("normal connection unaffected", try_(direct) == DIRECT_IP)

    print("Back to tunnel mode")
    check("reconnects", connect_frankfurt())
    set_policy(mode="tunnel")
    check("connected in tunnel mode", wait_state("connected"))
    check("kill switch active again", status()["kill_switch"]["enabled"])
    check("traffic captured again", try_(direct) == TUNNEL_IP, try_(direct))
    check("local proxy stopped", try_(socket.create_connection, socks, timeout=1).__class__ is str)

    print("VPN sharing with login and UDP (tunnel mode, kill switch on, LAN blocked)")
    set_policy(allow_lan=False)
    ipc({
        "cmd": "set_lan_proxy",
        "config": {"enabled": True, "port": 8080, "socks_port": 1080, "auth": {"username": "tv", "password": "s3cret"}},
    })
    lan = json.loads(json.dumps(ipc({"cmd": "get_lan_proxy"})))
    check("status shows the username, not the password", lan.get("auth_username") == "tv" and "s3cret" not in json.dumps(lan))
    state = open("/var/lib/alizy/state.json").read()
    check("password not stored", "s3cret" not in state and "tv" in state)
    check("SOCKS5 without login refused", in_lan("lan-socks-noauth").startswith("error"))
    check("SOCKS5 wrong password refused", in_lan("lan-socks", "tv", "nope").startswith("error"))
    r = in_lan("lan-socks", "tv", "s3cret")
    check("SOCKS5 with login goes through the tunnel", r == TUNNEL_IP, r)
    r = in_lan("lan-udp", "tv", "s3cret")
    check("SOCKS5 UDP from the LAN through the tunnel (kill switch on)", r == f"{TUNNEL_IP}|lan", r)
    r = in_lan("lan-http", "")
    check("HTTP proxy without login: 407", "407" in r, r)
    r = in_lan("lan-http", "tv:s3cret")
    check("HTTP proxy with login goes through the tunnel", r.endswith(TUNNEL_IP), r)

    print("VPN sharing in proxy mode")
    set_policy(mode="proxy")
    check("connected", wait_state("connected"))
    r = in_lan("lan-socks", "tv", "s3cret")
    check("shared device goes through the tunnel", r == TUNNEL_IP, r)


def client(cmd, *args):
    lan_socks = (DIRECT_IP, 1080)
    if cmd == "lan-socks-noauth":
        print(try_(socks_get, lan_socks, *WEB))
    elif cmd == "lan-socks":
        print(try_(socks_get, lan_socks, *WEB, auth=args))
    elif cmd == "lan-udp":
        print(try_(socks_udp, lan_socks, UDP, b"lan", auth=args))
    elif cmd == "lan-http":
        auth = tuple(args[0].split(":", 1)) if args[0] else None
        r = try_(http_proxy, (DIRECT_IP, 8080), auth)
        print(" ".join(r) if isinstance(r, tuple) else r)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        client(*sys.argv[1:])
    else:
        main()
