#!/usr/bin/env python3
"""Minimal alizyd IPC client for installer tests (stdlib only).

  ipc.py hello | state | verified | policy
  ipc.py kill-switch on|off
  ipc.py connect PRIVATE_KEY PEER_PUBLIC_KEY PEER_IP PORT
  ipc.py disconnect
"""
import json
import socket
import sys

SOCK = "/run/alizy/alizyd.sock"


def call(req, timeout=40):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    req = dict(req, id=1)
    s.sendall(json.dumps(req).encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    resp = json.loads(buf)
    res = resp.get("result", resp)
    if isinstance(res, dict) and "Err" in res:
        raise SystemExit("daemon error: %s" % json.dumps(res["Err"]))
    return res.get("Ok", res) if isinstance(res, dict) else res


def status():
    return call({"cmd": "get_status"})["data"]


def main(argv):
    cmd = argv[1]
    if cmd == "hello":
        print(json.dumps(call({"cmd": "hello", "protocol": 1})))
    elif cmd == "state":
        print(status()["state"])
    elif cmd == "verified":
        print(status()["kill_switch"]["firewall_verified"])
    elif cmd == "policy":
        print(json.dumps(call({"cmd": "get_policy"})["data"], sort_keys=True))
    elif cmd == "kill-switch":
        pol = call({"cmd": "get_policy"})["data"]
        pol["kill_switch"] = argv[2] == "on"
        call({"cmd": "set_policy", "policy": pol})
        print("ok")
    elif cmd == "connect":
        priv, pub, ip, port = argv[2:6]
        spec = {
            "profile_id": "itest",
            "profile_name": "Installer test",
            "config": {
                "interface": {"private_key": priv, "addresses": ["10.66.0.2/32"], "dns": ["10.66.0.1"],
                              "dns_search": [], "mtu": 1420, "listen_port": None},
                "peers": [{"public_key": pub, "preshared_key": None, "allowed_ips": ["0.0.0.0/0"],
                           "endpoint": {"host": {"kind": "ip", "value": ip}, "port": int(port)},
                           "persistent_keepalive": 5}],
            },
            "cached_endpoints": [None],
        }
        call({"cmd": "connect", "spec": spec}, timeout=60)
        print("ok")
    elif cmd == "disconnect":
        call({"cmd": "disconnect"})
        print("ok")
    else:
        raise SystemExit("unknown command " + cmd)


if __name__ == "__main__":
    main(sys.argv)
