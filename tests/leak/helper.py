#!/usr/bin/env python3
"""Traffic, DNS and IPC helpers for the Alizy network-namespace test suite.

Subcommands:
  recv PORT LOG                      UDP sink on 0.0.0.0/:: PORT; logs "<src> <payload>"
  send DST PORT PAYLOAD [DEV]        send 3 UDP datagrams, optionally SO_BINDTODEVICE DEV
                                     exit 0 = sent, 3 = rejected locally (EPERM/EACCES/unreachable)
  dns ADDR RECORDS.json LOG          tiny authoritative DNS server for tests
  ipc SOCKET JSON                    send one request to alizyd, print the response line
"""
import json
import socket
import struct
import sys
import threading
import time


def recv(port, log):
    def serve(fam, addr):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, int(port)))
        while True:
            data, src = s.recvfrom(2048)
            with open(log, "a") as f:
                f.write(f"{src[0]} {data.decode(errors='replace')}\n")

    threads = [threading.Thread(target=serve, args=a, daemon=True)
               for a in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::"))]
    for t in threads:
        t.start()
    while True:
        time.sleep(3600)


def send(dst, port, payload, dev=None):
    fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if dev:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
    try:
        for _ in range(3):
            s.sendto(payload.encode(), (dst, int(port)))
            time.sleep(0.05)
    except OSError as e:
        print(f"send blocked: {e}", file=sys.stderr)
        return 3
    return 0


def dns(addr, records_file, log):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.bind((addr, 53))

    def enc(name):
        out = b""
        for label in name.rstrip(".").split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\0"

    while True:
        q, src = s.recvfrom(1500)
        with open(log, "a") as f:
            f.write(f"RAW {src[0]}\n")
        try:
            handle_query(s, q, src, records_file, log, enc)
        except Exception as e:  # malformed probe packets must not kill the server
            with open(log, "a") as f:
                f.write(f"BAD {src[0]} {e}\n")


def handle_query(s, q, src, records_file, log, enc):
    if True:
        qid = q[:2]
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode())
            i += 1 + q[i]
        qname = ".".join(labels).lower()
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0]
        question = q[12:i + 5]
        with open(log, "a") as f:
            f.write(f"{src[0]} {qname} {qtype}\n")
        with open(records_file) as f:
            records = json.load(f)
        answers, name = [], qname
        rec = records.get(name)
        if rec and "cname" in rec:
            answers.append(enc(name) + struct.pack("!HHIH", 5, 1, rec.get("ttl", 60), len(enc(rec["cname"]))) + enc(rec["cname"]))
            name = rec["cname"]
            rec = records.get(name)
        if rec:
            for ip in rec.get("A" if qtype == 1 else "AAAA" if qtype == 28 else "-", []):
                raw = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6, ip)
                answers.append(enc(name) + struct.pack("!HHIH", qtype, 1, rec.get("ttl", 60), len(raw)) + raw)
        rcode = 0 if qname in records else 3
        hdr = qid + struct.pack("!BBHHHH", 0x81, 0x80 | rcode, 1, len(answers), 0, 0)
        s.sendto(hdr + question + b"".join(answers), src)


def dnsq(server, name, dev=None):
    """Exit 0 if `server` answers an A query for `name` within 3 s."""
    import random
    q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\0\0\1\0\1"
    s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM)
    if dev:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
    s.settimeout(3)
    try:
        s.sendto(q, (server, 53))
        s.recv(1500)
        return 0
    except OSError as e:
        print(f"no answer: {e}", file=sys.stderr)
        return 1


def ipc(sock_path, req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall(req.encode() + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    print(buf.decode().strip())


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "recv":
        recv(*args)
    elif cmd == "send":
        sys.exit(send(*args))
    elif cmd == "dns":
        dns(*args)
    elif cmd == "dnsq":
        sys.exit(dnsq(*args))
    elif cmd == "ipc":
        ipc(*args)
    else:
        sys.exit(__doc__)
