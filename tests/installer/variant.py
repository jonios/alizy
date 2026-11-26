#!/usr/bin/env python3
"""Derive test installers from a release installer.

  variant.py IN OUT VERSION            same payload, different version (upgrade test)
  variant.py IN OUT VERSION --broken   alizyd replaced by a stub whose service mode
                                       exits 1 (rollback test); --check/--version still work
"""
import hashlib
import io
import sys
import tarfile

MARKER = b"__ALIZY_PAYLOAD_" + b"BELOW__\n"
BROKEN = b"""#!/bin/sh
case "$1" in
  --check) exit 0 ;;
  --version) echo "alizyd broken-test"; exit 0 ;;
  --remove-firewall) exit 1 ;;
esac
echo "deliberately broken alizyd for the rollback test" >&2
exit 1
"""


def main(src, dst, version, broken):
    data = open(src, "rb").read()
    i = data.index(b"\n" + MARKER) + 1
    header, payload = data[:i].decode(), data[i + len(MARKER):]
    if broken:
        old = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
        out = io.BytesIO()
        new = tarfile.open(fileobj=out, mode="w:gz")
        for m in old.getmembers():
            if m.name.lstrip("./") == "bin/alizyd":
                m.size = len(BROKEN)
                new.addfile(m, io.BytesIO(BROKEN))
            else:
                new.addfile(m, old.extractfile(m) if m.isfile() else None)
        new.close()
        payload = out.getvalue()
    lines = header.splitlines(keepends=True)
    for n, line in enumerate(lines):
        if line.startswith("VERSION="):
            lines[n] = 'VERSION="%s"\n' % version
        elif line.startswith("PAYLOAD_SHA256="):
            lines[n] = 'PAYLOAD_SHA256="%s"\n' % hashlib.sha256(payload).hexdigest()
    with open(dst, "wb") as f:
        f.write("".join(lines).encode() + MARKER + payload)


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], a[1], a[2], "--broken" in a)
