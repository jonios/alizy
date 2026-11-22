# SSH tunnel real-system validation

Throwaway sshd (rootless Podman, no internet egress needed) + `run.sh`, which
installs the built Arch packages, connects an SSH profile through `alizyctl
ssh-connect` (daemon only, never the GUI database) and checks: host-key TOFU,
HTTP and DNS through the tunnel, UDP rejection, firewall verification, kill
switch with the server down, recovery, and `auth_failed` on a wrong password.

    podman build -t alizy-test-sshd tests/ssh
    head -c 18 /dev/urandom | base64 | tr -d '/+=' > /path/to/alice_pw   # test password, keep out of git
    podman run -d --rm --name alizy-test-sshd --cap-add NET_ADMIN -p 2222:22 \
      -v /path/to/alice_pw:/run/secrets/alice_pw:ro,Z alizy-test-sshd
    cargo build -p alizy-store --example alizyctl
    tests/ssh/run.sh <stable-LAN-IP> /path/to/alice_pw packaging/arch   # SKIP_INSTALL=1 to reuse installed packages

Use a LAN address that will not disappear (not another VPN's interface), and
quit the Alizy GUI first so it cannot auto-connect during the run.
Validated 2026-11-23 on Arch (kernel 7.2, systemd-resolved): all checks PASS.
The changed-host-key path is covered by unit tests only (the image reuses its key).
