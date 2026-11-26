#!/usr/bin/env bash
# Alizy system installer @VERSION@
#
# Installs, upgrades or removes Alizy's system service (alizyd): the WireGuard /
# SSH tunnel daemon that owns the nftables kill switch, DNS and routing. The
# desktop app is the separate Alizy-x86_64.AppImage; this installer can also put
# that file in your application menu.
#
#   ./alizy-installer-x86_64                 install or upgrade (asks before every change)
#   ./alizy-installer-x86_64 status          show what is installed and running
#   ./alizy-installer-x86_64 uninstall       remove the system service (keeps your profiles)
#   ./alizy-installer-x86_64 remove-app      remove the AppImage and its menu entry (your user only)
#   ./alizy-installer-x86_64 --help          all options
#
# Everything above the payload marker at the end of this file is this script;
# below it is a tar archive whose SHA-256 is checked before anything is used.
# Read it before running it:  less alizy-installer-x86_64
set -euo pipefail
umask 022

VERSION="@VERSION@"
PAYLOAD_SHA256="@PAYLOAD_SHA256@"

PREFIX=/usr/local
BIN=$PREFIX/bin/alizyd
UNIT=$PREFIX/lib/systemd/system/alizyd.service
SYSUSERS=$PREFIX/lib/sysusers.d/alizy.conf
POLKIT=/usr/share/polkit-1/actions/io.alizy.policy
LIBDIR=$PREFIX/lib/alizy
STATE=/var/lib/alizy
TABLE="inet alizy"
IFACE=alizy0
RELEASES=https://github.com/jonios/alizy/releases/latest

# ───────────────────────────── output helpers ─────────────────────────────
if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; N=$'\e[0m'; else B=; R=; Y=; G=; N=; fi
say()  { printf '%s\n' "$*"; }
section() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '\n%sError:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

ASSUME_YES=0
ask() { # question default(y|n) -> 0 for yes
  local q=$1 def=$2 hint ans
  [[ $def == y ]] && hint="[Y/n]" || hint="[y/N]"
  if [[ $ASSUME_YES == 1 ]]; then return 0; fi
  if [[ ! -t 0 ]]; then
    die "this step needs an answer (\"$q\") but no terminal is attached. Run it in a terminal, or pass --yes."
  fi
  read -r -p "  $q $hint " ans || ans=
  ans=${ans:-$def}
  [[ $ans == [yY] || $ans == [yY][eE][sS] ]]
}

usage() {
  cat <<EOF
Alizy system installer $VERSION

Usage: $(basename "$0") [command] [options]

Commands:
  install         install or upgrade the system service (default)
  status          show installed versions, service and protection state
  uninstall       remove the system service; profiles, keys and settings are kept
  remove-app      remove the AppImage and its menu entry for your user (no root needed)

Options:
  --appimage PATH   AppImage to add to your application menu (default: an
                    Alizy*.AppImage next to this installer, if there is one)
  --no-appimage     do not touch the AppImage or the menu entry
  --no-enable       install without enabling/starting the service
  --no-group        do not add your user to the 'alizy' group
  --install-deps    install missing required packages without asking
  --allow-downgrade allow installing an older version over a newer one
  --purge           with uninstall: also delete /var/lib/alizy (service state:
                    saved kill-switch setting, split-tunnel rules) and the
                    alizy group and alizy-ssh user. Never deletes your profiles.
  --yes             answer yes to every question (non-interactive)
  -h, --help        this help

The service needs systemd, nftables, WireGuard tools, iproute2 and polkit; the
installer checks for them and shows the install command for your distribution.
EOF
}

# ───────────────────────────── arguments ─────────────────────────────
CMD=install
APPIMAGE=""
NO_APPIMAGE=0
NO_ENABLE=0
NO_GROUP=0
INSTALL_DEPS=0
ALLOW_DOWNGRADE=0
PURGE=0
INVOKER=""          # set when re-executed with sudo/pkexec
SESSION_GROUP=""    # "1" when the invoking session already has group alizy
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case $1 in
    install|status|uninstall|remove-app) CMD=$1 ;;
    --appimage) APPIMAGE=${2:?--appimage needs a path}; shift ;;
    --no-appimage) NO_APPIMAGE=1 ;;
    --no-enable) NO_ENABLE=1 ;;
    --no-group) NO_GROUP=1 ;;
    --install-deps) INSTALL_DEPS=1 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1 ;;
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --invoked-by) INVOKER=${2:?}; shift ;;
    --session-group) SESSION_GROUP=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument '$1' (see --help)" ;;
  esac
  shift
done

SELF=$(readlink -f "$0")
SELF_DIR=$(dirname "$SELF")
[[ -n $APPIMAGE ]] && APPIMAGE=$(readlink -f "$APPIMAGE")

# ───────────────────────────── payload ─────────────────────────────
WORK=""
cleanup() { if [[ -n $WORK && -d $WORK ]]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT
extract_payload() {
  local marker line
  marker="__ALIZY_PAYLOAD_""BELOW__"
  line=$(awk -v m="$marker" '$0 == m { print NR + 1; exit }' "$SELF")
  [[ -n $line ]] || die "this installer file is damaged (payload marker missing). Download it again."
  WORK=$(mktemp -d)
  tail -n +"$line" "$SELF" > "$WORK/payload.tar.gz"
  local got
  got=$(sha256sum "$WORK/payload.tar.gz" | cut -d' ' -f1)
  [[ $got == "$PAYLOAD_SHA256" ]] || die "this installer file is damaged or incomplete (payload checksum mismatch). Download it again and check it against SHA256SUMS."
  mkdir "$WORK/p"
  tar -xzf "$WORK/payload.tar.gz" -C "$WORK/p" --no-same-owner
  # The desktop user reads the icons from here (nothing in the payload is secret).
  chmod 0755 "$WORK" "$WORK/p" "$WORK/p/share"
  [[ -x $WORK/p/bin/alizyd ]] || die "payload has no alizyd binary"
}

# ───────────────────────────── privileges ─────────────────────────────
invoking_user() {
  if [[ -n $INVOKER ]]; then echo "$INVOKER"
  elif [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then echo "$SUDO_USER"
  elif [[ -n ${PKEXEC_UID:-} ]]; then getent passwd "$PKEXEC_UID" | cut -d: -f1
  elif [[ $EUID -ne 0 ]]; then id -un
  fi
}
user_home() { getent passwd "$1" | cut -d: -f6; }

elevate() {
  [[ $EUID -eq 0 ]] && return 0
  local me sg=0
  me=$(id -un)
  [[ " $(id -nG) " == *" alizy "* ]] && sg=1
  say "${B}Administrator rights are needed${N} to install or change the system service."
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -- bash "$SELF" "${ORIG_ARGS[@]}" --invoked-by "$me" --session-group "$sg"
  elif command -v pkexec >/dev/null 2>&1; then
    exec pkexec bash "$SELF" "${ORIG_ARGS[@]}" --invoked-by "$me" --session-group "$sg"
  fi
  die "neither sudo nor pkexec is available. Run this installer as root (su -c '$SELF ${ORIG_ARGS[*]}')."
}

# ───────────────────────────── system state ─────────────────────────────
service_active()  { systemctl is-active --quiet alizyd.service 2>/dev/null; }
service_enabled() { systemctl is-enabled --quiet alizyd.service 2>/dev/null; }
table_present()   { nft list table $TABLE >/dev/null 2>&1; }
tunnel_present()  { ip link show $IFACE >/dev/null 2>&1; }
installed_version() { [[ -f $LIBDIR/VERSION ]] && cat "$LIBDIR/VERSION" || true; }

# Who owns an existing alizyd outside /usr/local? Prints a description or nothing.
foreign_install() {
  local f owner=""
  for f in /usr/bin/alizyd /usr/sbin/alizyd; do
    [[ -e $f ]] || continue
    if command -v pacman >/dev/null 2>&1 && owner=$(pacman -Qqo "$f" 2>/dev/null); then
      echo "package '$owner' ($(pacman -Q "$owner" 2>/dev/null | cut -d' ' -f2)) from pacman: update it with pacman/your AUR helper, or remove it first with: sudo pacman -R alizy alizyd"
      return
    elif command -v dpkg >/dev/null 2>&1 && owner=$(dpkg -S "$f" 2>/dev/null | cut -d: -f1); then
      echo "package '$owner' from dpkg/apt: update it with apt, or remove it first with: sudo apt remove $owner"
      return
    elif command -v rpm >/dev/null 2>&1 && owner=$(rpm -qf "$f" 2>/dev/null); then
      echo "package '$owner' from rpm: update it with dnf/zypper, or remove it first with: sudo dnf remove alizyd"
      return
    else
      echo "a manual installation at $f (packaging/linux/install.sh); remove it first with packaging/linux/uninstall.sh from the source tree (it keeps your data)"
      return
    fi
  done
}

version_lt() { # a < b (x.y.z[-pre])
  [[ $1 != "$2" ]] && [[ $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1) == "$1" ]]
}

kill_switch_saved_on() { grep -q '"kill_switch": *true' "$STATE/state.json" 2>/dev/null; }

protection_summary() {
  local s=""
  service_active && s+="service running" || s+="service not running"
  kill_switch_saved_on && s+=", kill switch on" || s+=", kill switch off"
  table_present && s+=", Alizy firewall table present" || s+=", no Alizy firewall table"
  tunnel_present && s+=", VPN tunnel up" || s+=", no tunnel"
  echo "$s"
}

# ───────────────────────────── dependencies ─────────────────────────────
check_dependencies() {
  section "Checking this system"
  local out rc=0 sev msg fix blockers=() pkgs=() prefix="" p
  out=$("$WORK/p/bin/alizyd" --check 2>&1) || rc=$?
  if [[ $rc -ne 0 && $rc -ne 2 ]]; then die "the system check failed: $out"; fi
  while IFS=$'\t' read -r sev msg fix; do
    [[ -z $sev ]] && continue
    case $sev in
      blocker) warn "${R}required:${N} $msg"; blockers+=("$msg")
               if [[ $fix =~ ^sudo\ (pacman\ -S\ --needed|apt\ install|dnf\ install|zypper\ install)\ (.+)$ ]]; then
                 prefix=${BASH_REMATCH[1]}; for p in ${BASH_REMATCH[2]}; do pkgs+=("$p"); done
               fi ;;
      warning) warn "$msg"; [[ -n $fix ]] && say "      optional fix: $fix" ;;
      info)    say "  - $msg"; [[ -n $fix ]] && say "      to enable: $fix" ;;
    esac
  done <<< "$out"
  [[ ${#blockers[@]} -eq 0 ]] && { ok "all required components are present"; return 0; }

  if [[ ${#pkgs[@]} -gt 0 && -n $prefix ]]; then
    local cmd="$prefix ${pkgs[*]}"
    say ""
    say "  Missing packages can be installed with:  ${B}$cmd${N}"
    if [[ $INSTALL_DEPS == 1 ]] || { [[ $ASSUME_YES == 0 ]] && ask "Run that command now?" n; }; then
      [[ $prefix == "apt install" ]] && apt-get update
      case $prefix in
        "pacman -S --needed") pacman -S --needed --noconfirm "${pkgs[@]}" ;;
        "apt install") DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" ;;
        "dnf install") dnf install -y "${pkgs[@]}" ;;
        "zypper install") zypper --non-interactive install "${pkgs[@]}" ;;
      esac
      out=$("$WORK/p/bin/alizyd" --check 2>&1) && return 0
      die "required components are still missing after installing packages:
$(grep '^blocker' <<< "$out" | cut -f2)"
    fi
  fi
  die "install the required components above, then run this installer again."
}

# ───────────────────────────── file installation ─────────────────────────────
put() { # src dst mode   (atomic: write next to the target, then rename)
  install -D -m "$3" -o root -g root "$1" "$2.alizy-new"
  mv -f "$2.alizy-new" "$2"
}

write_manifest() {
  mkdir -p "$LIBDIR"
  printf '%s\n' "$BIN" "$UNIT" "$SYSUSERS" "$POLKIT" "$LIBDIR/alizy-installer" "$LIBDIR/VERSION" "$LIBDIR/manifest" > "$LIBDIR/manifest"
}

install_files() {
  put "$WORK/p/bin/alizyd" "$BIN" 0755
  put "$WORK/p/systemd/alizyd.service" "$UNIT" 0644
  put "$WORK/p/sysusers/alizy.conf" "$SYSUSERS" 0644
  put "$WORK/p/polkit/io.alizy.policy" "$POLKIT" 0644
  put "$SELF" "$LIBDIR/alizy-installer" 0755
  printf '%s\n' "$VERSION" > "$LIBDIR/VERSION.alizy-new" && mv -f "$LIBDIR/VERSION.alizy-new" "$LIBDIR/VERSION"
  write_manifest
  systemd-sysusers "$SYSUSERS"
  systemctl daemon-reload
}

wait_ready() { # the unit is Type=notify: restart returns once protection is in place
  local i
  for i in $(seq 1 20); do
    service_active && [[ -S /run/alizy/alizyd.sock ]] && return 0
    sleep 0.5
  done
  return 1
}

# ───────────────────────────── per-user app integration ─────────────────────────────
APP_DEST_REL="Applications/Alizy.AppImage"
DESKTOP_REL=".local/share/applications/io.alizy.app.desktop"

find_appimage() {
  [[ $NO_APPIMAGE == 1 ]] && return 0
  if [[ -n $APPIMAGE ]]; then
    [[ -f $APPIMAGE ]] || die "AppImage not found: $APPIMAGE"
    echo "$APPIMAGE"; return
  fi
  local f
  f=$(ls -1t "$SELF_DIR"/Alizy*.AppImage 2>/dev/null | head -1 || true)
  [[ -n $f ]] && echo "$f"
  return 0
}

# Runs as the desktop user (never as root): copies the AppImage atomically and
# writes the menu entry and icons under that user's home.
user_install_app() {
  set -euo pipefail
  local src=$1 icons=$2 home=$3
  local dest="$home/Applications/Alizy.AppImage"
  mkdir -p "$home/Applications" "$home/.local/share/applications" \
    "$home/.local/share/icons/hicolor/256x256/apps" "$home/.local/share/icons/hicolor/scalable/apps"
  if [[ $(readlink -f "$src") != "$(readlink -f "$dest" 2>/dev/null || true)" ]]; then
    cp -f "$src" "$dest.tmp.$$"
    chmod 0755 "$dest.tmp.$$"
    mv -f "$dest.tmp.$$" "$dest"
  else
    chmod 0755 "$dest"
  fi
  cp -f "$icons/io.alizy.app.png" "$home/.local/share/icons/hicolor/256x256/apps/io.alizy.app.png"
  cp -f "$icons/io.alizy.app.svg" "$home/.local/share/icons/hicolor/scalable/apps/io.alizy.app.svg"
  cat > "$home/.local/share/applications/io.alizy.app.desktop.tmp" <<EOF
[Desktop Entry]
Type=Application
Name=Alizy
GenericName=WireGuard VPN client
Comment=WireGuard and SSH VPN client with an OS-level kill switch
Exec="$dest"
Icon=io.alizy.app
Terminal=false
Categories=Network;Security;
Keywords=vpn;wireguard;privacy;killswitch;
StartupWMClass=alizy
X-Alizy-Installer=1
EOF
  mv -f "$home/.local/share/applications/io.alizy.app.desktop.tmp" "$home/.local/share/applications/io.alizy.app.desktop"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$home/.local/share/applications" 2>/dev/null || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "$home/.local/share/icons/hicolor" 2>/dev/null || true
  echo "$dest"
}

user_remove_app() {
  set -euo pipefail
  local home=$1 removed=0 f
  for f in "$home/Applications/Alizy.AppImage" "$home/.local/share/applications/io.alizy.app.desktop" \
           "$home/.local/share/icons/hicolor/256x256/apps/io.alizy.app.png" "$home/.local/share/icons/hicolor/scalable/apps/io.alizy.app.svg"; do
    if [[ -e $f ]]; then rm -f "$f"; echo "  removed $f"; removed=1; fi
  done
  # The app's own "Launch at startup" entry, only if it points at the removed AppImage.
  f="$home/.config/autostart/Alizy.desktop"
  if [[ -f $f ]] && grep -q "Applications/Alizy.AppImage" "$f"; then rm -f "$f"; echo "  removed $f"; removed=1; fi
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$home/.local/share/applications" 2>/dev/null || true
  [[ $removed == 1 ]] || echo "  nothing to remove"
}

as_user() { # user function args...
  local u=$1 fn=$2; shift 2
  local home; home=$(user_home "$u")
  if [[ $EUID -ne 0 ]]; then "$fn" "$@"; return; fi
  runuser -u "$u" -- env HOME="$home" bash -c "$(declare -f "$fn"); $fn \"\$@\"" _ "$@"
}

# ───────────────────────────── commands ─────────────────────────────
cmd_status() {
  local v pkg
  section "Alizy system service"
  v=$(installed_version)
  pkg=$(foreign_install)
  if [[ -n $v ]]; then say "  installed by this installer: $v ($BIN)"
  elif [[ -n $pkg ]]; then say "  installed by: $pkg"
  else say "  not installed"; fi
  [[ -x $BIN ]] && say "  binary: $("$BIN" --version 2>/dev/null)"
  say "  service: $(systemctl is-active alizyd.service 2>/dev/null || true), $(systemctl is-enabled alizyd.service 2>/dev/null || echo not-installed) at boot"
  if [[ $EUID -eq 0 ]]; then
    say "  protection: $(protection_summary)"
  else
    say "  protection: (run with sudo to inspect firewall state)"
  fi
  [[ -S /run/alizy/alizyd.sock ]] && say "  socket: /run/alizy/alizyd.sock ($(stat -c '%a %U:%G' /run/alizy/alizyd.sock))"
  local u; u=$(invoking_user)
  if [[ -n $u ]]; then
    [[ " $(id -nG "$u") " == *" alizy "* ]] && say "  user $u: member of group alizy" || say "  user $u: NOT in group alizy"
    local home; home=$(user_home "$u")
    [[ -x $home/$APP_DEST_REL ]] && say "  app: $home/$APP_DEST_REL" || say "  app: no AppImage in $home/Applications"
  fi
  say "  this installer: $VERSION"
}

cmd_install() {
  elevate
  extract_payload
  local user home was_version foreign appimage upgrading=0 was_active=0 had_table=0 ks_on=0 added_group=0
  user=$(invoking_user)
  [[ $(uname -m) == x86_64 ]] || die "this installer is for x86_64; this machine is $(uname -m)."
  [[ -d /run/systemd/system ]] || die "systemd is not running as the init system. Alizy's service needs systemd for boot-time protection; it is not supported on this system."

  section "Alizy $VERSION — system service installer"
  foreign=$(foreign_install)
  [[ -z $foreign ]] || die "Alizy's service is already installed by $foreign.
The installer never overwrites files it did not install. Your profiles and settings are kept either way."
  was_version=$(installed_version)
  if [[ -n $was_version ]]; then
    upgrading=1
    if [[ $was_version == "$VERSION" ]]; then say "  Version $VERSION is already installed; files will be refreshed."
    elif version_lt "$VERSION" "$was_version"; then
      [[ $ALLOW_DOWNGRADE == 1 ]] || die "version $was_version is installed, this installer has the older $VERSION. Use --allow-downgrade if you really want to go back."
      warn "downgrading $was_version -> $VERSION"
    else say "  Upgrade: $was_version -> $VERSION"; fi
    service_active && was_active=1
    table_present && had_table=1
    kill_switch_saved_on && ks_on=1
    say "  Current state: $(protection_summary)"
  fi

  check_dependencies

  appimage=$(find_appimage)
  section "Plan"
  say "  - install the service files under $PREFIX (binary, systemd unit, sysusers) and the polkit action"
  if [[ $upgrading == 1 ]]; then
    if [[ $was_active == 1 ]]; then
      say "  - restart the running service onto the new version. A connected VPN drops for about a second;"
      if [[ $ks_on == 1 && $had_table == 1 ]]; then
        say "    the kill-switch rules stay in the kernel the whole time, so nothing leaks."
      else
        say "    The kill switch is off: for that second, traffic uses your normal connection."
      fi
      say "    The app reconnects your previous profile by itself."
      say "    If the new version fails to start, the previous one is restored automatically."
    fi
  elif [[ $NO_ENABLE == 0 ]]; then
    if grep -q '"kill_switch": *true' "$STATE/state.json" 2>/dev/null; then
      say "  - enable and start the service. ${B}Saved settings from an earlier installation have the kill"
      say "    switch ON:${N} once the service starts, all traffic outside the VPN is blocked until you"
      say "    connect a profile in the app (or turn the kill switch off there)."
    else
      say "  - enable and start the service (the kill switch stays OFF until you turn it on in the app)"
    fi
  fi
  if [[ -n $user && $user != root && $NO_GROUP == 0 ]] && ! [[ " $(id -nG "$user") " == *" alizy "* ]]; then
    say "  - add user '$user' to the 'alizy' group, which may control the VPN service"
  fi
  [[ -n $appimage && -n $user && $user != root ]] && say "  - put $(basename "$appimage") in ~$user/Applications and the application menu"
  say "  Your VPN profiles, private keys, settings and history are not touched."
  ask "Continue?" y || die "cancelled; nothing was changed."

  section "Installing"
  if [[ $upgrading == 1 ]]; then
    rm -rf "$LIBDIR/rollback"; mkdir -p "$LIBDIR/rollback"
    cp -a "$BIN" "$UNIT" "$LIBDIR/VERSION" "$LIBDIR/rollback/" 2>/dev/null || true
  fi
  install_files
  ok "files installed ($BIN, $UNIT)"

  if [[ $upgrading == 1 && $was_active == 1 ]]; then
    systemctl restart alizyd.service || true
    if wait_ready; then
      ok "service restarted on $("$BIN" --version)"
      if [[ $ks_on == 1 && $had_table == 1 ]]; then
        table_present && ok "kill-switch rules still in place" || warn "the kill-switch rules are not present after the restart (they are re-applied from the saved setting; check the app)"
      fi
      rm -rf "$LIBDIR/rollback"
    else
      warn "the new service did not start; restoring $was_version"
      journalctl -u alizyd.service -n 15 --no-pager 2>/dev/null | sed 's/^/      /' || true
      put "$LIBDIR/rollback/alizyd" "$BIN" 0755
      put "$LIBDIR/rollback/alizyd.service" "$UNIT" 0644
      cp -f "$LIBDIR/rollback/VERSION" "$LIBDIR/VERSION"
      systemctl daemon-reload
      # The failed version crash-looped (Restart=always) into systemd's start
      # rate limit; clear it or the restored version is refused too.
      systemctl reset-failed alizyd.service 2>/dev/null || true
      systemctl restart alizyd.service || true
      if wait_ready; then
        die "upgrade failed; version $was_version was restored and is running. Your protection settings are unchanged."
      fi
      die "upgrade failed and the previous version did not start either.
If the kill switch was on, its rules are still in the kernel (nothing leaks, but the network is blocked).
To get the network back without Alizy:   sudo $BIN --remove-firewall
Logs:  journalctl -u alizyd -b"
    fi
  elif [[ $upgrading == 1 ]]; then
    ok "service was not running; left stopped ($(systemctl is-enabled alizyd.service 2>/dev/null || true) at boot)"
  elif [[ $NO_ENABLE == 0 ]]; then
    systemctl enable alizyd.service >/dev/null 2>&1
    systemctl reset-failed alizyd.service 2>/dev/null || true
    systemctl start alizyd.service || true
    if wait_ready; then ok "service enabled and running"
    else
      journalctl -u alizyd.service -n 15 --no-pager 2>/dev/null | sed 's/^/      /' || true
      die "the service was installed but did not start (see the log above). Fix the cause, then: sudo systemctl start alizyd"
    fi
  else
    ok "service installed but not enabled (--no-enable). Start it with: sudo systemctl enable --now alizyd"
  fi

  if [[ -n $user && $user != root && $NO_GROUP == 0 ]]; then
    if ! [[ " $(id -nG "$user") " == *" alizy "* ]]; then
      if ask "Add '$user' to the 'alizy' group so this account can use Alizy?" y; then
        usermod -aG alizy "$user" && added_group=1 && ok "added $user to group alizy"
      fi
    fi
  fi

  if [[ -n $appimage && -n $user && $user != root ]]; then
    local dest
    dest=$(as_user "$user" user_install_app "$appimage" "$WORK/p/share" "$(user_home "$user")") \
      && ok "app installed: $dest (in your application menu as \"Alizy\")"
  elif [[ $NO_APPIMAGE == 0 ]]; then
    say "  No Alizy AppImage next to the installer: the menu entry was not created."
    say "  Download Alizy-x86_64.AppImage from $RELEASES and run the installer again (or pass --appimage PATH)."
  fi

  section "Done"
  if [[ $added_group == 1 ]] || [[ $SESSION_GROUP == 0 && -n $user && $user != root ]]; then
    say "  ${B}Log out completely and log back in${N} so your session joins the 'alizy' group."
    say "  Then check with:  id -nG | grep -w alizy"
    say "  If 'alizy' is missing after logging back in, your user session outlived the logout"
    say "  (lingering, uwsm or another open session): reboot once instead."
  fi
  say "  Start \"Alizy\" from your application menu. To remove the service later:"
  say "    sudo $LIBDIR/alizy-installer uninstall"
}

cleanup_network_state() {
  # Preferred: the daemon's own teardown (exact rule selectors).
  if [[ -x $BIN ]]; then "$BIN" --remove-firewall >/dev/null 2>&1 || true; fi
  # Fallback for a missing/broken binary: only objects Alizy owns.
  table_present && nft delete table $TABLE 2>/dev/null || true
  tunnel_present && ip link delete $IFACE 2>/dev/null || true
  local fam prio
  for fam in -4 -6; do
    for prio in 19029 19030 19031 19032 19033 19034; do
      while ip "$fam" rule show priority "$prio" 2>/dev/null | grep -q .; do ip "$fam" rule del priority "$prio" 2>/dev/null || break; done
    done
  done
  if [[ -f $STATE/resolv.conf.backup ]]; then
    if [[ -f $STATE/resolv.conf.link ]]; then ln -sfn "$(cat "$STATE/resolv.conf.link")" /etc/resolv.conf
    else cp -f "$STATE/resolv.conf.backup" /etc/resolv.conf; fi
    rm -f "$STATE/resolv.conf.backup" "$STATE/resolv.conf.link"
    ok "restored /etc/resolv.conf"
  fi
}

verify_network_clean() {
  local left=()
  table_present && left+=("nftables table $TABLE")
  tunnel_present && left+=("interface $IFACE")
  local fam prio
  for fam in -4 -6; do for prio in 19029 19030 19031 19032 19033 19034; do
    ip "$fam" rule show priority "$prio" 2>/dev/null | grep -q . && left+=("ip $fam rule priority $prio")
  done; done
  if [[ ${#left[@]} -gt 0 ]]; then
    die "could not remove: ${left[*]}. Nothing else was removed; run the uninstaller again, or remove them by hand."
  fi
}

cmd_uninstall() {
  elevate
  local v foreign user
  user=$(invoking_user)
  section "Remove the Alizy system service"
  foreign=$(foreign_install)
  [[ -z $foreign ]] || die "the service was installed by $foreign. Remove it that way; this installer only removes what it installed."
  v=$(installed_version)
  if [[ -z $v ]]; then
    if table_present || tunnel_present; then
      warn "no installation found, but Alizy network state is present: $(protection_summary)"
      ask "Remove the leftover Alizy firewall table, routes and interface?" y || die "cancelled"
      cleanup_network_state; verify_network_clean; ok "leftover network state removed"; return
    fi
    say "  Alizy's system service is not installed by this installer. Nothing to do."; return
  fi
  say "  Installed version: $v"
  say "  Current state: $(protection_summary)"
  say ""
  say "  ${B}What this does:${N}"
  say "  - stops and removes the service. ${B}The VPN disconnects and the kill switch is turned off:${N}"
  say "    from that moment your traffic uses your normal internet connection, unprotected."
  say "  - removes only Alizy's own firewall table, routing rules and network interface, and"
  say "    restores DNS. Other firewall rules (ufw, firewalld, ...) are not touched."
  if [[ $PURGE == 1 ]]; then
    say "  - --purge: deletes $STATE (saved kill-switch setting, split-tunnel rules) and the"
    say "    'alizy' group and 'alizy-ssh' user."
  else
    say "  - keeps $STATE, so a reinstall restores your kill-switch setting and split rules."
  fi
  say "  - never deletes your profiles, private keys, settings or history (they are in your home"
  say "    folder and keyring). The app itself (AppImage) is removed separately: remove-app."
  if [[ $ASSUME_YES == 0 ]]; then
    [[ -t 0 ]] || die "uninstall needs confirmation; run it in a terminal or pass --yes."
    local ans; read -r -p "  Type 'remove' to continue: " ans
    [[ $ans == remove ]] || die "cancelled; nothing was changed."
  fi

  section "Removing"
  systemctl disable --now alizyd.service >/dev/null 2>&1 || true
  ok "service stopped and disabled"
  cleanup_network_state
  verify_network_clean
  ok "Alizy firewall table, routing rules and interface removed"
  local f
  while read -r f; do [[ -n $f && $f == /* ]] && rm -f "$f"; done < "$LIBDIR/manifest"
  rm -rf "$LIBDIR"
  systemctl daemon-reload
  systemctl reset-failed alizyd.service >/dev/null 2>&1 || true
  ok "service files removed"
  if [[ $PURGE == 1 ]]; then
    rm -rf "$STATE"
    getent passwd alizy-ssh >/dev/null && userdel alizy-ssh 2>/dev/null || true
    getent group alizy >/dev/null && groupdel alizy 2>/dev/null || true
    ok "removed $STATE, user alizy-ssh and group alizy"
  fi

  section "Done"
  say "  The system service is gone and your network is back to normal."
  local home=""; [[ -n $user && $user != root ]] && home=$(user_home "$user")
  say "  Kept: your profiles, keys and settings in ${home:-~}/.local/share/io.alizy.app and the keyring entry 'io.alizy.app'."
  [[ $PURGE == 1 ]] || say "  Kept: $STATE, group 'alizy', user 'alizy-ssh' (remove with: uninstall --purge)."
  if [[ -n $home && -e $home/$APP_DEST_REL ]]; then
    say "  The app is still in $home/Applications; remove it with:  $(basename "$SELF") remove-app"
  fi
}

cmd_remove_app() {
  local u home
  if [[ $EUID -eq 0 ]]; then u=$(invoking_user); [[ -n $u && $u != root ]] || die "run remove-app as your normal user (no sudo)."
  else u=$(id -un); fi
  home=$(user_home "$u")
  section "Remove the Alizy app for $u"
  say "  Removes ~/Applications/Alizy.AppImage, its menu entry and icons. The system service,"
  say "  your profiles, keys and settings are not touched."
  ask "Continue?" y || die "cancelled"
  as_user "$u" user_remove_app "$home"
}

case $CMD in
  install) cmd_install ;;
  status) cmd_status ;;
  uninstall) cmd_uninstall ;;
  remove-app) cmd_remove_app ;;
esac
exit 0
