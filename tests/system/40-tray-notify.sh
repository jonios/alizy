#!/usr/bin/env bash
# Tray menu actions (driven through the tray's com.canonical.dbusmenu, the same
# path a click takes) + desktop notifications. Needs the GUI running and the
# session in group alizy. Takes NetworkManager $KEEP_CONN down briefly and always
# restores it. No root needed.
source "$(dirname "$0")/lib.sh"
rm -f "$OUT/DONE"
SVC=$(busctl --user get-property org.kde.StatusNotifierWatcher /StatusNotifierWatcher org.kde.StatusNotifierWatcher RegisteredStatusNotifierItems | grep -o '":[0-9.]*/org/ayatana/NotificationItem/tray_icon_tray_app_alizy_tray"' | tr -d '"')
BUS=${SVC%%/*}; MENU=/${SVC#*/}/Menu
layout() { gdbus call --session --dest "$BUS" --object-path "$MENU" --method com.canonical.dbusmenu.GetLayout -- 0 -1 "[]"; }
item_id() { layout | grep -oE "\(([0-9]+), \{[^}]*'label': <'[^']*'>" | sed -E "s/^\(([0-9]+), \{.*'label': <'([^']*)'>/\1\t\2/" | awk -F'\t' -v l="$1" 'index($2,l)==1 {print $1; exit}'; }
click() { gdbus call --session --dest "$BUS" --object-path "$MENU" --method com.canonical.dbusmenu.Event -- "$1" clicked "<0>" 0 >/dev/null; }
header() { layout | grep -oE "'label': <'[^']*'>" | head -1 | sed -E "s/.*<'(.*)'>/\1/"; }

dbus-monitor --session "interface='org.freedesktop.Notifications',member='Notify'" > "$OUT/notify.log" 2>&1 &
MON=$!
cleanup() { kill $MON 2>/dev/null; ctl disconnect >/dev/null 2>&1; keep_up; internet || echo "WARNING: internet not reachable after restore"; echo "summary: $PASS passed, $FAIL failed"; date > "$OUT/DONE"; }
trap cleanup EXIT INT TERM

check "tray registered with StatusNotifierWatcher" test -n "$BUS"
check "tray header shows daemon state (disconnected)" bash -c "h='$(header)'; echo \"\$h\"; [[ \$h == Disconnected* ]]"
keep_down; sleep 1
PA=$(item_id "$PROFILE_A")
check "tray: Connect > profile A clicked" click "$PA"
check "daemon connected after tray click" wait_state connected 30
sleep 3
check "tray header updated to Connected" bash -c "for i in 1 2 3 4 5; do h=\$(gdbus call --session --dest $BUS --object-path $MENU --method com.canonical.dbusmenu.GetLayout -- 0 -1 '[]' | grep -oE \"'label': <'[^']*'>\" | head -1); echo \"\$h\" | grep -q 'Connected' && { echo \"\$h\"; exit 0; }; sleep 1; done; echo \"\$h\"; exit 1"
check "internet works through Alizy tunnel" internet
check "notification sent: Connected to $PROFILE_A" bash -c "grep -A12 'member=Notify' $OUT/notify.log | grep -m1 -o 'Connected to $PROFILE_A'"
DISC=$(item_id "Disconnect")
check "tray: Disconnect clicked" click "$DISC"
check "daemon disconnected after tray click" wait_state disconnected 30
sleep 2
check "notification sent: Disconnected" bash -c "grep -A12 'member=Notify' $OUT/notify.log | grep -m1 -o '\"Disconnected\"'"
OPEN=$(item_id "Open Alizy")
check "tray: Open Alizy clicked" click "$OPEN"
sleep 1
check "Alizy window visible after Open" bash -c "hyprctl clients -j | python3 -c \"import json,sys;w=[c for c in json.load(sys.stdin) if c['class']=='alizy'];print(w and {'mapped':w[0]['mapped'],'hidden':w[0]['hidden']});sys.exit(0 if w and w[0]['mapped'] and not w[0]['hidden'] else 1)\""
